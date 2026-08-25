/**
 * @file MultiConnLinear.cpp
 * @brief 多连接线性扩展测试（Release，真实 TCP）
 * @details 每线程独立 ioc + 独立 vmess 连接（真实代理 worker 模式）：
 * 1/2/4 线程 × 各自连接，总吞吐应线性增长
 */

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

#include <common/Core/Transport/Reliable.hpp>
#include <common/Protocols/Vmess/Vmess.hpp>

using clk = std::chrono::steady_clock;
namespace net = boost::asio;

namespace
{
    auto now_ns() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(clk::now().time_since_epoch()).count();
    }

    // 每线程一个完整 vmess 连接（独立 ioc，thread_local Arena 安全）
    auto run_one_conn(const std::size_t Total, const std::size_t block) -> bool
    {
        using namespace Preview;
        net::io_context ioc;
        net::ip::tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto port = acceptor.local_endpoint().port();
        std::vector<std::uint8_t> chunk(block, 0x5A);
        const auto uuid = std::array<std::uint8_t, 16>{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                                        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
        bool completed = true; // 数据面完成标志（false = 断链/未写完，门禁 FAIL）

        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                net::ip::tcp::socket sock(ioc);
                co_await acceptor.async_accept(sock, net::use_awaitable);
                auto ss = std::make_shared<Transport::Reliable>(std::move(sock));
                Vmess::ServerConfig scfg;
                scfg.uuid = uuid;
                auto [err, req, Conn] = co_await Vmess::Accept(ss, scfg);
                if (err != Error::none || !Conn)
                {
                    co_return;
                }
                std::vector<std::uint8_t> buf(block);
                std::error_code ec;
                std::size_t Done = 0;
                while (Done < Total)
                {
                    const auto n = co_await Conn->AsyncReadSome(
                        std::span<std::byte>(reinterpret_cast<std::byte *>(buf.data()), buf.size()), ec);
                    if (ec || n == 0)
                    {
                        break;
                    }
                    Done += n;
                }
                Conn->Close();
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            auto ss = std::make_shared<Transport::Reliable>(ioc.get_executor());
            const auto ec2 = co_await ss->Connect(net::ip::tcp::endpoint(net::ip::address_v4::loopback(), port));
            if (ec2)
            {
                ioc.stop();
                co_return;
            }
            Vmess::ClientConfig ccfg;
            ccfg.uuid = uuid;
            auto [err, Conn] = co_await Vmess::Connect(
                ss, ccfg, Vmess::Address{Vmess::AddressType::Domain, "t.internal", 443});
            if (err != Error::none || !Conn)
            {
                ioc.stop();
                co_return;
            }
            std::size_t Done = 0;
            std::error_code ec;
            while (Done < Total)
            {
                const auto n = co_await Conn->AsyncWriteSome(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(chunk.data()), chunk.size()), ec);
                if (ec || n == 0)
                {
                    break; // 断链：completed=false 门禁 FAIL
                }
                Done += n;
            }
            if (Done < Total)
            {
                completed = false;
            }
            Conn->Close();
        }, [&](std::exception_ptr) { ioc.stop(); });
        ioc.run();
        return completed;
    }
} // namespace

int main()
{
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    constexpr std::size_t kTotal = 256ULL * 1024 * 1024; // 总数据固定

    for (const auto threads : {1, 2, 4})
    {
        const auto per = kTotal / threads;
        const auto t0 = now_ns();
        std::vector<std::thread> ts;
        std::vector<bool> Ok(threads, false);
        for (int t = 0; t < threads; ++t)
        {
            ts.emplace_back([&, t]() { Ok[t] = run_one_conn(per, 65535); });
        }
        for (auto &th : ts)
        {
            th.join();
        }
        const auto dt = now_ns() - t0;
        const double mbps = (kTotal / 1024.0 / 1024.0) / (dt / 1e9);
        std::printf("vmess %d 连接并行（每连接 %6.1f MB）: %7.2f ms  => %8.1f MB/s 总\n", threads,
                    per / 1024.0 / 1024.0, dt / 1e6, mbps);
        if (std::any_of(Ok.begin(), Ok.end(), [](bool b) { return !b; }) || mbps < 50.0)
        {
            std::printf("FAIL threads=%d: 有连接数据面未完成或总吞吐 %.1f MB/s 过低\n", threads, mbps);
            return 1;
        }
    }
    std::printf("MultiConnLinear: ALL PASS\n");
    return 0;
}
