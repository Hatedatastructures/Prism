/**
 * @file VmessMultiThread.cpp
 * @brief vmess 多线程并行测试（Release）
 * @details 单线程 vs 2/4 线程 ioc：验证"性能低"是否因读写串行化
 */

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

#include <common/core/transport/socket_stream.hpp>
#include <common/proxy/vmess/vmess.hpp>

using clk = std::chrono::steady_clock;
namespace net = boost::asio;

namespace
{
    auto now_ns() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(clk::now().time_since_epoch()).count();
    }

    auto bench(const std::size_t total, const std::size_t block, const int threads) -> std::int64_t
    {
        using namespace psmtest;
        net::io_context ioc;
        net::ip::tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto port = acceptor.local_endpoint().port();
        std::vector<std::uint8_t> chunk(block, 0x5A);
        const auto uuid = std::array<std::uint8_t, 16>{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                                        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};

        const std::int64_t t0 = now_ns();
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                net::ip::tcp::socket sock(ioc);
                co_await acceptor.async_accept(sock, net::use_awaitable);
                auto ss = std::make_shared<socket_stream>(std::move(sock));
                vmess::server_config scfg;
                scfg.uuid = uuid;
                auto [err, req, conn] = co_await vmess::accept(ss, scfg);
                if (err != error::none || !conn)
                {
                    co_return;
                }
                std::vector<std::uint8_t> buf(block);
                std::error_code ec;
                std::size_t done = 0;
                while (done < total)
                {
                    const auto n = co_await conn->async_read_some(
                        std::span<std::byte>(reinterpret_cast<std::byte *>(buf.data()), buf.size()), ec);
                    if (ec || n == 0)
                    {
                        break;
                    }
                    done += n;
                }
                conn->close();
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            auto ss = std::make_shared<socket_stream>(ioc.get_executor());
            const auto ec2 = co_await ss->connect(net::ip::tcp::endpoint(net::ip::address_v4::loopback(), port));
            if (ec2)
            {
                ioc.stop();
                co_return;
            }
            vmess::client_config ccfg;
            ccfg.uuid = uuid;
            auto [err, conn] = co_await vmess::connect(
                ss, ccfg, vmess::address{vmess::address_type::domain, "t.internal", 443});
            if (err != error::none || !conn)
            {
                ioc.stop();
                co_return;
            }
            std::size_t done = 0;
            std::error_code ec;
            while (done < total)
            {
                const auto n = co_await conn->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(chunk.data()), block), ec);
                done += n;
            }
            conn->close();
        }, [&](std::exception_ptr) { ioc.stop(); });

        // 多线程跑 ioc
        std::vector<std::thread> ts;
        for (int t = 0; t < threads; ++t)
        {
            ts.emplace_back([&]() { ioc.run(); });
        }
        for (auto &th : ts)
        {
            th.join();
        }
        return now_ns() - t0;
    }
} // namespace

int main()
{
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    constexpr std::size_t kTotal = 256ULL * 1024 * 1024;

    for (const auto block : {16384UL, 65535UL})
    {
        for (const auto threads : {1, 2, 4})
        {
            std::array<std::int64_t, 3> s{};
            for (int i = 0; i < 3; ++i)
            {
                s[i] = bench(kTotal, block, threads);
            }
            std::sort(s.begin(), s.end());
            std::printf("vmess chunk=%6zu 线程=%d: med=%7.2f ms  => %8.1f MB/s\n", block, threads,
                        s[1] / 1e6, (kTotal / 1024.0 / 1024.0) / (s[1] / 1e9));
        }
    }
    return 0;
}
