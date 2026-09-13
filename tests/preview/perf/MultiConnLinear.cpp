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

#include <preview/Transport/Reliable.hpp>
#include <preview/Protocols/Vmess/Vmess.hpp>

using Clock = std::chrono::steady_clock;
namespace Net = boost::asio;

namespace
{
    auto now_ns() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count();
    }

    using VmessUuid = std::array<std::uint8_t, 16>;

    auto RunServer(
        Net::ip::tcp::acceptor &Acceptor,
        const std::size_t Total,
        const std::size_t Block,
        VmessUuid Uuid) -> Net::awaitable<void>
    {
        Net::ip::tcp::socket Sock(Acceptor.get_executor());
        co_await Acceptor.async_accept(Sock, Net::use_awaitable);
        auto Ss = std::make_shared<Preview::Transport::Reliable>(std::move(Sock));
        Preview::Vmess::ServerConfig ServerConfig;
        ServerConfig.uuid = Uuid;
        auto [Err, Req, Conn] = co_await Preview::Vmess::Accept(Ss, ServerConfig);
        (void)Req;
        if (Err != Preview::Error::None || !Conn)
        {
            co_return;
        }

        std::vector<std::uint8_t> Buffer(Block);
        std::error_code Ec;
        std::size_t Done = 0;
        while (Done < Total)
        {
            const auto N = co_await Conn->async_read_some(
                std::span<std::byte>(reinterpret_cast<std::byte *>(Buffer.data()), Buffer.size()), Ec);
            if (Ec || N == 0)
            {
                break;
            }
            Done += N;
        }
        Conn->Close();
    }

    auto RunClient(
        Net::io_context &Ioc,
        const unsigned short Port,
        const std::size_t Total,
        const std::size_t Block,
        VmessUuid Uuid,
        bool &Completed) -> Net::awaitable<void>
    {
        std::vector<std::uint8_t> Chunk(Block, 0x5A);
        auto Ss = std::make_shared<Preview::Transport::Reliable>(Ioc.get_executor());
        const auto Ec = co_await Ss->Connect(
            Net::ip::tcp::endpoint(Net::ip::address_v4::loopback(), Port));
        if (Ec)
        {
            Completed = false;
            Ioc.stop();
            co_return;
        }

        Preview::Vmess::ClientConfig ClientConfig;
        ClientConfig.uuid = Uuid;
        auto [Err, Conn] = co_await Preview::Vmess::Connect(
            Ss, ClientConfig, Preview::Vmess::Address{Preview::Vmess::AddressType::Domain, "t.internal", 443});
        if (Err != Preview::Error::None || !Conn)
        {
            Completed = false;
            Ioc.stop();
            co_return;
        }

        std::size_t Done = 0;
        std::error_code WriteError;
        while (Done < Total)
        {
            const auto N = co_await Conn->async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Chunk.data()), Chunk.size()),
                WriteError);
            if (WriteError || N == 0)
            {
                Completed = false;
                break;
            }
            Done += N;
        }
        if (Done < Total)
        {
            Completed = false;
        }
        Conn->Close();
    }

    // 每线程一个完整 vmess 连接（独立 ioc，thread_local Arena 安全）
    auto RunOneConnection(const std::size_t Total, const std::size_t Block) -> bool
    {
        Net::io_context Ioc;
        Net::ip::tcp::acceptor Acceptor(
            Ioc,
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto Port = Acceptor.local_endpoint().port();
        const VmessUuid Uuid{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                             0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
        bool Completed = true; // 数据面完成标志（false = 断链/未写完，门禁 FAIL）

        Net::co_spawn(Ioc, RunServer(Acceptor, Total, Block, Uuid), Net::detached);
        Net::co_spawn(Ioc, RunClient(Ioc, Port, Total, Block, Uuid, Completed),
                      [&](std::exception_ptr) { Ioc.stop(); });
        Ioc.run();
        return Completed;
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
        // vector<bool> 使用位代理存储；不同线程写不同下标仍可能争用同一字，改用字节数组。
        std::vector<std::uint8_t> Ok(threads, 0);
        for (int t = 0; t < threads; ++t)
        {
            ts.emplace_back(
                [&, t]()
                {
                    if (RunOneConnection(per, 65535))
                    {
                        Ok[t] = 1;
                    }
                    else
                    {
                        Ok[t] = 0;
                    }
                });
        }
        for (auto &th : ts)
        {
            th.join();
        }
        const auto dt = now_ns() - t0;
        const double mbps = (kTotal / 1024.0 / 1024.0) / (dt / 1e9);
        std::printf("vmess %d 连接并行（每连接 %6.1f MB）: %7.2f ms  => %8.1f MB/s 总\n", threads,
                    per / 1024.0 / 1024.0, dt / 1e6, mbps);
        if (std::any_of(Ok.begin(), Ok.end(), [](std::uint8_t b) { return b == 0; }) || mbps < 50.0)
        {
            std::printf("FAIL threads=%d: 有连接数据面未完成或总吞吐 %.1f MB/s 过低\n", threads, mbps);
            return 1;
        }
    }
    std::printf("MultiConnLinear: ALL PASS\n");
    return 0;
}
