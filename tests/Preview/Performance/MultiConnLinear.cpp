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
#include <variant>
#include <vector>

#include <Preview/Transport/Reliable.hpp>
#include <Preview/Protocols/Vmess/Vmess.hpp>

using Clock = std::chrono::steady_clock;
namespace Net = boost::asio;

namespace
{
    auto now_ns() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count();
    }

    using VmessUuid = std::array<std::uint8_t, 16>;

    struct VmessServerRequest final
    {
        Net::ip::tcp::acceptor &Acceptor;
        std::size_t Total{0};
        std::size_t Block{0};
        VmessUuid Uuid{};
    };

    struct VmessClientRequest final
    {
        Net::io_context &IoContext;
        unsigned short Port{0};
        std::size_t Total{0};
        std::size_t Block{0};
        VmessUuid Uuid{};
        bool &Completed;
    };

    auto RunServer(VmessServerRequest Request) -> Net::awaitable<void>
    {
        Net::ip::tcp::socket Sock(Request.Acceptor.get_executor());
        co_await Request.Acceptor.async_accept(Sock, Net::use_awaitable);
        auto Ss = std::make_shared<Preview::Transport::Reliable>(std::move(Sock));
        Preview::Vmess::ServerConfig ServerConfig;
        ServerConfig.uuid = Request.Uuid;
        auto AcceptResult = co_await Preview::Vmess::AcceptSession(Ss, ServerConfig);
        EXPECT_TRUE(AcceptResult);
        auto *Accepted = AcceptResult
            ? std::get_if<Preview::Vmess::AcceptedConnection>(&*AcceptResult)
            : nullptr;
        if (AcceptResult) EXPECT_NE(Accepted, nullptr);
        if (!AcceptResult || !Accepted || !Accepted->Connection)
        {
            if (AcceptResult && std::holds_alternative<Preview::Vmess::AcceptedDatagram>(*AcceptResult))
            {
                auto Datagram = std::move(
                    std::get<Preview::Vmess::AcceptedDatagram>(*AcceptResult).Connection);
                auto Underlying = Datagram->Stream();
                (void)Datagram->Close();
                (void)Underlying->Close();
                (void)co_await Datagram->Activity()->Drain();
                (void)co_await Underlying->Activity()->Drain();
            }
            co_return;
        }
        auto Conn = std::move(Accepted->Connection);

        std::vector<std::uint8_t> Buffer(Request.Block);
        std::size_t Done = 0;
        while (Done < Request.Total)
        {
            const auto Window = std::span<std::byte>(
                reinterpret_cast<std::byte *>(Buffer.data()), Buffer.size());
            const auto Read = co_await Conn->ReadSome(Window);
            if (Read.Bytes > Window.size())
            {
                break;
            }
            Done += Read.Bytes;
            if (Read.Failure.Failed() || Read.Bytes == 0)
            {
                break;
            }
        }
        (void)Conn->Close();
    }

    auto RunClient(VmessClientRequest Request) -> Net::awaitable<void>
    {
        std::vector<std::uint8_t> Chunk(Request.Block, 0x5A);
        auto Ss = std::make_shared<Preview::Transport::Reliable>(Request.IoContext.get_executor());
        const auto Ec = co_await Ss->Connect(
            Net::ip::tcp::endpoint(Net::ip::address_v4::loopback(), Request.Port));
        if (Ec)
        {
            Request.Completed = false;
            Request.IoContext.stop();
            co_return;
        }

        Preview::Vmess::ClientConfig ClientConfig;
        ClientConfig.uuid = Request.Uuid;
        auto ConnectResult = co_await Preview::Vmess::Connect(Preview::Vmess::ConnectParameters{
            Ss, ClientConfig, Preview::Vmess::Address{Preview::Vmess::AddressType::Domain, "t.internal", 443}});
        EXPECT_TRUE(ConnectResult);
        if (ConnectResult) EXPECT_TRUE(*ConnectResult);
        if (!ConnectResult || !*ConnectResult)
        {
            Request.Completed = false;
            Request.IoContext.stop();
            co_return;
        }
        auto Conn = std::move(*ConnectResult);

        std::size_t Done = 0;
        while (Done < Request.Total)
        {
            const auto WriteSize = std::min(Chunk.size(), Request.Total - Done);
            const auto Window = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Chunk.data()), WriteSize);
            std::size_t BlockWritten = 0;
            while (BlockWritten < WriteSize)
            {
                const auto Remaining = Window.subspan(BlockWritten);
                const auto Write = co_await Conn->WriteSome(Remaining);
                if (Write.Bytes > Remaining.size())
                {
                    Request.Completed = false;
                    break;
                }
                BlockWritten += Write.Bytes;
                Done += Write.Bytes;
                if (Write.Failure.Failed() || Write.Bytes == 0)
                {
                    Request.Completed = false;
                    break;
                }
            }
            if (!Request.Completed)
            {
                break;
            }
        }
        if (Done < Request.Total)
        {
            Request.Completed = false;
        }
        (void)Conn->Close();
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

        Net::co_spawn(Ioc, RunServer(VmessServerRequest{Acceptor, Total, Block, Uuid}), Net::detached);
        Net::co_spawn(Ioc, RunClient(VmessClientRequest{Ioc, Port, Total, Block, Uuid, Completed}),
                      [&](std::exception_ptr) { Ioc.stop(); });
        Ioc.run();
        return Completed;
    }

    auto RunThreadConnection(const std::size_t Total, const std::size_t Lane,
                             std::vector<std::uint8_t> &Results) -> void
    {
        Results[Lane] = RunOneConnection(Total, 65535) ? 1U : 0U;
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
            ts.emplace_back(RunThreadConnection, per, static_cast<std::size_t>(t), std::ref(Ok));
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
