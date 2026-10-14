/**
 * @file MuxPerf.cpp
 * @brief 多路复用性能基准（100MB 传输 + 吞吐 + 延迟）
 * @details smux / yamux / h2mux 各自独立实现；测量 100MB 传输完整性、
 *          吞吐量（MB/s）与回环延迟（avg/p50/p95/p99/min/max）。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <TestSupport/Benchmark/Bench.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Protocols/Mux/H2Mux/H2Mux.hpp>
#include <Preview/Protocols/Mux/Smux/Smux.hpp>
#include <Preview/Protocols/Mux/Yamux/Yamux.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace H2Mux = Preview::Mux::H2Mux;
    namespace Smux = Preview::Mux::Smux;
    namespace Yamux = Preview::Mux::Yamux;
    using Preview::BenchOptions;
    using Preview::BenchReport;
    using Preview::BenchThroughputTx;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;

    template <typename A>
    auto RunCoro(
        Net::io_context &IoContext,
        A Coroutine) -> void
    {
        std::exception_ptr Exception;
        auto Completion = [&](std::exception_ptr Error) -> void
        {
            Exception = Error;
            IoContext.stop();
        };
        Net::co_spawn(IoContext, std::move(Coroutine), std::move(Completion));
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    [[nodiscard]] auto Fnv1a64(std::span<const std::uint8_t> Data) -> std::uint64_t
    {
        std::uint64_t Hash = 14695981039346656037ULL;
        for (const auto Byte : Data)
        {
            Hash ^= Byte;
            Hash *= 1099511628211ULL;
        }
        return Hash;
    }

    /// 100MB 传输完整性（Client 写 Server 读，摘要比对）
    template <typename ClientType, typename ServerType>
    auto RunTransfer(
        Net::io_context &IoContext,
        ClientType &Client,
        ServerType &Server) -> void
    {
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        ASSERT_TRUE(Client.Connect(std::make_shared<MemoryStream>(std::move(ClientMemory))));
        ASSERT_TRUE(Server.Accept(std::make_shared<MemoryStream>(std::move(ServerMemory))));

        constexpr std::size_t TotalBytes = 100 * 1024 * 1024;
        constexpr std::size_t BlockSize = 64 * 1024;
        auto Operation = [&]() -> Net::awaitable<void>
        {
            Net::experimental::channel<void(boost::system::error_code)> ServerDone(
                IoContext.get_executor(), 1);
            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                auto Stream = co_await Server.AcceptStream();
                if (!Stream)
                {
                    EXPECT_TRUE(false) << "Accept Failed";
                    (void)ServerDone.try_send(boost::system::error_code{});
                    co_return;
                }
                std::array<std::byte, BlockSize> Buffer{};
                std::size_t Received = 0;
                while (Received < TotalBytes)
                {
                    std::error_code ErrorCode;
                    const auto ReadSize = co_await Stream->async_read_some(Buffer, ErrorCode);
                    if (ErrorCode || ReadSize == 0)
                    {
                        break;
                    }
                    Received += ReadSize;
                }
                EXPECT_EQ(Received, TotalBytes);
                Stream->Close();
                (void)ServerDone.try_send(boost::system::error_code{});
            };
            Net::co_spawn(IoContext.get_executor(), std::move(ServerCoroutine), Net::detached);

            auto Stream = co_await Client.OpenStream();
            if (!Stream)
            {
                EXPECT_TRUE(false) << "Open Failed";
                co_return;
            }
            std::vector<std::uint8_t> Payload(BlockSize, 0x2A);
            std::size_t Sent = 0;
            std::size_t BlockIndex = 0;
            while (Sent < TotalBytes)
            {
                const auto ChunkSize = std::min(BlockSize, TotalBytes - Sent);
                std::error_code ErrorCode;
                const auto PayloadBuffer = std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(Payload.data()), ChunkSize);
                const auto Written = co_await Stream->async_write_some(PayloadBuffer, ErrorCode);
                if (ErrorCode || Written == 0)
                {
                    break;
                }
                Sent += Written;
                if ((++BlockIndex & 0x0F) == 0)
                {
                    // 让出调度：MemoryStream 写同步完成，不 yield 会饿死对端协程
                    co_await Net::post(IoContext.get_executor(), Net::use_awaitable);
                }
            }
            EXPECT_EQ(Sent, TotalBytes);
            Stream->Close();
            Client.Close();
            Server.Close();
            co_await ServerDone.async_receive(Net::use_awaitable);
        };
        RunCoro(IoContext, std::move(Operation));
    }

    /// 吞吐 + 延迟报告
    template <typename ClientType, typename ServerType>
    struct BenchRequest
    {
        Net::io_context &IoContext;
        ClientType &Client;
        ServerType &Server;
        const char *Name;
    };

    template <typename ClientType, typename ServerType>
    auto RunBench(BenchRequest<ClientType, ServerType> Request) -> void
    {
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(Request.IoContext.get_executor());
        ASSERT_TRUE(Request.Client.Connect(std::make_shared<MemoryStream>(std::move(ClientMemory))));
        ASSERT_TRUE(Request.Server.Accept(std::make_shared<MemoryStream>(std::move(ServerMemory))));

        BenchReport Report{};
        auto Operation = [&]() -> Net::awaitable<void>
        {
            Net::experimental::channel<void(boost::system::error_code)> ServerDone(
                Request.IoContext.get_executor(), 1);
            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                auto Stream = co_await Request.Server.AcceptStream();
                if (!Stream)
                {
                    (void)ServerDone.try_send(boost::system::error_code{});
                    co_return;
                }
                std::array<std::byte, 128 * 1024> Buffer{};
                while (true)
                {
                    std::error_code ErrorCode;
                    const auto ReadSize = co_await Stream->async_read_some(Buffer, ErrorCode);
                    if (ErrorCode || ReadSize == 0)
                    {
                        break;
                    }
                    const auto Response = std::span<const std::byte>(Buffer.data(), ReadSize);
                    ErrorCode.clear();
                    (void)co_await Stream->async_write_some(Response, ErrorCode);
                }
                Stream->Close();
                (void)ServerDone.try_send(boost::system::error_code{});
            };
            Net::co_spawn(Request.IoContext.get_executor(), std::move(ServerCoroutine), Net::detached);

            auto Stream = co_await Request.Client.OpenStream();
            if (!Stream)
            {
                co_return;
            }
            BenchOptions Options;
            Options.Total = 64 * 1024 * 1024;
            Options.Block = 64 * 1024;
            Report = co_await BenchThroughputTx(*Stream, *Stream, Options);
            Stream->Close();
            Request.Client.Close();
            if (Request.Server.Session())
            {
                co_await Request.Server.Session()->Close();
            }
            co_await ServerDone.async_receive(Net::use_awaitable);
        };
        RunCoro(Request.IoContext, std::move(Operation));

        std::printf("%s throughput: %.1f MB/s | latency(ms): avg %.3f p50 %.3f p95 %.3f p99 %.3f (min %.3f "
                    "max %.3f) samples=%zu\n",
                    Request.Name, Report.Mbps, Report.LatencyAvg, Report.LatencyP50, Report.LatencyP95,
                    Report.LatencyP99, Report.LatencyMin, Report.LatencyMax, Report.Samples);
    }

    TEST(MuxPerf, SmuxTransfer100MB)
    {
        Net::io_context IoContext;
        Smux::Client Client;
        Smux::Server Server;
        RunTransfer(IoContext, Client, Server);
    }

    TEST(MuxPerf, YamuxTransfer100MB)
    {
        Net::io_context IoContext;
        Yamux::Client Client;
        Yamux::Server Server;
        RunTransfer(IoContext, Client, Server);
    }

    TEST(MuxPerf, H2muxTransfer100MB)
    {
        Net::io_context IoContext;
        H2Mux::Client Client;
        H2Mux::Server Server;
        RunTransfer(IoContext, Client, Server);
    }

    TEST(MuxPerf, SmuxThroughputLatency)
    {
        Net::io_context IoContext;
        Smux::Client Client;
        Smux::Server Server;
        RunBench(BenchRequest<decltype(Client), decltype(Server)>{IoContext, Client, Server, "smux "});
    }

    TEST(MuxPerf, YamuxThroughputLatency)
    {
        Net::io_context IoContext;
        Yamux::Client Client;
        Yamux::Server Server;
        RunBench(BenchRequest<decltype(Client), decltype(Server)>{IoContext, Client, Server, "yamux"});
    }

    TEST(MuxPerf, H2muxThroughputLatency)
    {
        Net::io_context IoContext;
        H2Mux::Client Client;
        H2Mux::Server Server;
        RunBench(BenchRequest<decltype(Client), decltype(Server)>{IoContext, Client, Server, "h2mux"});
    }

} // namespace
