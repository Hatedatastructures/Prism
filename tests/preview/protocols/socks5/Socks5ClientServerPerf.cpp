/**
 * @file Socks5ClientServerPerf.cpp
 * @brief SOCKS5 客户端/服务端完整会话测试（握手 + 传输 + 性能）
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <TestSupport/Benchmark/Bench.hpp>
#include <preview/Transport/MemoryStream.hpp>
#include <preview/Protocols/Socks5/Socks5.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Socks5 = Preview::Socks5;
    using Preview::BenchOptions;
    using Preview::BenchReport;
    using Preview::BenchThroughputTx;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;

    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    template <typename Awaitable>
    auto RunCoro(
        Net::io_context &IoContext,
        Awaitable Operation) -> void
    {
        std::exception_ptr Exception;
        auto Completion = [&](std::exception_ptr ErrorValue) -> void
        {
            Exception = ErrorValue;
            IoContext.stop();
        };
        Net::co_spawn(IoContext, std::move(Operation), std::move(Completion));
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    [[nodiscard]] auto MakeDestination() -> Socks5::Address
    {
        Socks5::Address Destination{};
        Destination.Type = Socks5::AddressType::Ipv4;
        Destination.Host = "93.184.216.34";
        Destination.Port = 443;
        return Destination;
    }

    TEST(Socks5ClientServer, HandshakeAndTransfer100MB)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());

        constexpr std::size_t TotalBytes = 100 * 1024 * 1024;
        constexpr std::size_t BlockSize = 64 * 1024;
        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                {
                    auto ServerDone = std::make_shared<CompletionChannel>(
                        IoContext.get_executor(), 1);
                    auto ServerTransport = std::make_shared<MemoryStream>(std::move(ServerMemory));
                    auto ServerCoroutine = [
                        ServerTransport = std::move(ServerTransport), TotalBytes, BlockSize]() mutable
                        -> Net::awaitable<void>
                    {
                        Socks5::ServerConfig ServerConfig{};
                        auto [AcceptError, Request, Connection] = co_await Socks5::Accept(
                            std::move(ServerTransport), ServerConfig);
                        if (AcceptError != Error::None || !Connection)
                        {
                            EXPECT_TRUE(false) << "Accept Failed";
                            co_return;
                        }
                        EXPECT_EQ(Request.Target.Port, 443u);
                        std::array<std::byte, BlockSize> Buffer{};
                        std::size_t Received = 0;
                        while (Received < TotalBytes)
                        {
                            std::error_code ErrorCode;
                            const auto ReadSize = co_await Connection->async_read_some(Buffer, ErrorCode);
                            if (ErrorCode || ReadSize == 0)
                            {
                                break;
                            }
                            Received += ReadSize;
                        }
                        EXPECT_EQ(Received, TotalBytes);
                        Connection->Close();
                    };
                    auto ServerCompletion = [ServerDone](std::exception_ptr) -> void
                    {
                        (void)ServerDone->try_send(boost::system::error_code{});
                    };
                    Net::co_spawn(
                        IoContext.get_executor(), std::move(ServerCoroutine), std::move(ServerCompletion));

                    Socks5::ClientConfig ClientConfig{};
                    auto ClientTransport = std::make_shared<MemoryStream>(std::move(ClientMemory));
                    const auto Destination = MakeDestination();
                    auto [ConnectError, Client] = co_await Socks5::Connect(
                        std::move(ClientTransport), ClientConfig, Destination);
                    if (ConnectError != Error::None || !Client)
                    {
                        EXPECT_TRUE(false) << "Connect Failed";
                        co_return;
                    }
                    std::vector<std::uint8_t> Payload(BlockSize, 0x6D);
                    std::size_t Sent = 0;
                    std::size_t YieldCount = 0;
                    while (Sent < TotalBytes)
                    {
                        if ((++YieldCount % 16) == 0)
                        {
                            co_await Net::post(IoContext.get_executor(), Net::use_awaitable);
                        }
                        const auto ChunkSize = std::min(BlockSize, TotalBytes - Sent);
                        std::size_t WrittenTotal = 0;
                        while (WrittenTotal < ChunkSize)
                        {
                            std::error_code ErrorCode;
                            const auto PayloadBuffer = std::span<const std::byte>(
                                reinterpret_cast<const std::byte *>(Payload.data() + WrittenTotal),
                                ChunkSize - WrittenTotal);
                            const auto Written = co_await Client->async_write_some(PayloadBuffer, ErrorCode);
                            if (ErrorCode || Written == 0)
                            {
                                break;
                            }
                            WrittenTotal += Written;
                        }
                        if (WrittenTotal < ChunkSize)
                        {
                            break;
                        }
                        Sent += ChunkSize;
                    }
                    EXPECT_EQ(Sent, TotalBytes);
                    Client->Close();
                    co_await ServerDone->async_receive(Net::use_awaitable);
                });
    }

    TEST(Socks5ClientServer, ThroughputLatency)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());

        BenchReport ThroughputReport{};
        BenchReport LatencyReport{};
        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                {
                    auto ServerDone = std::make_shared<CompletionChannel>(
                        IoContext.get_executor(), 1);
                    auto ServerTransport = std::make_shared<MemoryStream>(std::move(ServerMemory));
                    auto ServerCoroutine = [ServerTransport = std::move(ServerTransport)]() mutable
                        -> Net::awaitable<void>
                    {
                        Socks5::ServerConfig ServerConfig{};
                        auto [AcceptError, Request, Connection] = co_await Socks5::Accept(
                            std::move(ServerTransport), ServerConfig);
                        (void)Request;
                        if (AcceptError != Error::None || !Connection)
                        {
                            co_return;
                        }
                        std::array<std::byte, 128 * 1024> Buffer{};
                        while (true)
                        {
                            std::error_code ErrorCode;
                            const auto ReadSize = co_await Connection->async_read_some(Buffer, ErrorCode);
                            if (ErrorCode || ReadSize == 0)
                            {
                                break;
                            }
                            const auto Response = std::span<const std::byte>(Buffer.data(), ReadSize);
                            ErrorCode.clear();
                            (void)co_await Connection->async_write_some(Response, ErrorCode);
                        }
                        Connection->Close();
                    };
                    auto ServerCompletion = [ServerDone](std::exception_ptr) -> void
                    {
                        (void)ServerDone->try_send(boost::system::error_code{});
                    };
                    Net::co_spawn(
                        IoContext.get_executor(), std::move(ServerCoroutine), std::move(ServerCompletion));

                    Socks5::ClientConfig ClientConfig{};
                    auto ClientTransport = std::make_shared<MemoryStream>(std::move(ClientMemory));
                    const auto Destination = MakeDestination();
                    auto [ConnectError, Client] = co_await Socks5::Connect(
                        std::move(ClientTransport), ClientConfig, Destination);
                    if (ConnectError != Error::None || !Client)
                    {
                        co_return;
                    }
                    BenchOptions ThroughputOptions;
                    ThroughputOptions.Total = 64 * 1024 * 1024;
                    ThroughputOptions.Block = 64 * 1024;
                    ThroughputReport = co_await BenchThroughputTx(
                        *Client, *Client, ThroughputOptions);
                    Client->Close();
                    co_await ServerDone->async_receive(Net::use_awaitable);

                    auto [LatencyClientMemory, LatencyServerMemory] = MakeMemoryPair(
                        IoContext.get_executor());
                    auto LatencyServerDone = std::make_shared<CompletionChannel>(
                        IoContext.get_executor(), 1);
                    auto LatencyServerTransport = std::make_shared<MemoryStream>(
                        std::move(LatencyServerMemory));
                    auto LatencyServerCoroutine = [
                        LatencyServerTransport = std::move(LatencyServerTransport)]() mutable
                        -> Net::awaitable<void>
                    {
                        Socks5::ServerConfig ServerConfig{};
                        auto [AcceptError, Request, Connection] = co_await Socks5::Accept(
                            std::move(LatencyServerTransport), ServerConfig);
                        (void)Request;
                        if (AcceptError != Error::None || !Connection)
                        {
                            co_return;
                        }
                        std::array<std::byte, 128 * 1024> Buffer{};
                        while (true)
                        {
                            std::error_code ErrorCode;
                            const auto ReadSize = co_await Connection->async_read_some(Buffer, ErrorCode);
                            if (ErrorCode || ReadSize == 0)
                            {
                                break;
                            }
                            const auto Response = std::span<const std::byte>(Buffer.data(), ReadSize);
                            ErrorCode.clear();
                            (void)co_await Connection->async_write_some(Response, ErrorCode);
                        }
                        Connection->Close();
                    };
                    auto LatencyServerCompletion = [LatencyServerDone](std::exception_ptr) -> void
                    {
                        (void)LatencyServerDone->try_send(boost::system::error_code{});
                    };
                    Net::co_spawn(IoContext.get_executor(), std::move(LatencyServerCoroutine),
                                  std::move(LatencyServerCompletion));

                    auto LatencyClientTransport = std::make_shared<MemoryStream>(
                        std::move(LatencyClientMemory));
                    const auto LatencyDestination = MakeDestination();
                    auto [LatencyConnectError, LatencyClient] = co_await Socks5::Connect(
                        std::move(LatencyClientTransport), ClientConfig, LatencyDestination);
                    if (LatencyConnectError != Error::None || !LatencyClient)
                    {
                        co_return;
                    }
                    BenchOptions LatencyOptions;
                    LatencyOptions.Total = 1000 * 4 * 1024;
                    LatencyOptions.Block = 4 * 1024;
                    LatencyReport = co_await BenchThroughputTx(
                        *LatencyClient, *LatencyClient, LatencyOptions);
                    LatencyClient->Close();
                    co_await LatencyServerDone->async_receive(Net::use_awaitable);
                });

        std::printf("socks5 throughput: %.1f MB/s | latency(ms): avg %.3f p50 %.3f p95 %.3f p99 %.3f (min "
                    "%.3f max %.3f) samples=%zu\n",
                    ThroughputReport.Mbps,
                    LatencyReport.LatencyAvg,
                    LatencyReport.LatencyP50,
                    LatencyReport.LatencyP95,
                    LatencyReport.LatencyP99,
                    LatencyReport.LatencyMin,
                    LatencyReport.LatencyMax,
                    LatencyReport.Samples);
    }

} // namespace
