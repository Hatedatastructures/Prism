/**
 * @file ClientServerPerf.cpp
 * @brief VLESS 客户端/服务端封装测试（完整传输与性能）
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <TestSupport/Benchmark/Bench.hpp>
#include <gtest/gtest.h>
#include <Prism/Protocols/Vless/Vless.hpp>
#include <Prism/Transport/MemoryStream.hpp>

namespace Net = boost::asio;

namespace
{
    namespace Vless = Prism::Vless;

    using Address = Vless::Address;
    using AddressType = Vless::AddressType;
    using BenchOptions = Prism::BenchOptions;
    using BenchReport = Prism::BenchReport;
    using ClientConfig = Vless::ClientConfig;
    using Error = Prism::Error;
    using ExecutorType = Net::any_io_executor;
    using MemoryStream = Prism::MemoryStream;
    using ServerConfig = Vless::ServerConfig;
    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code, bool)>;

    struct ServerOptions
    {
        MemoryStream Stream;
        std::size_t ExpectedBytes;
        std::size_t BlockSize;
        bool Echo;
        std::shared_ptr<CompletionChannel> Completion;
    };

    template <typename Awaitable>
    auto RunCoroutine(
        Net::io_context &IoContext,
        Awaitable Coroutine) -> void
    {
        std::exception_ptr Exception;
        auto Completion =
            [&Exception, &IoContext](std::exception_ptr ErrorValue) -> void
        {
            Exception = ErrorValue;
            IoContext.stop();
        };
        Net::co_spawn(
            IoContext,
            std::move(Coroutine),
            std::move(Completion));
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    [[nodiscard]] auto MakeUuid() -> std::array<std::uint8_t, Vless::UuidLen>
    {
        std::array<std::uint8_t, Vless::UuidLen> Uuid{};
        Uuid.fill(0x55);
        return Uuid;
    }

    [[nodiscard]] auto MakeDestination() -> Address
    {
        Address Destination;
        Destination.Type = AddressType::Ipv4;
        Destination.Host = "93.184.216.34";
        Destination.Port = 443;
        return Destination;
    }

    auto RunServer(ServerOptions Options) -> Net::awaitable<void>
    {
        ServerConfig Config;
        Config.uuid = MakeUuid();
        const auto AcceptResult = co_await Vless::Accept(
            std::make_shared<MemoryStream>(std::move(Options.Stream)),
            Config);
        EXPECT_TRUE(AcceptResult);
        if (AcceptResult) EXPECT_TRUE(AcceptResult->Connection);
        if (!AcceptResult || !AcceptResult->Connection)
        {
            (void)Options.Completion->try_send(
                boost::system::error_code{}, false);
            co_return;
        }
        auto Connection = std::move(AcceptResult->Connection);

        std::vector<std::byte> Buffer(Options.BlockSize);
        std::size_t Received = 0;
        while (Received < Options.ExpectedBytes)
        {
            const auto ReadSize =
                std::min(Options.BlockSize, Options.ExpectedBytes - Received);
            auto ReadWindow = std::span<std::byte>(
                Buffer.data(),
                ReadSize);
            std::error_code ReadError;
            const auto Read = co_await Connection->ReadSome(ReadWindow);
            ReadError = Prism::Fault::ToNative(Read.Failure);
            const auto Count = Read.Bytes;
            if (ReadError || Count == 0 || Count > ReadSize)
            {
                break;
            }
            if (Options.Echo)
            {
                std::error_code WriteError;
                auto WriteWindow = std::span<const std::byte>(
                    Buffer.data(),
                    Count);
                const auto Write = co_await Connection->WriteSome(WriteWindow);
                WriteError = Prism::Fault::ToNative(Write.Failure);
                const auto Written = Write.Bytes;
                if (WriteError || Written != Count)
                {
                    break;
                }
            }
            Received += Count;
        }
        (void)Connection->Close();
        const bool Completed = Received == Options.ExpectedBytes;
        (void)Options.Completion->try_send(
            boost::system::error_code{},
            Completed);
    }

    [[nodiscard]] auto SpawnServer(
        ExecutorType Executor,
        ServerOptions Options)
        -> std::shared_ptr<CompletionChannel>
    {
        const auto Done =
            std::make_shared<CompletionChannel>(Executor, 1);
        Options.Completion = Done;
        auto Completion =
            [Done](std::exception_ptr Exception) -> void
        {
            if (Exception)
            {
                (void)Done->try_send(
                    boost::system::error_code{}, false);
            }
        };
        Net::co_spawn(
            Executor,
            RunServer(std::move(Options)),
            std::move(Completion));
        return Done;
    }

    [[nodiscard]] auto MakeServerConfig() -> ServerConfig
    {
        ServerConfig Config;
        Config.uuid = MakeUuid();
        return Config;
    }

    [[nodiscard]] auto MakeClientConfig() -> ClientConfig
    {
        ClientConfig Config;
        Config.uuid = MakeUuid();
        return Config;
    }

    struct Transfer100MbRequest final
    {
        Net::io_context &IoContext;
        MemoryStream ClientStream;
        MemoryStream ServerStream;
        std::size_t TotalBytes;
        std::size_t BlockSize;
    };

    auto RunTransfer100Mb(Transfer100MbRequest Request) -> Net::awaitable<void>
    {
        const auto Completion = SpawnServer(
            Request.IoContext.get_executor(),
            ServerOptions{
                std::move(Request.ServerStream),
                Request.TotalBytes,
                Request.BlockSize,
                false,
                {}});
        auto ClientResult = co_await Vless::Connect(Vless::ConnectParameters{
            std::make_shared<MemoryStream>(std::move(Request.ClientStream)),
            MakeClientConfig(),
            MakeDestination()});
        EXPECT_TRUE(ClientResult);
        if (ClientResult) EXPECT_TRUE(*ClientResult);
        if (!ClientResult || !*ClientResult)
        {
            co_return;
        }
        auto Client = std::move(*ClientResult);
        std::vector<std::uint8_t> Payload(Request.BlockSize, 0x3C);
        std::size_t Sent = 0;
        while (Sent < Request.TotalBytes)
        {
            const auto WriteSize = std::min(Request.BlockSize, Request.TotalBytes - Sent);
            const auto WriteWindow = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Payload.data()), WriteSize);
            const auto Write = co_await Client->WriteSome(WriteWindow);
            const auto WriteError = Prism::Fault::ToNative(Write.Failure);
            if (WriteError || Write.Bytes == 0 || Write.Bytes > WriteSize)
            {
                break;
            }
            Sent += Write.Bytes;
            if (((Sent / Request.BlockSize) & 0x0F) == 0)
            {
                co_await Net::post(Request.IoContext.get_executor(), Net::use_awaitable);
            }
        }
        EXPECT_EQ(Sent, Request.TotalBytes);
        (void)Client->Close();
        const auto ServerCompleted = co_await Completion->async_receive(Net::use_awaitable);
        EXPECT_TRUE(ServerCompleted);
    }

    struct ThroughputLatencyResult final
    {
        BenchReport Throughput;
        BenchReport Latency;
    };

    auto RunThroughputLatency(
        Net::io_context &IoContext,
        std::shared_ptr<ThroughputLatencyResult> Result) -> Net::awaitable<void>
    {
        auto [ClientStream, ServerStream] = Prism::MakeMemoryPair(IoContext.get_executor());
        constexpr std::size_t ThroughputTotal = 64 * 1024 * 1024;
        const auto ThroughputCompletion = SpawnServer(
            IoContext.get_executor(),
            ServerOptions{std::move(ServerStream), ThroughputTotal, 64 * 1024, true, {}});
        auto ClientResult = co_await Vless::Connect(Vless::ConnectParameters{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            MakeClientConfig(), MakeDestination()});
        EXPECT_TRUE(ClientResult);
        if (ClientResult) EXPECT_TRUE(*ClientResult);
        if (!ClientResult || !*ClientResult)
        {
            co_return;
        }
        auto Client = std::move(*ClientResult);
        BenchOptions ThroughputOptions;
        ThroughputOptions.Total = ThroughputTotal;
        ThroughputOptions.Block = 64 * 1024;
        Result->Throughput = co_await Prism::BenchThroughputTx(
            *Client, *Client, ThroughputOptions);
        EXPECT_EQ(Result->Throughput.Bytes, ThroughputOptions.Total);
        (void)Client->Close();
        const auto ThroughputCompleted =
            co_await ThroughputCompletion->async_receive(Net::use_awaitable);
        EXPECT_TRUE(ThroughputCompleted);

        auto [LatencyClientStream, LatencyServerStream] = Prism::MakeMemoryPair(IoContext.get_executor());
        constexpr std::size_t LatencyTotal = 1000 * 4 * 1024;
        const auto LatencyCompletion = SpawnServer(
            IoContext.get_executor(),
            ServerOptions{std::move(LatencyServerStream), LatencyTotal, 4 * 1024, true, {}});
        auto LatencyResult = co_await Vless::Connect(Vless::ConnectParameters{
            std::make_shared<MemoryStream>(std::move(LatencyClientStream)),
            MakeClientConfig(), MakeDestination()});
        EXPECT_TRUE(LatencyResult);
        if (LatencyResult) EXPECT_TRUE(*LatencyResult);
        if (!LatencyResult || !*LatencyResult)
        {
            co_return;
        }
        auto LatencyClient = std::move(*LatencyResult);
        BenchOptions LatencyOptions;
        LatencyOptions.Total = LatencyTotal;
        LatencyOptions.Block = 4 * 1024;
        Result->Latency = co_await Prism::BenchThroughputTx(
            *LatencyClient, *LatencyClient, LatencyOptions);
        EXPECT_EQ(Result->Latency.Bytes, LatencyOptions.Total);
        (void)LatencyClient->Close();
        const auto LatencyCompleted =
            co_await LatencyCompletion->async_receive(Net::use_awaitable);
        EXPECT_TRUE(LatencyCompleted);
    }

    TEST(VlessClientServer, Transfer100MB)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] =
            Prism::MakeMemoryPair(IoContext.get_executor());
        constexpr std::size_t TotalBytes = 100 * 1024 * 1024;
        constexpr std::size_t BlockSize = 64 * 1024;
        RunCoroutine(IoContext, RunTransfer100Mb(Transfer100MbRequest{
            IoContext, std::move(ClientStream), std::move(ServerStream), TotalBytes, BlockSize}));
    }

    TEST(VlessClientServer, ThroughputLatency)
    {
        Net::io_context IoContext;
        auto Result = std::make_shared<ThroughputLatencyResult>();
        RunCoroutine(IoContext, RunThroughputLatency(IoContext, Result));

        EXPECT_GT(Result->Throughput.Mbps, 0.0);
        EXPECT_GT(Result->Latency.Samples, 0u);
        std::printf(
            "vless throughput: %.1f MB/s | latency(ms): avg %.3f p50 %.3f "
            "p95 %.3f p99 %.3f (min %.3f max %.3f) samples=%zu\n",
            Result->Throughput.Mbps,
            Result->Latency.LatencyAvg,
            Result->Latency.LatencyP50,
            Result->Latency.LatencyP95,
            Result->Latency.LatencyP99,
            Result->Latency.LatencyMin,
            Result->Latency.LatencyMax,
            Result->Latency.Samples);
    }
} // namespace
