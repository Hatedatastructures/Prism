/**
 * @file VlessClientServerPerf.cpp
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
#include <preview/Protocols/Vless/Vless.hpp>
#include <preview/Transport/MemoryStream.hpp>

namespace Net = boost::asio;

namespace
{
    namespace Vless = Preview::Vless;

    using Address = Vless::Address;
    using AddressType = Vless::AddressType;
    using BenchOptions = Preview::BenchOptions;
    using BenchReport = Preview::BenchReport;
    using ClientConfig = Vless::ClientConfig;
    using Error = Preview::Error;
    using ExecutorType = Net::any_io_executor;
    using MemoryStream = Preview::MemoryStream;
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
        const auto HandshakeError = std::get<0>(AcceptResult);
        const auto &Request = std::get<1>(AcceptResult);
        const auto &Connection = std::get<2>(AcceptResult);
        (void)Request;
        if (HandshakeError != Error::None || !Connection)
        {
            (void)Options.Completion->try_send(
                boost::system::error_code{}, false);
            co_return;
        }

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
            const auto Count = co_await Connection->async_read_some(
                ReadWindow,
                ReadError);
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
                const auto Written = co_await Connection->async_write_some(
                    WriteWindow,
                    WriteError);
                if (WriteError || Written != Count)
                {
                    break;
                }
            }
            Received += Count;
        }
        Connection->Close();
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

    TEST(VlessClientServer, Transfer100MB)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] =
            Preview::MakeMemoryPair(IoContext.get_executor());
        constexpr std::size_t TotalBytes = 100 * 1024 * 1024;
        constexpr std::size_t BlockSize = 64 * 1024;
        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            const auto Completion = SpawnServer(
                IoContext.get_executor(),
                ServerOptions{
                    std::move(ServerStream),
                    TotalBytes,
                    BlockSize,
                    false,
                    {}});
            auto ClientResult = co_await Vless::Connect(
                std::make_shared<MemoryStream>(std::move(ClientStream)),
                MakeClientConfig(),
                MakeDestination());
            const auto HandshakeError = std::get<0>(ClientResult);
            auto Client = std::get<1>(std::move(ClientResult));
            EXPECT_EQ(HandshakeError, Error::None);
            EXPECT_NE(Client, nullptr);
            if (HandshakeError != Error::None || !Client)
            {
                co_return;
            }
            std::vector<std::uint8_t> Payload(BlockSize, 0x3C);
            std::size_t Sent = 0;
            while (Sent < TotalBytes)
            {
                const auto WriteSize =
                    std::min(BlockSize, TotalBytes - Sent);
                auto WriteWindow = std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(Payload.data()),
                    WriteSize);
                std::error_code WriteError;
                const auto Written = co_await Client->async_write_some(
                    WriteWindow,
                    WriteError);
                if (WriteError || Written == 0 || Written > WriteSize)
                {
                    break;
                }
                Sent += Written;
                if (((Sent / BlockSize) & 0x0F) == 0)
                {
                    const auto PostToken = Net::use_awaitable;
                    co_await Net::post(
                        IoContext.get_executor(),
                        PostToken);
                }
            }
            EXPECT_EQ(Sent, TotalBytes);
            Client->Close();
            const auto ServerCompleted = co_await Completion->async_receive(
                Net::use_awaitable);
            EXPECT_TRUE(ServerCompleted);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(VlessClientServer, ThroughputLatency)
    {
        Net::io_context IoContext;
        BenchReport ThroughputReport;
        BenchReport LatencyReport;
        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            auto [ClientStream, ServerStream] =
                Preview::MakeMemoryPair(IoContext.get_executor());
            constexpr std::size_t ThroughputTotal = 64 * 1024 * 1024;
            const auto ThroughputCompletion = SpawnServer(
                IoContext.get_executor(),
                ServerOptions{
                    std::move(ServerStream),
                    ThroughputTotal,
                    64 * 1024,
                    true,
                    {}});
            auto ClientResult = co_await Vless::Connect(
                std::make_shared<MemoryStream>(std::move(ClientStream)),
                MakeClientConfig(),
                MakeDestination());
            const auto HandshakeError = std::get<0>(ClientResult);
            auto Client = std::get<1>(std::move(ClientResult));
            EXPECT_EQ(HandshakeError, Error::None);
            EXPECT_NE(Client, nullptr);
            if (HandshakeError != Error::None || !Client)
            {
                co_return;
            }
            BenchOptions ThroughputOptions;
            ThroughputOptions.Total = ThroughputTotal;
            ThroughputOptions.Block = 64 * 1024;
            ThroughputReport = co_await Preview::BenchThroughputTx(
                *Client,
                *Client,
                ThroughputOptions);
            EXPECT_EQ(ThroughputReport.Bytes, ThroughputOptions.Total);
            Client->Close();
            const auto ThroughputCompleted =
                co_await ThroughputCompletion->async_receive(Net::use_awaitable);
            EXPECT_TRUE(ThroughputCompleted);

            auto [LatencyClientStream, LatencyServerStream] =
                Preview::MakeMemoryPair(IoContext.get_executor());
            constexpr std::size_t LatencyTotal = 1000 * 4 * 1024;
            const auto LatencyCompletion = SpawnServer(
                IoContext.get_executor(),
                ServerOptions{
                    std::move(LatencyServerStream),
                    LatencyTotal,
                    4 * 1024,
                    true,
                    {}});
            auto LatencyResult = co_await Vless::Connect(
                std::make_shared<MemoryStream>(std::move(LatencyClientStream)),
                MakeClientConfig(),
                MakeDestination());
            const auto LatencyHandshakeError = std::get<0>(LatencyResult);
            auto LatencyClient =
                std::get<1>(std::move(LatencyResult));
            EXPECT_EQ(LatencyHandshakeError, Error::None);
            EXPECT_NE(LatencyClient, nullptr);
            if (LatencyHandshakeError != Error::None || !LatencyClient)
            {
                co_return;
            }
            BenchOptions LatencyOptions;
            LatencyOptions.Total = LatencyTotal;
            LatencyOptions.Block = 4 * 1024;
            LatencyReport = co_await Preview::BenchThroughputTx(
                *LatencyClient,
                *LatencyClient,
                LatencyOptions);
            EXPECT_EQ(LatencyReport.Bytes, LatencyOptions.Total);
            LatencyClient->Close();
            const auto LatencyCompleted =
                co_await LatencyCompletion->async_receive(Net::use_awaitable);
            EXPECT_TRUE(LatencyCompleted);
        };
        RunCoroutine(IoContext, std::move(Coroutine));

        EXPECT_GT(ThroughputReport.Mbps, 0.0);
        EXPECT_GT(LatencyReport.Samples, 0u);
        std::printf(
            "vless throughput: %.1f MB/s | latency(ms): avg %.3f p50 %.3f "
            "p95 %.3f p99 %.3f (min %.3f max %.3f) samples=%zu\n",
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
