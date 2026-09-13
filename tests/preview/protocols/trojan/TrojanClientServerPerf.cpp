/**
 * @file TrojanClientServerPerf.cpp
 * @brief Trojan 客户端/服务端封装测试（完整传输与性能）
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <memory>
#include <span>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>

#include <TestSupport/Benchmark/Bench.hpp>
#include <gtest/gtest.h>
#include <preview/Protocols/Trojan/Trojan.hpp>
#include <preview/Transport/MemoryStream.hpp>

namespace Net = boost::asio;

namespace
{
    namespace Trojan = Preview::Trojan;

    using Address = Trojan::Address;
    using AddressType = Trojan::AddressType;
    using BenchOptions = Preview::BenchOptions;
    using BenchReport = Preview::BenchReport;
    using ClientConfig = Trojan::ClientConfig;
    using Error = Preview::Error;
    using ExecutorType = Net::any_io_executor;
    using MemoryStream = Preview::MemoryStream;
    using ServerConfig = Trojan::ServerConfig;
    struct ServerOptions
    {
        std::size_t ExpectedBytes;
        std::size_t BlockSize;
        bool Echo;
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

    [[nodiscard]] auto MakeDestination() -> Address
    {
        Address Destination;
        Destination.Type = AddressType::Ipv4;
        Destination.Host = "93.184.216.34";
        Destination.Port = 443;
        return Destination;
    }

    [[nodiscard]] auto MakeServerConfig() -> ServerConfig
    {
        return ServerConfig{"pw123456"};
    }

    [[nodiscard]] auto MakeClientConfig() -> ClientConfig
    {
        return ClientConfig{"pw123456"};
    }

    auto RunServer(
        std::shared_ptr<MemoryStream> Stream,
        ServerOptions Options) -> Net::awaitable<void>
    {
        const auto ServerConfigValue = MakeServerConfig();
        auto [ErrorValue, Request, Connection] = co_await Trojan::Accept(
            std::move(Stream),
            ServerConfigValue);
        (void)Request;
        if (ErrorValue != Error::None || !Connection)
        {
            throw std::runtime_error("Trojan server handshake failed");
        }
        std::vector<std::byte> Buffer(Options.BlockSize);
        std::size_t Received = 0;
        while (Received < Options.ExpectedBytes)
        {
            const auto ReadSize = std::min(
                Options.BlockSize,
                Options.ExpectedBytes - Received);
            auto ReadWindow = std::span<std::byte>(
                Buffer.data(),
                ReadSize);
            std::error_code ReadError;
            const auto Count = co_await Connection->async_read_some(
                ReadWindow,
                ReadError);
            if (ReadError || Count == 0 || Count > ReadSize)
            {
                throw std::runtime_error("Trojan server read failed");
            }
            if (Options.Echo)
            {
                std::error_code WriteError;
                const auto WriteWindow = std::span<const std::byte>(
                    Buffer.data(),
                    Count);
                const auto Written = co_await Connection->async_write_some(
                    WriteWindow,
                    WriteError);
                if (WriteError || Written != Count)
                {
                    throw std::runtime_error("Trojan server echo failed");
                }
            }
            Received += Count;
        }
        Connection->Close();
        if (Received != Options.ExpectedBytes)
        {
            throw std::runtime_error("Trojan server received incomplete data");
        }
    }

    auto SpawnServer(
        ExecutorType Executor,
        Net::awaitable<void> Operation,
        const std::shared_ptr<std::atomic_bool> &Completed) -> void
    {
        auto Completion =
            [Completed](std::exception_ptr Exception) -> void
        {
            Completed->store(
                Exception == nullptr,
                std::memory_order_release);
        };
        Net::co_spawn(
            Executor,
            std::move(Operation),
            std::move(Completion));
    }

    [[nodiscard]] auto WaitForFlag(
        ExecutorType Executor,
        const std::shared_ptr<std::atomic_bool> &Flag)
        -> Net::awaitable<bool>
    {
        Net::steady_timer Timer(Executor);
        const auto Deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (!Flag->load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < Deadline)
        {
            Timer.expires_after(std::chrono::milliseconds(1));
            co_await Timer.async_wait(Net::use_awaitable);
        }
        co_return Flag->load(std::memory_order_acquire);
    }

    TEST(TrojanClientServer, Transfer100MB)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] =
            Preview::MakeMemoryPair(IoContext.get_executor());
        constexpr std::size_t TotalBytes = 100 * 1024 * 1024;
        constexpr std::size_t BlockSize = 64 * 1024;
        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            const auto ServerCompleted =
                std::make_shared<std::atomic_bool>(false);
            SpawnServer(
                IoContext.get_executor(),
                RunServer(
                    std::make_shared<MemoryStream>(std::move(ServerStream)),
                    ServerOptions{
                        TotalBytes,
                        BlockSize,
                        false}),
                ServerCompleted);
            const auto ClientConfigValue = MakeClientConfig();
            const auto Destination = MakeDestination();
            auto ClientResult = co_await Trojan::Connect(
                std::make_shared<MemoryStream>(std::move(ClientStream)),
                ClientConfigValue,
                Destination);
            const auto HandshakeError = std::get<0>(ClientResult);
            auto Client = std::get<1>(std::move(ClientResult));
            EXPECT_EQ(HandshakeError, Error::None);
            EXPECT_NE(Client, nullptr);
            if (HandshakeError != Error::None || !Client)
            {
                co_return;
            }
            std::vector<std::uint8_t> Payload(BlockSize, 0x4D);
            std::size_t Sent = 0;
            while (Sent < TotalBytes)
            {
                const auto WriteSize = std::min(BlockSize, TotalBytes - Sent);
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
                const auto PostToken = Net::use_awaitable;
                co_await Net::post(
                    IoContext.get_executor(),
                    PostToken);
            }
            EXPECT_EQ(Sent, TotalBytes);
            const auto Done = co_await WaitForFlag(
                IoContext.get_executor(),
                ServerCompleted);
            EXPECT_TRUE(Done);
            EXPECT_TRUE(ServerCompleted->load(std::memory_order_acquire));
            Client->Close();
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(TrojanClientServer, ThroughputLatency)
    {
        Net::io_context IoContext;
        BenchReport ThroughputReport;
        BenchReport LatencyReport;
        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            auto [ClientStream, ServerStream] =
                Preview::MakeMemoryPair(IoContext.get_executor());
            constexpr std::size_t ThroughputTotal = 64 * 1024 * 1024;
            const auto ThroughputServerCompleted =
                std::make_shared<std::atomic_bool>(false);
            SpawnServer(
                IoContext.get_executor(),
                RunServer(
                    std::make_shared<MemoryStream>(std::move(ServerStream)),
                    ServerOptions{
                        ThroughputTotal,
                        64 * 1024,
                        true}),
                ThroughputServerCompleted);
            const auto ClientConfigValue = MakeClientConfig();
            const auto Destination = MakeDestination();
            auto ClientResult = co_await Trojan::Connect(
                std::make_shared<MemoryStream>(std::move(ClientStream)),
                ClientConfigValue,
                Destination);
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
            const auto ThroughputDone = co_await WaitForFlag(
                IoContext.get_executor(),
                ThroughputServerCompleted);
            EXPECT_TRUE(ThroughputDone);
            EXPECT_TRUE(ThroughputServerCompleted->load(
                std::memory_order_acquire));

            auto [LatencyClientStream, LatencyServerStream] =
                Preview::MakeMemoryPair(IoContext.get_executor());
            constexpr std::size_t LatencyTotal = 1000 * 4 * 1024;
            const auto LatencyServerCompleted =
                std::make_shared<std::atomic_bool>(false);
            SpawnServer(
                IoContext.get_executor(),
                RunServer(
                    std::make_shared<MemoryStream>(std::move(LatencyServerStream)),
                    ServerOptions{
                        LatencyTotal,
                        4 * 1024,
                        true}),
                LatencyServerCompleted);
            const auto LatencyClientConfig = MakeClientConfig();
            const auto LatencyDestination = MakeDestination();
            auto LatencyResult = co_await Trojan::Connect(
                std::make_shared<MemoryStream>(std::move(LatencyClientStream)),
                LatencyClientConfig,
                LatencyDestination);
            const auto LatencyHandshakeError = std::get<0>(LatencyResult);
            auto LatencyClient = std::get<1>(std::move(LatencyResult));
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
            const auto LatencyDone = co_await WaitForFlag(
                IoContext.get_executor(),
                LatencyServerCompleted);
            EXPECT_TRUE(LatencyDone);
            EXPECT_TRUE(LatencyServerCompleted->load(
                std::memory_order_acquire));
        };
        RunCoroutine(IoContext, std::move(Coroutine));
        EXPECT_GT(ThroughputReport.Mbps, 0.0);
        EXPECT_GT(LatencyReport.Samples, 0u);
        std::printf(
            "trojan throughput: %.1f MB/s | latency(ms): avg %.3f p50 %.3f "
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
