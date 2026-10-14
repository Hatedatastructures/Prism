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
#include <Preview/Protocols/Trojan/Trojan.hpp>
#include <Preview/Transport/MemoryStream.hpp>

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
        auto AcceptResult = co_await Trojan::Accept(
            std::move(Stream),
            ServerConfigValue);
        EXPECT_TRUE(AcceptResult);
        if (AcceptResult) EXPECT_TRUE(AcceptResult->Connection);
        if (!AcceptResult || !AcceptResult->Connection)
        {
            throw std::runtime_error("Trojan server handshake failed");
        }
        auto Connection = std::move(AcceptResult->Connection);
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
            const auto Read = co_await Connection->ReadSome(ReadWindow);
            if (Read.Failure.Failed() || Read.Bytes == 0 || Read.Bytes > ReadSize)
            {
                throw std::runtime_error("Trojan server read failed");
            }
            if (Options.Echo)
            {
                const auto WriteWindow = std::span<const std::byte>(
                    Buffer.data(),
                    Read.Bytes);
                const auto Written = co_await Connection->WriteExact(WriteWindow);
                if (Written.Failure.Failed() || Written.Bytes != Read.Bytes)
                {
                    throw std::runtime_error("Trojan server echo failed");
                }
            }
            Received += Read.Bytes;
        }
        const auto Close = Connection->Close();
        if (!Close)
        {
            throw std::runtime_error("Trojan server close failed");
        }
        const auto Drain = co_await Connection->Activity()->Drain();
        if (!Drain)
        {
            throw std::runtime_error("Trojan server drain failed");
        }
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

    struct TransferScenarioRequest final
    {
        Net::io_context &IoContext;
        MemoryStream ClientStream;
        MemoryStream ServerStream;
        std::size_t TotalBytes;
        std::size_t BlockSize;
        bool Echo;
    };

    /** @brief 驱动一次完整 Trojan 客户端/服务端传输并等待 server completion。 */
    auto RunTransferScenario(TransferScenarioRequest Request) -> Net::awaitable<void>
    {
        const auto ServerCompleted =
            std::make_shared<std::atomic_bool>(false);
        SpawnServer(
            Request.IoContext.get_executor(),
            RunServer(
                std::make_shared<MemoryStream>(std::move(Request.ServerStream)),
                ServerOptions{
                    Request.TotalBytes,
                    Request.BlockSize,
                    Request.Echo}),
            ServerCompleted);
        const auto ClientConfigValue = MakeClientConfig();
        const auto Destination = MakeDestination();
        auto ClientResult = co_await Trojan::Connect(Trojan::ConnectParameters{
            std::make_shared<MemoryStream>(std::move(Request.ClientStream)),
            ClientConfigValue,
            Destination});
        EXPECT_TRUE(ClientResult);
        if (ClientResult) EXPECT_TRUE(*ClientResult);
        if (!ClientResult || !*ClientResult)
        {
            co_return;
        }
        auto Client = std::move(*ClientResult);
        std::vector<std::uint8_t> Payload(Request.BlockSize, 0x4D);
        std::size_t Sent = 0;
        while (Sent < Request.TotalBytes)
        {
            const auto WriteSize = std::min(Request.BlockSize, Request.TotalBytes - Sent);
            const auto WriteWindow = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Payload.data()), WriteSize);
            const auto Written = co_await Client->WriteSome(WriteWindow);
            if (Written.Failure.Failed() || Written.Bytes == 0 || Written.Bytes > WriteSize)
            {
                break;
            }
            Sent += Written.Bytes;
            co_await Net::post(Request.IoContext.get_executor(), Net::use_awaitable);
        }
        EXPECT_EQ(Sent, Request.TotalBytes);
        const auto Done = co_await WaitForFlag(
            Request.IoContext.get_executor(), ServerCompleted);
        EXPECT_TRUE(Done);
        EXPECT_TRUE(ServerCompleted->load(std::memory_order_acquire));
        const auto Close = Client->Close();
        EXPECT_TRUE(Close);
        const auto Drain = co_await Client->Activity()->Drain();
        EXPECT_TRUE(Drain);
    }

    struct ThroughputLatencyRequest final
    {
        Net::io_context &IoContext;
        BenchReport *ThroughputReport;
        BenchReport *LatencyReport;
    };

    /** @brief 运行完整吞吐和 latency 两个原始 benchmark 场景。 */
    auto RunThroughputLatency(ThroughputLatencyRequest Request) -> Net::awaitable<void>
    {
        auto [ClientStream, ServerStream] =
            Preview::MakeMemoryPair(Request.IoContext.get_executor());
        constexpr std::size_t ThroughputTotal = 64 * 1024 * 1024;
        const auto ThroughputServerCompleted =
            std::make_shared<std::atomic_bool>(false);
        SpawnServer(
            Request.IoContext.get_executor(),
            RunServer(
                std::make_shared<MemoryStream>(std::move(ServerStream)),
                ServerOptions{ThroughputTotal, 64 * 1024, true}),
            ThroughputServerCompleted);
        auto ThroughputResult = co_await Trojan::Connect(Trojan::ConnectParameters{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            MakeClientConfig(), MakeDestination()});
        EXPECT_TRUE(ThroughputResult);
        if (ThroughputResult) EXPECT_TRUE(*ThroughputResult);
        if (!ThroughputResult || !*ThroughputResult)
        {
            co_return;
        }
        auto ThroughputClient = std::move(*ThroughputResult);
        BenchOptions ThroughputOptions;
        ThroughputOptions.Total = ThroughputTotal;
        ThroughputOptions.Block = 64 * 1024;
        *Request.ThroughputReport = co_await Preview::BenchThroughputTx(
            *ThroughputClient, *ThroughputClient, ThroughputOptions);
        EXPECT_EQ(Request.ThroughputReport->Bytes, ThroughputOptions.Total);
        const auto ThroughputClose = ThroughputClient->Close();
        EXPECT_TRUE(ThroughputClose);
        const auto ThroughputDrain = co_await ThroughputClient->Activity()->Drain();
        EXPECT_TRUE(ThroughputDrain);
        const auto ThroughputDone = co_await WaitForFlag(
            Request.IoContext.get_executor(), ThroughputServerCompleted);
        EXPECT_TRUE(ThroughputDone);
        EXPECT_TRUE(ThroughputServerCompleted->load(std::memory_order_acquire));

        auto [LatencyClientStream, LatencyServerStream] =
            Preview::MakeMemoryPair(Request.IoContext.get_executor());
        constexpr std::size_t LatencyTotal = 1000 * 4 * 1024;
        const auto LatencyServerCompleted =
            std::make_shared<std::atomic_bool>(false);
        SpawnServer(
            Request.IoContext.get_executor(),
            RunServer(
                std::make_shared<MemoryStream>(std::move(LatencyServerStream)),
                ServerOptions{LatencyTotal, 4 * 1024, true}),
            LatencyServerCompleted);
        auto LatencyResult = co_await Trojan::Connect(Trojan::ConnectParameters{
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
        *Request.LatencyReport = co_await Preview::BenchThroughputTx(
            *LatencyClient, *LatencyClient, LatencyOptions);
        EXPECT_EQ(Request.LatencyReport->Bytes, LatencyOptions.Total);
        const auto LatencyClose = LatencyClient->Close();
        EXPECT_TRUE(LatencyClose);
        const auto LatencyDrain = co_await LatencyClient->Activity()->Drain();
        EXPECT_TRUE(LatencyDrain);
        const auto LatencyDone = co_await WaitForFlag(
            Request.IoContext.get_executor(), LatencyServerCompleted);
        EXPECT_TRUE(LatencyDone);
        EXPECT_TRUE(LatencyServerCompleted->load(std::memory_order_acquire));
    }

    TEST(TrojanClientServer, Transfer100MB)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] =
            Preview::MakeMemoryPair(IoContext.get_executor());
        constexpr std::size_t TotalBytes = 100 * 1024 * 1024;
        constexpr std::size_t BlockSize = 64 * 1024;
        RunCoroutine(IoContext, RunTransferScenario(TransferScenarioRequest{
            IoContext,
            std::move(ClientStream),
            std::move(ServerStream),
            TotalBytes,
            BlockSize,
            false}));
    }

    TEST(TrojanClientServer, ThroughputLatency)
    {
        Net::io_context IoContext;
        BenchReport ThroughputReport;
        BenchReport LatencyReport;
        RunCoroutine(IoContext, RunThroughputLatency(ThroughputLatencyRequest{
            IoContext,
            &ThroughputReport,
            &LatencyReport}));
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
