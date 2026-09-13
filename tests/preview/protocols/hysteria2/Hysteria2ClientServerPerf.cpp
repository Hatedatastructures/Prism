/**
 * @file Hysteria2ClientServerPerf.cpp
 * @brief Hysteria2 客户端/服务端封装测试（传输 + 性能）
 * @details 所有服务端协程都通过完成通道纳入测试主协程生命周期，
 *          同时校验实际传输字节数与性能采样数。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <TestSupport/Benchmark/Bench.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include <preview/Protocols/Hysteria2/Hysteria2.hpp>
#include <preview/Transport/MemoryStream.hpp>

namespace Net = boost::asio;

namespace
{
    namespace Hysteria2 = Preview::Hysteria2;

    using Address = Hysteria2::Address;
    using BenchOptions = Preview::BenchOptions;
    using BenchReport = Preview::BenchReport;
    using ClientConfig = Hysteria2::ClientConfig;
    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code, bool)>;
    using Error = Preview::Error;
    using ExecutorType = Net::any_io_executor;
    using MemoryStream = Preview::MemoryStream;
    using ServerConfig = Hysteria2::ServerConfig;
    using SharedDgram = Hysteria2::SharedDgram;
    using SharedMemoryStream = std::shared_ptr<MemoryStream>;
    using SharedTask = std::shared_ptr<struct TaskResult>;

    using Preview::BenchThroughputTx;
    using Preview::MakeMemoryPair;

    constexpr std::string_view Password = "pw123456";

    struct ServerOptions
    {
        SharedMemoryStream Stream;
        std::size_t ExpectedBytes{0};
        std::size_t BlockSize{64 * 1024};
        bool Echo{false};
    };

    struct TaskResult
    {
        explicit TaskResult(ExecutorType Executor)
            : Done(std::move(Executor), 1)
        {
        }

        CompletionChannel Done;
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
            Exception = std::move(ErrorValue);
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

    [[nodiscard]] auto MakeClientConfig() -> ClientConfig
    {
        return ClientConfig{std::string(Password)};
    }

    [[nodiscard]] auto MakeServerConfig() -> ServerConfig
    {
        return ServerConfig{std::string(Password)};
    }

    [[nodiscard]] auto MakeDestination() -> Address
    {
        Address Destination{};
        Destination.Type = Hysteria2::AddressType::Ipv4;
        Destination.Host = "93.184.216.34";
        Destination.Port = 443;
        return Destination;
    }

    [[nodiscard]] auto MakePayload(std::string_view Text)
        -> std::vector<std::uint8_t>
    {
        const auto *Begin = reinterpret_cast<const std::uint8_t *>(Text.data());
        return {Begin, Begin + Text.size()};
    }

    [[nodiscard]] auto ExpectedSamples(const BenchOptions &Options)
        -> std::size_t
    {
        if (Options.Block == 0)
        {
            return 0;
        }
        auto Samples = Options.Total / Options.Block;
        if (Options.Total % Options.Block != 0)
        {
            ++Samples;
        }
        return Samples;
    }

    [[nodiscard]] auto SpawnTask(
        ExecutorType Executor,
        Net::awaitable<void> Coroutine) -> SharedTask
    {
        const auto Task = std::make_shared<TaskResult>(std::move(Executor));
        auto Completion = [Task](std::exception_ptr Exception) -> void
        {
            const bool Completed = Exception == nullptr;
            (void)Task->Done.try_send(
                boost::system::error_code{},
                Completed);
        };
        Net::co_spawn(
            Task->Done.get_executor(),
            std::move(Coroutine),
            std::move(Completion));
        return Task;
    }

    [[nodiscard]] auto WaitTask(const SharedTask &Task)
        -> Net::awaitable<bool>
    {
        if (!Task)
        {
            co_return false;
        }
        boost::system::error_code ErrorCode;
        const auto Completed = co_await Task->Done.async_receive(
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        if (ErrorCode)
        {
            co_return false;
        }
        co_return Completed;
    }

    auto RunServer(ServerOptions Options) -> Net::awaitable<void>
    {
        if (!Options.Stream)
        {
            throw std::runtime_error("Hysteria2 server stream is empty");
        }
        if (Options.ExpectedBytes == 0)
        {
            throw std::runtime_error("Hysteria2 server byte count is zero");
        }
        if (Options.BlockSize == 0)
        {
            throw std::runtime_error("Hysteria2 server block size is zero");
        }

        auto [HandshakeError, Request, Connection] = co_await Hysteria2::Accept(
            std::move(Options.Stream),
            MakeServerConfig());
        if (HandshakeError != Error::None || !Connection)
        {
            throw std::runtime_error("Hysteria2 server authentication failed");
        }
        EXPECT_EQ(Request.dst.Port, 443u);
        if (Request.dst.Port != 443u)
        {
            throw std::runtime_error("Hysteria2 server target mismatch");
        }

        std::vector<std::byte> Buffer(Options.BlockSize);
        std::size_t Received = 0;
        while (Received < Options.ExpectedBytes)
        {
            const auto ReadSize = std::min(
                Options.BlockSize,
                Options.ExpectedBytes - Received);
            const auto ReadWindow = std::span<std::byte>(
                Buffer.data(),
                ReadSize);
            std::error_code ReadError;
            const auto Count = co_await Connection->async_read_some(
                ReadWindow,
                ReadError);
            if (ReadError)
            {
                throw std::runtime_error("Hysteria2 server read failed");
            }
            if (Count == 0)
            {
                throw std::runtime_error(
                    "Hysteria2 server received incomplete data");
            }
            if (Count > ReadSize)
            {
                throw std::runtime_error(
                    "Hysteria2 server read exceeded buffer");
            }

            if (Options.Echo)
            {
                std::size_t Written = 0;
                while (Written < Count)
                {
                    const auto WriteWindow = std::span<const std::byte>(
                        Buffer.data() + Written,
                        Count - Written);
                    std::error_code WriteError;
                    const auto WriteCount = co_await Connection->async_write_some(
                        WriteWindow,
                        WriteError);
                    if (WriteError)
                    {
                        throw std::runtime_error(
                            "Hysteria2 server echo failed");
                    }
                    if (WriteCount == 0)
                    {
                        throw std::runtime_error(
                            "Hysteria2 server echo made no progress");
                    }
                    if (WriteCount > WriteWindow.size())
                    {
                        throw std::runtime_error(
                            "Hysteria2 server echo exceeded buffer");
                    }
                    Written += WriteCount;
                }
            }
            Received += Count;
        }
        Connection->Close();
    }

    auto RunTransfer(
        Net::io_context &IoContext,
        const std::size_t TotalBytes) -> void
    {
        constexpr std::size_t BlockSize = 64 * 1024;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());
        const auto ServerStream = std::make_shared<MemoryStream>(
            std::move(ServerMemory));

        auto Coroutine =
            [&IoContext,
             ClientMemory = std::move(ClientMemory),
             ServerStream,
             TotalBytes]() mutable -> Net::awaitable<void>
        {
            const auto ServerTask = SpawnTask(
                IoContext.get_executor(),
                RunServer(ServerOptions{
                    ServerStream,
                    TotalBytes,
                    BlockSize,
                    false}));

            auto [HandshakeError, Client] = co_await Hysteria2::Connect(
                std::make_shared<MemoryStream>(std::move(ClientMemory)),
                MakeClientConfig(),
                MakeDestination());
            EXPECT_EQ(HandshakeError, Error::None);
            EXPECT_NE(Client, nullptr);
            if (HandshakeError != Error::None || !Client)
            {
                ServerStream->Close();
                (void)co_await WaitTask(ServerTask);
                co_return;
            }

            const std::vector<std::byte> Payload(
                BlockSize,
                std::byte{0x4D});
            const auto PayloadWindow = std::span<const std::byte>(Payload);
            std::size_t Sent = 0;
            std::size_t YieldCount = 0;
            while (Sent < TotalBytes)
            {
                ++YieldCount;
                if (YieldCount % 16 == 0)
                {
                    co_await Net::post(
                        IoContext.get_executor(),
                        Net::use_awaitable);
                }

                const auto Chunk = std::min(
                    PayloadWindow.size(),
                    TotalBytes - Sent);
                const auto WriteWindow = PayloadWindow.first(Chunk);
                std::size_t Written = 0;
                while (Written < Chunk)
                {
                    const auto RemainingWindow = WriteWindow.subspan(Written);
                    std::error_code WriteError;
                    const auto WriteCount = co_await Client->async_write_some(
                        RemainingWindow,
                        WriteError);
                    if (WriteError)
                    {
                        break;
                    }
                    if (WriteCount == 0)
                    {
                        break;
                    }
                    if (WriteCount > RemainingWindow.size())
                    {
                        break;
                    }
                    Written += WriteCount;
                }
                if (Written != Chunk)
                {
                    break;
                }
                Sent += Written;
            }
            EXPECT_EQ(Sent, TotalBytes);
            Client->Close();
            const auto ServerCompleted = co_await WaitTask(ServerTask);
            EXPECT_TRUE(ServerCompleted);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    [[nodiscard]] auto RunBenchConnection(
        Net::io_context &IoContext,
        const BenchOptions &Options) -> Net::awaitable<BenchReport>
    {
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());
        const auto ServerStream = std::make_shared<MemoryStream>(
            std::move(ServerMemory));
        const auto ServerTask = SpawnTask(
            IoContext.get_executor(),
            RunServer(ServerOptions{
                ServerStream,
                Options.Total,
                Options.Block,
                true}));

        auto [HandshakeError, Client] = co_await Hysteria2::Connect(
            std::make_shared<MemoryStream>(std::move(ClientMemory)),
            MakeClientConfig(),
            MakeDestination());
        EXPECT_EQ(HandshakeError, Error::None);
        EXPECT_NE(Client, nullptr);
        if (HandshakeError != Error::None || !Client)
        {
            ServerStream->Close();
            (void)co_await WaitTask(ServerTask);
            co_return BenchReport{};
        }

        const auto Report = co_await BenchThroughputTx(
            *Client,
            *Client,
            Options);
        Client->Close();
        const auto ServerCompleted = co_await WaitTask(ServerTask);
        EXPECT_TRUE(ServerCompleted);
        co_return Report;
    }

    auto RunBenchmarks(
        Net::io_context &IoContext,
        BenchReport &ThroughputReport,
        BenchReport &LatencyReport) -> Net::awaitable<void>
    {
        BenchOptions ThroughputOptions;
        ThroughputOptions.Total = 64 * 1024 * 1024;
        ThroughputOptions.Block = 64 * 1024;
        ThroughputReport = co_await RunBenchConnection(
            IoContext,
            ThroughputOptions);

        BenchOptions LatencyOptions;
        LatencyOptions.Total = 1000 * 4 * 1024;
        LatencyOptions.Block = 4 * 1024;
        LatencyReport = co_await RunBenchConnection(
            IoContext,
            LatencyOptions);
    }

    auto RunUdpServer(SharedDgram Server) -> Net::awaitable<void>
    {
        if (!Server)
        {
            throw std::runtime_error("Hysteria2 UDP server is empty");
        }

        Address Source;
        std::vector<std::uint8_t> Payload;
        const auto ReceiveError = co_await Server->AsyncReceiveFrom(
            Source,
            Payload);
        const auto ExpectedPayload = MakePayload("hello udp");
        EXPECT_EQ(ReceiveError, Error::None);
        EXPECT_EQ(Payload, ExpectedPayload);
        if (ReceiveError != Error::None || Payload != ExpectedPayload)
        {
            throw std::runtime_error("Hysteria2 UDP server received bad data");
        }

        std::vector<std::uint8_t> Response(
            Payload.rbegin(),
            Payload.rend());
        const auto ResponseWindow = std::span<const std::uint8_t>(Response);
        const auto SendError = co_await Server->AsyncSendTo(
            Source,
            ResponseWindow);
        EXPECT_EQ(SendError, Error::None);
        if (SendError != Error::None)
        {
            throw std::runtime_error("Hysteria2 UDP server send failed");
        }
        Server->Close();
    }

    TEST(Hysteria2ClientServer, HandshakeAndTransfer)
    {
        Net::io_context IoContext;
        RunTransfer(IoContext, 4 * 1024 * 1024);
    }

    TEST(Hysteria2ClientServer, ThroughputLatency)
    {
        constexpr std::size_t ThroughputTotal = 64 * 1024 * 1024;
        constexpr std::size_t ThroughputBlock = 64 * 1024;
        constexpr std::size_t LatencyTotal = 1000 * 4 * 1024;
        constexpr std::size_t LatencyBlock = 4 * 1024;

        Net::io_context IoContext;
        BenchReport ThroughputReport{};
        BenchReport LatencyReport{};
        auto Coroutine = RunBenchmarks(
            IoContext,
            ThroughputReport,
            LatencyReport);
        RunCoroutine(IoContext, std::move(Coroutine));

        BenchOptions ThroughputOptions;
        ThroughputOptions.Total = ThroughputTotal;
        ThroughputOptions.Block = ThroughputBlock;
        BenchOptions LatencyOptions;
        LatencyOptions.Total = LatencyTotal;
        LatencyOptions.Block = LatencyBlock;

        EXPECT_EQ(ThroughputReport.Bytes, ThroughputTotal);
        EXPECT_EQ(
            ThroughputReport.Samples,
            ExpectedSamples(ThroughputOptions));
        EXPECT_GT(ThroughputReport.Mbps, 0.0);
        EXPECT_EQ(LatencyReport.Bytes, LatencyTotal);
        EXPECT_EQ(
            LatencyReport.Samples,
            ExpectedSamples(LatencyOptions));
        EXPECT_GT(LatencyReport.Samples, 0u);
        std::printf(
            "hysteria2 throughput: %.1f MB/s bytes=%zu | latency(ms): "
            "avg %.3f p50 %.3f p95 %.3f p99 %.3f (min %.3f max %.3f) "
            "bytes=%zu samples=%zu\n",
            ThroughputReport.Mbps,
            ThroughputReport.Bytes,
            LatencyReport.LatencyAvg,
            LatencyReport.LatencyP50,
            LatencyReport.LatencyP95,
            LatencyReport.LatencyP99,
            LatencyReport.LatencyMin,
            LatencyReport.LatencyMax,
            LatencyReport.Bytes,
            LatencyReport.Samples);
    }

    TEST(Hysteria2ClientServer, UdpDatagramRoundtrip)
    {
        Net::io_context IoContext;
        auto [ClientProvider, ServerProvider] =
            Preview::Testing::MemoryDatagramProvider::MakePair(
                IoContext.get_executor());
        auto Client = Hysteria2::ConnectPacket(
            ClientProvider,
            MakeClientConfig());
        auto Server = Hysteria2::AcceptPacket(
            ServerProvider,
            MakeServerConfig());
        ASSERT_NE(Client, nullptr);
        ASSERT_NE(Server, nullptr);

        auto Coroutine =
            [&IoContext, Client, Server]() -> Net::awaitable<void>
        {
            const auto ServerTask = SpawnTask(
                IoContext.get_executor(),
                RunUdpServer(Server));

            const auto Payload = MakePayload("hello udp");
            const auto PayloadWindow = std::span<const std::uint8_t>(Payload);
            const auto SendError = co_await Client->AsyncSendTo(
                MakeDestination(),
                PayloadWindow);
            EXPECT_EQ(SendError, Error::None);
            if (SendError != Error::None)
            {
                Client->Close();
                Server->Close();
                (void)co_await WaitTask(ServerTask);
                co_return;
            }

            Address Source;
            std::vector<std::uint8_t> Response;
            const auto ReceiveError = co_await Client->AsyncReceiveFrom(
                Source,
                Response);
            EXPECT_EQ(ReceiveError, Error::None);
            const auto ExpectedResponse = std::vector<std::uint8_t>(
                Payload.rbegin(),
                Payload.rend());
            EXPECT_EQ(Response, ExpectedResponse);
            if (ReceiveError != Error::None || Response != ExpectedResponse)
            {
                Client->Close();
                Server->Close();
                (void)co_await WaitTask(ServerTask);
                co_return;
            }

            Client->Close();
            const auto ServerCompleted = co_await WaitTask(ServerTask);
            EXPECT_TRUE(ServerCompleted);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

} // namespace
