/**
 * @file TuicClientServerPerf.cpp
 * @brief TUIC 客户端/服务端完整会话测试（传输 + 性能）
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

#include <TestSupport/Benchmark/Bench.hpp>
#include <Preview/Protocols/Tuic/Tuic.hpp>
#include <Preview/Transport/MemoryStream.hpp>

namespace Net = boost::asio;

namespace
{
    namespace Preview = ::Preview;
    namespace Tuic = Preview::Tuic;

    using Address = Tuic::Address;
    using BenchOptions = Preview::BenchOptions;
    using BenchReport = Preview::BenchReport;
    using ClientConfig = Tuic::ClientConfig;
    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code, bool)>;
    using Error = Preview::Error;
    using ExecutorType = Net::any_io_executor;
    using MemoryStream = Preview::MemoryStream;
    using ServerConfig = Tuic::ServerConfig;
    using SharedTask = std::shared_ptr<struct TaskResult>;

    using Preview::BenchThroughputTx;
    using Preview::MakeMemoryPair;

    struct ServerOptions
    {
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
        std::exception_ptr Exception;
    };

    template <typename Awaitable>
    auto RunCoroutine(Net::io_context &IoContext, Awaitable Coroutine) -> void
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

    [[nodiscard]] auto MakeUuid() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> Uuid{};
        Uuid.fill(0x55);
        return Uuid;
    }

    [[nodiscard]] auto TestExporter(
        std::span<std::uint8_t> Output,
        std::span<const std::uint8_t> Label,
        std::string_view Context) -> bool
    {
        std::uint8_t State = 0x5A;
        for (const auto Byte : Label)
        {
            State = static_cast<std::uint8_t>((State * 33U) ^ Byte);
        }
        for (const auto Character : Context)
        {
            State = static_cast<std::uint8_t>(
                (State * 33U) ^ static_cast<std::uint8_t>(Character));
        }
        for (std::size_t Index = 0; Index < Output.size(); ++Index)
        {
            State = static_cast<std::uint8_t>(
                State * 33U + static_cast<std::uint8_t>(Index));
            Output[Index] = State;
        }
        return true;
    }

    [[nodiscard]] auto MakeDestination() -> Address
    {
        Address Destination{};
        Destination.Type = Tuic::AddressType::Ipv4;
        Destination.Host = "93.184.216.34";
        Destination.Port = 443;
        return Destination;
    }

    [[nodiscard]] auto MakeClientConfig(
        std::shared_ptr<MemoryStream> AuthStream) -> ClientConfig
    {
        ClientConfig Config{};
        Config.uuid = MakeUuid();
        Config.password = "pw";
        Config.AuthStream = std::move(AuthStream);
        Config.Exporter = TestExporter;
        return Config;
    }

    [[nodiscard]] auto MakeServerConfig(
        std::shared_ptr<MemoryStream> AuthStream) -> ServerConfig
    {
        ServerConfig Config{};
        Config.uuid = MakeUuid();
        Config.password = "pw";
        Config.AuthStream = std::move(AuthStream);
        Config.Exporter = TestExporter;
        return Config;
    }

    auto CloseStreams(
        const std::shared_ptr<MemoryStream> &Stream,
        const std::shared_ptr<MemoryStream> &AuthStream) -> void
    {
        if (Stream)
        {
            Stream->Close();
        }
        if (AuthStream)
        {
            AuthStream->Close();
        }
    }

    [[nodiscard]] auto SpawnTask(
        ExecutorType Executor,
        Net::awaitable<void> Coroutine) -> SharedTask
    {
        const auto Task = std::make_shared<TaskResult>(std::move(Executor));
        auto Completion = [Task](std::exception_ptr Exception) -> void
        {
            Task->Exception = std::move(Exception);
            const bool Completed = Task->Exception == nullptr;
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

    [[nodiscard]] auto WaitTask(
        const SharedTask &Task) -> Net::awaitable<bool>
    {
        boost::system::error_code ErrorCode;
        const auto Completed = co_await Task->Done.async_receive(
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        if (ErrorCode)
        {
            co_return false;
        }
        if (Task->Exception)
        {
            std::rethrow_exception(Task->Exception);
        }
        co_return Completed;
    }

    auto RunServer(
        std::shared_ptr<MemoryStream> Stream,
        std::shared_ptr<MemoryStream> AuthStream,
        ServerOptions Options) -> Net::awaitable<void>
    {
        if (Options.BlockSize == 0)
        {
            throw std::runtime_error("TUIC server block size is zero");
        }

        const auto Config = MakeServerConfig(std::move(AuthStream));
        auto [ErrorValue, Request, Connection] = co_await Tuic::Accept(
            std::move(Stream),
            Config);
        if (ErrorValue != Error::None || !Connection)
        {
            throw std::runtime_error("TUIC server authentication failed");
        }
        EXPECT_EQ(Request.dst.Port, 443u);
        if (Request.dst.Port != 443u)
        {
            throw std::runtime_error("TUIC server target mismatch");
        }

        std::vector<std::byte> Buffer(Options.BlockSize);
        std::size_t Received = 0;
        while (Options.ExpectedBytes == 0 || Received < Options.ExpectedBytes)
        {
            std::size_t ReadSize = Buffer.size();
            if (Options.ExpectedBytes > 0)
            {
                const auto Remaining = Options.ExpectedBytes - Received;
                ReadSize = std::min(ReadSize, Remaining);
            }
            const std::span<std::byte> ReadWindow(Buffer.data(), ReadSize);
            std::error_code ReadError;
            const auto Count = co_await Connection->async_read_some(
                ReadWindow,
                ReadError);
            if (ReadError)
            {
                throw std::runtime_error("TUIC server read failed");
            }
            if (Count == 0)
            {
                if (Options.ExpectedBytes > 0 && Received < Options.ExpectedBytes)
                {
                    throw std::runtime_error("TUIC server received incomplete data");
                }
                break;
            }
            if (Count > ReadSize)
            {
                throw std::runtime_error("TUIC server read exceeded buffer");
            }

            if (Options.Echo)
            {
                const std::span<const std::byte> EchoWindow(
                    Buffer.data(),
                    Count);
                std::size_t Written = 0;
                while (Written < EchoWindow.size())
                {
                    const auto WriteWindow = EchoWindow.subspan(Written);
                    std::error_code WriteError;
                    const auto WriteCount = co_await Connection->async_write_some(
                        WriteWindow,
                        WriteError);
                    if (WriteError || WriteCount == 0 ||
                        WriteCount > EchoWindow.size() - Written)
                    {
                        throw std::runtime_error("TUIC server echo failed");
                    }
                    Written += WriteCount;
                }
            }
            Received += Count;
        }
        Connection->Close();
        if (Options.ExpectedBytes > 0 && Received != Options.ExpectedBytes)
        {
            throw std::runtime_error("TUIC server received incomplete data");
        }
    }

    auto RunUdpServer(
        std::shared_ptr<MemoryStream> Stream,
        std::shared_ptr<MemoryStream> AuthStream) -> Net::awaitable<void>
    {
        const auto Config = MakeServerConfig(std::move(AuthStream));
        auto [ErrorValue, Request, Connection] = co_await Tuic::Accept(
            std::move(Stream),
            Config);
        if (ErrorValue != Error::None || !Connection)
        {
            throw std::runtime_error("TUIC UDP server authentication failed");
        }
        EXPECT_EQ(Request.dst.Port, 443u);
        if (Request.dst.Port != 443u)
        {
            throw std::runtime_error("TUIC UDP server target mismatch");
        }

        Address Source;
        std::vector<std::uint8_t> Payload;
        const auto ReceiveError = co_await Connection->AsyncReceiveDatagram(
            Source,
            Payload);
        EXPECT_EQ(ReceiveError, Error::None);
        if (ReceiveError != Error::None)
        {
            throw std::runtime_error("TUIC UDP server receive failed");
        }
        const std::string ReceivedPayload(Payload.begin(), Payload.end());
        EXPECT_EQ(ReceivedPayload, "hello udp");
        if (ReceivedPayload != "hello udp")
        {
            throw std::runtime_error("TUIC UDP server payload mismatch");
        }

        std::vector<std::uint8_t> Response(Payload.rbegin(), Payload.rend());
        const std::span<const std::uint8_t> ResponseSpan(Response);
        const auto SendError = co_await Connection->AsyncSendDatagram(
            Source,
            ResponseSpan);
        EXPECT_EQ(SendError, Error::None);
        if (SendError != Error::None)
        {
            throw std::runtime_error("TUIC UDP server send failed");
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
        auto [ClientAuthMemory, ServerAuthMemory] =
            MakeMemoryPair(IoContext.get_executor());

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            const auto ServerStream = std::make_shared<MemoryStream>(
                std::move(ServerMemory));
            const auto ServerAuthStream = std::make_shared<MemoryStream>(
                std::move(ServerAuthMemory));
            auto ServerOperation =
                [ServerStream, ServerAuthStream, TotalBytes]()
                -> Net::awaitable<void>
            {
                co_await RunServer(
                    ServerStream,
                    ServerAuthStream,
                    ServerOptions{TotalBytes, BlockSize, false});
            };
            const auto ServerTask = SpawnTask(
                IoContext.get_executor(),
                ServerOperation());

            const auto ClientAuthStream = std::make_shared<MemoryStream>(
                std::move(ClientAuthMemory));
            const auto ClientConfigValue = MakeClientConfig(ClientAuthStream);
            const auto Destination = MakeDestination();
            auto [HandshakeError, Client] = co_await Tuic::Connect(
                std::make_shared<MemoryStream>(std::move(ClientMemory)),
                ClientConfigValue,
                Destination);
            EXPECT_EQ(HandshakeError, Error::None);
            EXPECT_NE(Client, nullptr);
            if (HandshakeError != Error::None || !Client)
            {
                CloseStreams(ServerStream, ServerAuthStream);
                const auto ServerCompleted = co_await WaitTask(ServerTask);
                EXPECT_TRUE(ServerCompleted);
                co_return;
            }

            std::vector<std::uint8_t> Payload(BlockSize, 0x4D);
            const std::span<const std::byte> PayloadWindow(
                reinterpret_cast<const std::byte *>(Payload.data()),
                Payload.size());
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
                const auto Chunk = std::min(BlockSize, TotalBytes - Sent);
                const auto WriteWindow = PayloadWindow.first(Chunk);
                std::size_t Written = 0;
                while (Written < Chunk)
                {
                    const auto Remaining = WriteWindow.subspan(Written);
                    std::error_code WriteError;
                    const auto WriteCount = co_await Client->async_write_some(
                        Remaining,
                        WriteError);
                    if (WriteError || WriteCount == 0 ||
                        WriteCount > Chunk - Written)
                    {
                        break;
                    }
                    Written += WriteCount;
                }
                if (Written < Chunk)
                {
                    break;
                }
                Sent += Chunk;
            }
            EXPECT_EQ(Sent, TotalBytes);
            Client->Close();
            const auto ServerCompleted = co_await WaitTask(ServerTask);
            EXPECT_TRUE(ServerCompleted);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    auto RunBenchConnection(
        Net::io_context &IoContext,
        const BenchOptions &Options) -> Net::awaitable<BenchReport>
    {
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());
        auto [ClientAuthMemory, ServerAuthMemory] =
            MakeMemoryPair(IoContext.get_executor());
        const auto ServerStream = std::make_shared<MemoryStream>(
            std::move(ServerMemory));
        const auto ServerAuthStream = std::make_shared<MemoryStream>(
            std::move(ServerAuthMemory));
        auto ServerOperation =
            [ServerStream, ServerAuthStream, Options]()
            -> Net::awaitable<void>
        {
            co_await RunServer(
                ServerStream,
                ServerAuthStream,
                ServerOptions{Options.Total, Options.Block, true});
        };
        const auto ServerTask = SpawnTask(
            IoContext.get_executor(),
            ServerOperation());

        const auto ClientAuthStream = std::make_shared<MemoryStream>(
            std::move(ClientAuthMemory));
        const auto ClientConfigValue = MakeClientConfig(ClientAuthStream);
        const auto Destination = MakeDestination();
        auto [HandshakeError, Client] = co_await Tuic::Connect(
            std::make_shared<MemoryStream>(std::move(ClientMemory)),
            ClientConfigValue,
            Destination);
        EXPECT_EQ(HandshakeError, Error::None);
        EXPECT_NE(Client, nullptr);
        if (HandshakeError != Error::None || !Client)
        {
            CloseStreams(ServerStream, ServerAuthStream);
            const auto ServerCompleted = co_await WaitTask(ServerTask);
            EXPECT_TRUE(ServerCompleted);
            co_return BenchReport{};
        }

        const auto Report = co_await BenchThroughputTx(
            *Client,
            *Client,
            Options);
        EXPECT_EQ(Report.Bytes, Options.Total);
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

    TEST(TuicClientServer, Transfer100MB)
    {
        Net::io_context IoContext;
        RunTransfer(IoContext, 100 * 1024 * 1024);
    }

    TEST(TuicClientServer, ThroughputLatency)
    {
        Net::io_context IoContext;
        BenchReport ThroughputReport{};
        BenchReport LatencyReport{};
        auto Coroutine = RunBenchmarks(
            IoContext,
            ThroughputReport,
            LatencyReport);
        RunCoroutine(IoContext, std::move(Coroutine));

        EXPECT_EQ(ThroughputReport.Bytes, 64u * 1024u * 1024u);
        EXPECT_EQ(LatencyReport.Bytes, 1000u * 4u * 1024u);
        EXPECT_GT(ThroughputReport.Mbps, 0.0);
        EXPECT_GT(LatencyReport.Samples, 0u);
        std::printf(
            "tuic throughput: %.1f MB/s | latency(ms): avg %.3f p50 %.3f "
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

    TEST(TuicClientServer, UdpDatagramRoundtrip)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());
        auto [ClientAuthMemory, ServerAuthMemory] =
            MakeMemoryPair(IoContext.get_executor());

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            const auto ServerStream = std::make_shared<MemoryStream>(
                std::move(ServerMemory));
            const auto ServerAuthStream = std::make_shared<MemoryStream>(
                std::move(ServerAuthMemory));
            auto ServerOperation = [ServerStream, ServerAuthStream]()
                -> Net::awaitable<void>
            {
                co_await RunUdpServer(ServerStream, ServerAuthStream);
            };
            const auto ServerTask = SpawnTask(
                IoContext.get_executor(),
                ServerOperation());

            const auto ClientAuthStream = std::make_shared<MemoryStream>(
                std::move(ClientAuthMemory));
            const auto ClientConfigValue = MakeClientConfig(ClientAuthStream);
            const auto Destination = MakeDestination();
            auto [HandshakeError, Client] = co_await Tuic::Connect(
                std::make_shared<MemoryStream>(std::move(ClientMemory)),
                ClientConfigValue,
                Destination);
            EXPECT_EQ(HandshakeError, Error::None);
            EXPECT_NE(Client, nullptr);
            if (HandshakeError != Error::None || !Client)
            {
                CloseStreams(ServerStream, ServerAuthStream);
                const auto ServerCompleted = co_await WaitTask(ServerTask);
                EXPECT_TRUE(ServerCompleted);
                co_return;
            }

            const std::string Payload = "hello udp";
            const std::span<const std::uint8_t> PayloadSpan(
                reinterpret_cast<const std::uint8_t *>(Payload.data()),
                Payload.size());
            const auto SendError = co_await Client->AsyncSendDatagram(
                Destination,
                PayloadSpan);
            EXPECT_EQ(SendError, Error::None);
            if (SendError != Error::None)
            {
                Client->Close();
                CloseStreams(ServerStream, ServerAuthStream);
                const auto ServerCompleted = co_await WaitTask(ServerTask);
                EXPECT_TRUE(ServerCompleted);
                co_return;
            }

            Address Source;
            std::vector<std::uint8_t> Response;
            const auto ReceiveError = co_await Client->AsyncReceiveDatagram(
                Source,
                Response);
            EXPECT_EQ(ReceiveError, Error::None);
            const std::string ReceivedPayload(
                Response.begin(),
                Response.end());
            EXPECT_EQ(ReceivedPayload, "pdu olleh");
            Client->Close();
            const auto ServerCompleted = co_await WaitTask(ServerTask);
            EXPECT_TRUE(ServerCompleted);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

} // namespace
