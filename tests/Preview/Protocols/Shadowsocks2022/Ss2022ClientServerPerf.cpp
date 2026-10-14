/**
 * @file Ss2022ClientServerPerf.cpp
 * @brief SS2022 客户端/服务端封装测试（握手、完整传输与性能）
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

#include <TestSupport/Benchmark/Bench.hpp>
#include <gtest/gtest.h>
#include <Preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <Preview/Transport/MemoryStream.hpp>

namespace Net = boost::asio;

namespace
{
    namespace Shadowsocks = Preview::Shadowsocks2022;

    using Address = Shadowsocks::Address;
    using AddressType = Shadowsocks::AddressType;
    using BenchOptions = Preview::BenchOptions;
    using BenchReport = Preview::BenchReport;
    using ClientConfig = Shadowsocks::ClientConfig;
    using Error = Preview::Error;
    using MemoryStream = Preview::MemoryStream;
    using ServerConfig = Shadowsocks::ServerConfig;
    using SharedTransmission = Preview::SharedTransmission;
    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code, bool)>;
    inline constexpr std::array<std::uint8_t, 16> PerfPsk{
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30};

    struct ServerCompletion final
    {
        explicit ServerCompletion(Net::any_io_executor Executor)
            : Done(std::make_shared<CompletionChannel>(Executor, 1)),
              Failure(std::make_shared<std::exception_ptr>()),
              Signaled(std::make_shared<std::atomic_bool>(false))
        {
        }

        std::shared_ptr<CompletionChannel> Done;
        std::shared_ptr<std::exception_ptr> Failure;
        std::shared_ptr<std::atomic_bool> Signaled;
    };

    auto CompleteServer(
        const std::shared_ptr<ServerCompletion> &Completion,
        const bool Completed,
        std::exception_ptr Failure) -> void
    {
        if (Completion->Signaled->exchange(true))
        {
            return;
        }
        *Completion->Failure = std::move(Failure);
        (void)Completion->Done->try_send(boost::system::error_code{}, Completed);
    }

    struct ServerSession final
    {
        SharedTransmission Transport;
        ServerConfig Config;
        std::shared_ptr<ServerCompletion> Completion;
    };

    struct TransferSpec final
    {
        std::size_t ExpectedBytes;
        bool Echo;
    };

    struct ServerResult final
    {
        bool Completed{false};
        std::exception_ptr Failure;
    };

    auto AwaitServer(
        const std::shared_ptr<ServerCompletion> &Completion)
        -> Net::awaitable<ServerResult>
    {
        const auto Completed =
            co_await Completion->Done->async_receive(Net::use_awaitable);
        co_return ServerResult{Completed, *Completion->Failure};
    }

    struct ClientResult final
    {
        Error ErrorCode{Error::IoError};
        SharedTransmission Connection;
        std::exception_ptr Failure;
    };

    auto ConnectClient(
        SharedTransmission Transport,
        ClientConfig Config,
        Address Target) -> Net::awaitable<ClientResult>
    {
        const auto KeepAlive = Transport;
        try
        {
            auto Result = co_await Shadowsocks::Connect(
                std::move(Transport), std::move(Config), std::move(Target));
            co_return ClientResult{
                std::get<0>(Result), std::get<1>(std::move(Result)), nullptr};
        }
        catch (...)
        {
            if (KeepAlive)
            {
                (void)KeepAlive->Close();
            }
            co_return ClientResult{
                Error::IoError, nullptr, std::current_exception()};
        }
    }

    struct TransferResult final
    {
        std::size_t Sent{0};
        std::exception_ptr Failure;
    };

    auto WriteTransfer(
        const SharedTransmission &Client,
        const std::size_t Total) -> Net::awaitable<TransferResult>
    {
        constexpr std::size_t Block = 64 * 1024;
        std::vector<std::uint8_t> Payload(Block, 0x6E);
        std::size_t Sent = 0;
        try
        {
            while (Sent < Total)
            {
                const auto WriteSize = std::min(Block, Total - Sent);
                std::error_code WriteError;
                const auto Write = co_await Client->WriteSome(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(Payload.data()),
                        WriteSize));
                WriteError = Preview::Fault::ToNative(Write.Failure);
                const auto Written = Write.Bytes;
                if (WriteError || Written == 0 || Written > WriteSize)
                {
                    break;
                }
                Sent += Written;
            }
        }
        catch (...)
        {
            (void)Client->Close();
            co_return TransferResult{Sent, std::current_exception()};
        }
        co_return TransferResult{Sent, nullptr};
    }

    template <typename Awaitable>
    auto RunCoroutine(
        Net::io_context &IoContext,
        Awaitable Coroutine) -> void
    {
        std::exception_ptr Exception;
        auto Completion =
            [&Exception](std::exception_ptr ErrorValue) -> void
        {
            if (!Exception)
            {
                Exception = std::move(ErrorValue);
            }
        };
        IoContext.restart();
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

    auto RunServer(
        ServerSession Session,
        TransferSpec Spec) -> Net::awaitable<void>
    {
        try
        {
        const auto AcceptResult = co_await Shadowsocks::Accept(
            Session.Transport, Session.Config);
        const auto HandshakeError = std::get<0>(AcceptResult);
        const auto &Request = std::get<1>(AcceptResult);
        const auto &Connection = std::get<2>(AcceptResult);
        (void)Request;
        if (HandshakeError != Error::None || !Connection)
        {
            CompleteServer(Session.Completion, false, nullptr);
            co_return;
        }

        std::array<std::byte, 128 * 1024> Buffer{};
        std::size_t Done = 0;
        std::error_code ReadError;
        while (Done < Spec.ExpectedBytes)
        {
            const auto ReadSize =
                std::min(Buffer.size(), Spec.ExpectedBytes - Done);
            auto ReadWindow = std::span<std::byte>(
                Buffer.data(),
                ReadSize);
            const auto Read = co_await Connection->ReadSome(ReadWindow);
            ReadError = Preview::Fault::ToNative(Read.Failure);
            const auto Count = Read.Bytes;
            if (ReadError || Count == 0 || Count > ReadSize)
            {
                break;
            }
            Done += Count;
            if (Spec.Echo)
            {
                std::error_code WriteError;
                auto WriteWindow = std::span<const std::byte>(
                    Buffer.data(),
                    Count);
                const auto Write = co_await Connection->WriteSome(WriteWindow);
                WriteError = Preview::Fault::ToNative(Write.Failure);
                const auto Written = Write.Bytes;
                if (WriteError || Written != Count)
                {
                    break;
                }
            }
        }

        (void)Connection->Close();
        CompleteServer(Session.Completion, Done == Spec.ExpectedBytes, nullptr);
        }
        catch (...)
        {
            if (Session.Transport)
            {
                (void)Session.Transport->Close();
            }
            throw;
        }
    }

    auto SpawnServer(
        Net::io_context &IoContext,
        ServerSession Session,
        TransferSpec Spec) -> void
    {
        const auto Completion = Session.Completion;
        auto ServerCompletion =
            [Completion](std::exception_ptr Exception) -> void
        {
            CompleteServer(Completion, false, std::move(Exception));
        };
        Net::co_spawn(
            IoContext.get_executor(),
            RunServer(std::move(Session), Spec),
            std::move(ServerCompletion));
    }

    [[nodiscard]] auto MakeServerConfig() -> ServerConfig
    {
        ServerConfig Config;
        Config.Psk = PerfPsk;
        return Config;
    }

    [[nodiscard]] auto MakeClientConfig() -> ClientConfig
    {
        ClientConfig Config;
        Config.Psk = PerfPsk;
        return Config;
    }

    struct MemoryPair final
    {
        MemoryStream Client;
        MemoryStream Server;
    };

    struct TransferRequest final
    {
        Net::io_context &IoContext;
        MemoryPair Streams;
        std::size_t Total;
    };

    /** @brief 驱动 SS2022 100MB transfer 并等待 server completion。 */
    auto RunTransfer(TransferRequest Request) -> Net::awaitable<void>
    {
        auto ClientTransport = std::make_shared<MemoryStream>(
            std::move(Request.Streams.Client));
        auto ServerTransport = std::make_shared<MemoryStream>(
            std::move(Request.Streams.Server));
        auto Completion = std::make_shared<ServerCompletion>(
            Request.IoContext.get_executor());
        SpawnServer(
            Request.IoContext,
            ServerSession{ServerTransport, MakeServerConfig(), Completion},
            TransferSpec{Request.Total, false});
        auto ClientResult = co_await ConnectClient(
            ClientTransport, MakeClientConfig(), MakeDestination());
        const auto HandshakeError = ClientResult.ErrorCode;
        auto Client = std::move(ClientResult.Connection);
        EXPECT_EQ(HandshakeError, Error::None);
        EXPECT_NE(Client, nullptr);
        std::exception_ptr Failure = std::move(ClientResult.Failure);
        TransferResult Written;
        if (!Failure && HandshakeError == Error::None && Client)
        {
            Written = co_await WriteTransfer(Client, Request.Total);
            if (Written.Failure)
            {
                Failure = std::move(Written.Failure);
            }
        }
        EXPECT_EQ(Written.Sent, Request.Total);
        if (Client)
        {
            (void)Client->Close();
        }
        if (Failure || HandshakeError != Error::None || !Client)
        {
            (void)ClientTransport->Close();
            (void)ServerTransport->Close();
        }
        const auto ServerResult = co_await AwaitServer(Completion);
        if (!Failure && ServerResult.Failure)
        {
            Failure = std::move(ServerResult.Failure);
        }
        EXPECT_TRUE(ServerResult.Completed);
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    struct BenchRequest final
    {
        Net::io_context &IoContext;
        BenchReport &Throughput;
        BenchReport &Latency;
    };

    struct BenchSpec final
    {
        std::size_t Total;
        std::size_t Block;
    };

    auto RunBenchMeasurement(
        const SharedTransmission &Client,
        BenchSpec Spec,
        BenchReport &Report) -> Net::awaitable<std::exception_ptr>
    {
        try
        {
            BenchOptions Options;
            Options.Total = Spec.Total;
            Options.Block = Spec.Block;
            Report = co_await Preview::BenchThroughputTx(
                *Client, *Client, Options);
        }
        catch (...)
        {
            (void)Client->Close();
            co_return std::current_exception();
        }
        co_return nullptr;
    }

    /** @brief 执行一个 benchmark session 并等待 server。 */
    auto RunBenchOne(
        Net::io_context &IoContext,
        BenchSpec Spec,
        BenchReport &Report) -> Net::awaitable<void>
    {
        auto [ClientMemory, ServerMemory] = Preview::MakeMemoryPair(
            IoContext.get_executor());
        auto ClientTransport = std::make_shared<MemoryStream>(
            std::move(ClientMemory));
        auto ServerTransport = std::make_shared<MemoryStream>(
            std::move(ServerMemory));
        auto Completion = std::make_shared<ServerCompletion>(
            IoContext.get_executor());
        SpawnServer(
            IoContext,
            ServerSession{ServerTransport, MakeServerConfig(), Completion},
            TransferSpec{Spec.Total, true});
        auto Result = co_await ConnectClient(
            ClientTransport, MakeClientConfig(), MakeDestination());
        auto Client = std::move(Result.Connection);
        EXPECT_EQ(Result.ErrorCode, Error::None);
        EXPECT_NE(Client, nullptr);
        std::exception_ptr Failure = std::move(Result.Failure);
        if (!Failure && Result.ErrorCode == Error::None && Client)
        {
            Failure = co_await RunBenchMeasurement(Client, Spec, Report);
        }
        if (Client)
        {
            (void)Client->Close();
        }
        if (Failure || Result.ErrorCode != Error::None || !Client)
        {
            (void)ClientTransport->Close();
            (void)ServerTransport->Close();
        }
        const auto ServerResult = co_await AwaitServer(Completion);
        if (!Failure && ServerResult.Failure)
        {
            Failure = std::move(ServerResult.Failure);
        }
        EXPECT_TRUE(ServerResult.Completed);
        EXPECT_EQ(Report.Bytes, Spec.Total);
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    /** @brief 驱动 SS2022 throughput/latency 两组真实 session。 */
    auto RunBenchmarks(BenchRequest Request) -> Net::awaitable<void>
    {
        co_await RunBenchOne(
            Request.IoContext,
            BenchSpec{64 * 1024 * 1024, 64 * 1024},
            Request.Throughput);
        co_await RunBenchOne(
            Request.IoContext,
            BenchSpec{1000 * 4 * 1024, 4 * 1024},
            Request.Latency);
    }

    TEST(Ss2022ClientServer, HandshakeAndTransfer100MB)
    {
        Net::io_context IoContext;
        auto [ClientInput, ServerInput] = Preview::MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, RunTransfer(TransferRequest{
            IoContext, MemoryPair{std::move(ClientInput), std::move(ServerInput)},
            100 * 1024 * 1024}));
    }

    TEST(Ss2022ClientServer, ThroughputLatency)
    {
        Net::io_context IoContext;
        BenchReport ThroughputReport{};
        BenchReport LatencyReport{};
        RunCoroutine(IoContext, RunBenchmarks(BenchRequest{
            IoContext, ThroughputReport, LatencyReport}));
        EXPECT_GT(ThroughputReport.Mbps, 0.0);
        EXPECT_GT(LatencyReport.Samples, 0u);
        std::printf(
            "ss2022 throughput: %.1f MB/s | latency(ms): avg %.3f p50 %.3f "
            "p95 %.3f p99 %.3f (min %.3f max %.3f) samples=%zu\n",
            ThroughputReport.Mbps, LatencyReport.LatencyAvg,
            LatencyReport.LatencyP50, LatencyReport.LatencyP95,
            LatencyReport.LatencyP99, LatencyReport.LatencyMin,
            LatencyReport.LatencyMax, LatencyReport.Samples);
    }

} // namespace
