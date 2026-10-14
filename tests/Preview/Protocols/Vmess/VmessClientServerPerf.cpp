/**
 * @file VmessClientServerPerf.cpp
 * @brief VMess 客户端/服务端封装测试（传输完整性 + 性能）
 * @details 覆盖：
 *          - 100MB / 1GB 传输完整性
 *          - 吞吐量（MB/s）
 *          - 回环延迟（avg/p50/p95/p99/min/max）
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <cstdio>
#include <memory>
#include <string>
#include <variant>
#include <vector>

#include <TestSupport/Benchmark/Bench.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Protocols/Vmess/Vmess.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Vmess = Preview::Vmess;
    using Preview::AsBytes;
    using Preview::BenchOptions;
    using Preview::BenchPreviewThroughput;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::PreviewBenchResult;

    template <typename A>
    auto RunCoroutine(Net::io_context &IoContext, A Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Coroutine),
                      [&](std::exception_ptr ErrorValue)
                      {
                          Exception = ErrorValue;
                          IoContext.stop();
                      });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    auto MakeUuid() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> Uuid{};
        Uuid.fill(0x42);
        return Uuid;
    }

    auto MakeDestination() -> Vmess::Address
    {
        Vmess::Address Destination{};
        Destination.Type = Vmess::AddressType::Ipv4;
        Destination.Host = "93.184.216.34";
        Destination.Port = 443;
        return Destination;
    }

    /** @brief 将 VMess 读到的每个有效字节完整回送后再处理终态 Failure。 */
    auto RunVmessEchoServer(Vmess::SharedConn Connection) -> Net::awaitable<void>
    {
        std::array<std::byte, 128 * 1024> Buffer{};
        while (true)
        {
            const auto Read = co_await Connection->ReadSome(Buffer);
            if (Read.Bytes > Buffer.size() || Read.Bytes == 0)
            {
                break;
            }
            std::size_t Written = 0;
            bool Failed = false;
            while (Written < Read.Bytes)
            {
                const auto Window = std::span<const std::byte>(Buffer).subspan(
                    Written, Read.Bytes - Written);
                const auto Result = co_await Connection->WriteSome(Window);
                if (Result.Bytes > Window.size())
                {
                    Failed = true;
                    break;
                }
                Written += Result.Bytes;
                if (Result.Failure.Failed() || Result.Bytes == 0)
                {
                    Failed = true;
                    break;
                }
            }
            if (Failed || Written != Read.Bytes || Read.Failure.Failed())
            {
                break;
            }
        }
        (void)Connection->Close();
    }

    inline constexpr std::size_t VmessTransferBlock = 64 * 1024;

    /** @brief 接收固定 VMess 负载并返回真实字节进度。 */
    [[nodiscard]] auto RunVmessTransferServer(
        Preview::SharedTransmission Upstream,
        const std::size_t Total) -> Net::awaitable<bool>
    {
        auto AcceptResult = co_await Vmess::AcceptSession(
            std::move(Upstream), Vmess::ServerConfig{MakeUuid()});
        EXPECT_TRUE(AcceptResult);
        auto* Accepted = AcceptResult
            ? std::get_if<Vmess::AcceptedConnection>(&*AcceptResult)
            : nullptr;
        if (AcceptResult) EXPECT_NE(Accepted, nullptr);
        if (!AcceptResult || !Accepted || !Accepted->Connection)
        {
            if (AcceptResult)
            {
                if (auto* Datagram = std::get_if<Vmess::AcceptedDatagram>(&*AcceptResult))
                {
                    auto Carrier = Datagram->Connection;
                    auto Stream = Carrier->Stream();
                    (void)Carrier->Close();
                    (void)Stream->Close();
                    (void)co_await Carrier->Activity()->Drain();
                    (void)co_await Stream->Activity()->Drain();
                }
            }
            EXPECT_TRUE(false) << "Accept Failed";
            co_return false;
        }
        auto Message = std::move(Accepted->Request);
        auto Connection = std::move(Accepted->Connection);
        EXPECT_EQ(Message.dst.Port, 443u);
        std::array<std::byte, VmessTransferBlock> Buffer{};
        std::size_t Received = 0;
        bool Failed = false;
        while (Received < Total)
        {
            const auto Limit = (std::min)(Buffer.size(), Total - Received);
            const auto Window = std::span<std::byte>(Buffer).first(Limit);
            const auto Read = co_await Connection->ReadSome(Window);
            if (Read.Bytes > Limit)
            {
                Failed = true;
                break;
            }
            Received += Read.Bytes;
            if (Read.Failure.Failed() || Read.Bytes == 0)
            {
                Failed = true;
                break;
            }
        }
        (void)Connection->Close();
        EXPECT_EQ(Received, Total);
        EXPECT_FALSE(Failed);
        co_return !Failed && Received == Total;
    }

    /** @brief 写完 VMess 固定负载并保留短写后的有效进度。 */
    [[nodiscard]] auto RunVmessTransferClient(
        Preview::SharedTransmission Upstream,
        const std::size_t Total) -> Net::awaitable<bool>
    {
        const auto Executor = Upstream->Executor();
        auto ConnectResult = co_await Vmess::Connect(Vmess::ConnectParameters{
            std::move(Upstream), Vmess::ClientConfig{MakeUuid()}, MakeDestination()});
        EXPECT_TRUE(ConnectResult);
        if (ConnectResult) EXPECT_TRUE(*ConnectResult);
        if (!ConnectResult || !*ConnectResult)
        {
            EXPECT_TRUE(false) << "Connect Failed";
            co_return false;
        }
        auto Client = std::move(*ConnectResult);
        std::vector<std::uint8_t> Payload(VmessTransferBlock, 0x5A);
        std::size_t Sent = 0;
        std::size_t YieldCount = 0;
        bool Failed = false;
        while (Sent < Total)
        {
            if ((++YieldCount % 16) == 0)
            {
                co_await Net::post(Executor, Net::use_awaitable);
            }
            const auto Limit = (std::min)(Payload.size(), Total - Sent);
            const auto Window = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Payload.data()), Limit);
            std::size_t BlockWritten = 0;
            while (BlockWritten < Limit)
            {
                const auto Remaining = Window.subspan(BlockWritten);
                const auto Write = co_await Client->WriteSome(Remaining);
                if (Write.Bytes > Remaining.size())
                {
                    Failed = true;
                    break;
                }
                BlockWritten += Write.Bytes;
                Sent += Write.Bytes;
                if (Write.Failure.Failed() || Write.Bytes == 0)
                {
                    Failed = true;
                    break;
                }
            }
            if (Failed)
            {
                break;
            }
        }
        (void)Client->Close();
        EXPECT_EQ(Sent, Total);
        EXPECT_FALSE(Failed);
        co_return !Failed && Sent == Total;
    }

    struct VmessBenchReports final
    {
        PreviewBenchResult Throughput;
        PreviewBenchResult Latency;
    };
    /** @brief 执行 VMess 基准用的认证服务端会话。 */
    auto RunVmessAcceptServer(std::shared_ptr<MemoryStream> Stream) -> Net::awaitable<void>
    {
        auto AcceptResult = co_await Vmess::AcceptSession(Stream, Vmess::ServerConfig{MakeUuid()});
        EXPECT_TRUE(AcceptResult);
        auto* Accepted = AcceptResult
            ? std::get_if<Vmess::AcceptedConnection>(&*AcceptResult)
            : nullptr;
        if (AcceptResult) EXPECT_NE(Accepted, nullptr);
        if (!AcceptResult || !Accepted || !Accepted->Connection)
        {
            if (AcceptResult)
            {
                if (auto* Datagram = std::get_if<Vmess::AcceptedDatagram>(&*AcceptResult))
                {
                    auto Carrier = Datagram->Connection;
                    auto Underlying = Carrier->Stream();
                    (void)Carrier->Close();
                    (void)Underlying->Close();
                    (void)co_await Carrier->Activity()->Drain();
                    (void)co_await Underlying->Activity()->Drain();
                }
            }
            co_return;
        }
        co_await RunVmessEchoServer(std::move(Accepted->Connection));
    }

    /** @brief 运行固定吞吐和延迟 VMess 基准场景。 */
    auto RunVmessThroughputLatency(
        Net::io_context& IoContext,
        VmessBenchReports& Reports) -> Net::awaitable<void>
    {
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        auto ThroughputServer = std::make_shared<MemoryStream>(std::move(ServerStream));
        auto ThroughputClient = std::make_shared<MemoryStream>(std::move(ClientStream));
        Net::co_spawn(IoContext.get_executor(), [ThroughputServer]() -> Net::awaitable<void>
        {
            co_await RunVmessAcceptServer(ThroughputServer);
        }, Net::detached);
        auto ThroughputResult = co_await Vmess::Connect(Vmess::ConnectParameters{
            ThroughputClient, Vmess::ClientConfig{MakeUuid()}, MakeDestination()});
        if (!ThroughputResult)
        {
            Reports.Throughput.Failure = ThroughputResult.error();
            co_return;
        }
        EXPECT_TRUE(*ThroughputResult);
        if (!*ThroughputResult)
        {
            Reports.Throughput.Failure =
                Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument};
            co_return;
        }
        auto ThroughputConnection = std::move(*ThroughputResult);
        BenchOptions ThroughputOptions;
        ThroughputOptions.Total = 64 * 1024 * 1024;
        ThroughputOptions.Block = 64 * 1024;
        Reports.Throughput = co_await BenchPreviewThroughput(
            *ThroughputConnection, *ThroughputConnection, ThroughputOptions);
        (void)ThroughputConnection->Close();

        auto [LatencyClientStream, LatencyServerStream] = MakeMemoryPair(IoContext.get_executor());
        auto LatencyServer = std::make_shared<MemoryStream>(std::move(LatencyServerStream));
        auto LatencyClient = std::make_shared<MemoryStream>(std::move(LatencyClientStream));
        Net::co_spawn(IoContext.get_executor(), [LatencyServer]() -> Net::awaitable<void>
        {
            co_await RunVmessAcceptServer(LatencyServer);
        }, Net::detached);
        auto LatencyResult = co_await Vmess::Connect(Vmess::ConnectParameters{
            LatencyClient, Vmess::ClientConfig{MakeUuid()}, MakeDestination()});
        if (!LatencyResult)
        {
            Reports.Latency.Failure = LatencyResult.error();
            co_return;
        }
        EXPECT_TRUE(*LatencyResult);
        if (!*LatencyResult)
        {
            Reports.Latency.Failure =
                Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument};
            co_return;
        }
        auto LatencyConnection = std::move(*LatencyResult);
        BenchOptions LatencyOptions;
        LatencyOptions.Total = 1000 * 4 * 1024;
        LatencyOptions.Block = 4 * 1024;
        Reports.Latency = co_await BenchPreviewThroughput(
            *LatencyConnection, *LatencyConnection, LatencyOptions);
        (void)LatencyConnection->Close();
    }

    auto CheckBenchResult(
        const char *Name,
        const PreviewBenchResult &Result,
        const std::size_t ExpectedBytes) -> void
    {
        const auto &Failure = Result.Failure;
        EXPECT_TRUE(Failure.Succeeded())
            << Name << " failure code=" << static_cast<int>(Failure.Code)
            << " native=" << (Failure.Native ? Failure.Native.category().name() : "none")
            << '/' << Failure.Native.value()
            << " written=" << Result.BytesWritten << " read=" << Result.BytesRead;
        EXPECT_EQ(Result.Report.Bytes, ExpectedBytes);
        EXPECT_EQ(Result.BytesWritten, ExpectedBytes);
        EXPECT_EQ(Result.BytesRead, ExpectedBytes);
    }

    /// 传输完整性测试（Client 写 Server 读）
    auto RunTransfer(Net::io_context& IoContext, const std::size_t Total) -> void
    {
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        auto Server = std::make_shared<MemoryStream>(std::move(ServerStream));
        auto Client = std::make_shared<MemoryStream>(std::move(ClientStream));
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
        {
            Net::co_spawn(
                IoContext.get_executor(),
                RunVmessTransferServer(Server, Total),
                Net::detached);
            const auto Completed = co_await RunVmessTransferClient(Client, Total);
            EXPECT_TRUE(Completed);
        });
    }

    TEST(VmessClientServer, Transfer100MB)
    {
        Net::io_context ioc;
        RunTransfer(ioc, 100 * 1024 * 1024);
    }

    TEST(VmessClientServer, Transfer1GB)
    {
        Net::io_context ioc;
        RunTransfer(ioc, 1024 * 1024 * 1024);
    }

    TEST(VmessClientServer, ThroughputLatency)
    {
        Net::io_context IoContext;
        VmessBenchReports Reports{};
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
        {
            co_await RunVmessThroughputLatency(IoContext, Reports);
        });

        CheckBenchResult("throughput", Reports.Throughput, 64U * 1024U * 1024U);
        CheckBenchResult("latency", Reports.Latency, 1000U * 4U * 1024U);

        std::printf("vmess throughput: %.1f MB/s | latency(ms): avg %.3f p50 %.3f p95 %.3f p99 %.3f (min "
                    "%.3f max %.3f) samples=%zu\n",
                    Reports.Throughput.Report.Mbps, Reports.Latency.Report.LatencyAvg,
                    Reports.Latency.Report.LatencyP50, Reports.Latency.Report.LatencyP95,
                    Reports.Latency.Report.LatencyP99, Reports.Latency.Report.LatencyMin,
                    Reports.Latency.Report.LatencyMax, Reports.Latency.Report.Samples);
    }

} // namespace
