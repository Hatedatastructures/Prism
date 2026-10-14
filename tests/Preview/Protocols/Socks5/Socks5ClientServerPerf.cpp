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
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <TestSupport/Benchmark/Bench.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Protocols/Socks5/Socks5.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Socks5 = Preview::Socks5;
    using Preview::BenchOptions;
    using Preview::BenchReport;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;

    using ByteHash = std::uint64_t;
    constexpr ByteHash FnvOffset = 14695981039346656037ULL;
    constexpr ByteHash FnvPrime = 1099511628211ULL;
    constexpr std::byte BenchByte{0x5a};

    inline auto UpdateHash(ByteHash &Hash, std::span<const std::byte> Bytes) -> void
    {
        for (const auto Byte : Bytes)
        {
            Hash ^= std::to_integer<std::uint8_t>(Byte);
            Hash *= FnvPrime;
        }
    }

    [[nodiscard]] inline auto ValidatePattern(
        std::span<const std::byte> Bytes, const std::byte Expected) -> bool
    {
        for (const auto Byte : Bytes)
        {
            if (Byte != Expected)
            {
                return false;
            }
        }
        return true;
    }

    struct StreamObservation final
    {
        std::size_t ClientSentBytes{0};
        std::size_t ClientReceivedBytes{0};
        std::size_t ServerReceivedBytes{0};
        std::size_t ServerSentBytes{0};
        ByteHash ClientSentHash{FnvOffset};
        ByteHash ClientReceivedHash{FnvOffset};
        ByteHash ServerReceivedHash{FnvOffset};
        ByteHash ServerSentHash{FnvOffset};
        bool ClientSentValid{true};
        bool ClientReceivedValid{true};
        bool ServerReceivedValid{true};
        bool ServerSentValid{true};
        bool ServerReadEof{false};
        bool ClientPeerEof{false};
        bool ServerReadError{false};
        bool ServerWriteError{false};
        bool ServerSucceeded{false};
        bool ServerException{false};
    };

    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code, bool)>;

    /**
     * @brief 持有 SOCKS5 服务端任务完成回调所需的对象。
     * @details 完成回调报告服务端结果；失败时关闭服务端传输，并唤醒等待方。
     */
    struct ServerSessionCompletion final
    {
        std::shared_ptr<CompletionChannel> Done;
        std::shared_ptr<StreamObservation> Observation;
        std::shared_ptr<MemoryStream> Transport;

        /** @brief 处理服务端协程的最终完成事件。 */
        auto Complete(std::exception_ptr Exception) -> void
        {
            Observation->ServerException = Exception != nullptr;
            if (Exception || !Observation->ServerSucceeded)
            {
                Transport->Close();
            }
            (void)Done->try_send(
                boost::system::error_code{}, Exception == nullptr && Observation->ServerSucceeded);
        }
    };

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

    struct TransferRequest final
    {
        Net::io_context &IoContext;
        std::shared_ptr<MemoryStream> ClientMemory;
        std::shared_ptr<MemoryStream> ServerMemory;
        std::size_t TotalBytes;
        std::size_t BlockSize;
    };

    struct TransferServerRequest final
    {
        std::shared_ptr<MemoryStream> Transport;
        std::size_t TotalBytes;
        std::size_t BlockSize;
        std::shared_ptr<StreamObservation> Observation;
    };

    auto RunTransferServer(TransferServerRequest ServerRequest) -> Net::awaitable<void>
    {
        const auto ServerTransport = ServerRequest.Transport;
        Socks5::ServerConfig ServerConfig{};
        auto [AcceptError, HandshakeRequest, Connection] = co_await Socks5::Accept(
            std::move(ServerRequest.Transport), ServerConfig);
        if (AcceptError != Error::None || !Connection)
        {
            EXPECT_TRUE(false) << "Accept Failed";
            co_return;
        }
        EXPECT_EQ(HandshakeRequest.Target.Port, 443u);
        auto &Observation = *ServerRequest.Observation;
        std::vector<std::byte> Buffer(ServerRequest.BlockSize);
        std::size_t Received = 0;
        while (Received < ServerRequest.TotalBytes)
        {
            const auto Read = co_await Connection->ReadSome(Buffer);
            if (Read.Bytes != 0U)
            {
                const auto ReadBytes = std::span<const std::byte>(Buffer.data(), Read.Bytes);
                UpdateHash(Observation.ServerReceivedHash, ReadBytes);
                Observation.ServerReceivedValid =
                    Observation.ServerReceivedValid && ValidatePattern(ReadBytes, std::byte{0x6D});
                Received += Read.Bytes;
            }
            if (Read.Failure.Failed())
            {
                Observation.ServerReadEof = Read.Failure.Code == Preview::Fault::Code::Eof;
                Observation.ServerReadError = !Observation.ServerReadEof;
                break;
            }
            if (Read.Bytes == 0U)
            {
                Observation.ServerReadError = true;
                break;
            }
        }
        Observation.ServerReceivedBytes = Received;
        if (!Observation.ServerReadError && !Observation.ServerReadEof)
        {
            std::array<std::byte, 1> Tail{};
            const auto TailRead = co_await Connection->ReadSome(Tail);
            Observation.ServerReadError = TailRead.Failure.Failed() &&
                TailRead.Failure.Code != Preview::Fault::Code::Eof;
            Observation.ServerReadEof = TailRead.Bytes == 0U &&
                TailRead.Failure.Code == Preview::Fault::Code::Eof;
        }
        Observation.ServerSucceeded =
            Observation.ServerReceivedBytes == ServerRequest.TotalBytes &&
            Observation.ServerReceivedValid && Observation.ServerReadEof &&
            !Observation.ServerReadError;
        const auto Close = Connection->Close();
        EXPECT_TRUE(Close);
        const auto ConnectionDrain = co_await Connection->Activity()->Drain();
        EXPECT_TRUE(ConnectionDrain);
        const auto TransportDrain = co_await ServerTransport->Activity()->Drain();
        EXPECT_TRUE(TransportDrain);
    }

    inline auto AssertTransferObservation(
        const StreamObservation &Observation, const std::size_t TotalBytes) -> void
    {
        EXPECT_FALSE(Observation.ServerException);
        EXPECT_TRUE(Observation.ServerSucceeded);
        EXPECT_EQ(Observation.ClientSentBytes, TotalBytes);
        EXPECT_EQ(Observation.ServerReceivedBytes, TotalBytes);
        EXPECT_EQ(Observation.ClientSentHash, Observation.ServerReceivedHash);
        EXPECT_TRUE(Observation.ClientSentValid);
        EXPECT_TRUE(Observation.ServerReceivedValid);
        EXPECT_TRUE(Observation.ServerReadEof);
        EXPECT_TRUE(Observation.ClientPeerEof);
        EXPECT_FALSE(Observation.ServerReadError);
    }

    auto RunHandshakeAndTransfer(TransferRequest Request) -> Net::awaitable<void>
    {
        auto ServerDone = std::make_shared<CompletionChannel>(
            Request.IoContext.get_executor(), 1);
        auto Observation = std::make_shared<StreamObservation>();
        const auto ServerTransport = Request.ServerMemory;
        auto ServerCompletion = [Completion = ServerSessionCompletion{
                                     ServerDone, Observation, ServerTransport}](
                                    std::exception_ptr Exception) mutable -> void
        {
            Completion.Complete(Exception);
        };
        const auto ClientTransport = Request.ClientMemory;
        Net::co_spawn(
            Request.IoContext.get_executor(),
            RunTransferServer(TransferServerRequest{
                std::move(Request.ServerMemory), Request.TotalBytes, Request.BlockSize, Observation}),
            std::move(ServerCompletion));

        Socks5::ClientConfig ClientConfig{};
        const auto Destination = MakeDestination();
        auto [ConnectError, Client] = co_await Socks5::Connect(
            std::move(Request.ClientMemory), ClientConfig, Destination);
        if (ConnectError != Error::None || !Client)
        {
            EXPECT_TRUE(false) << "Connect Failed";
            const auto ClientClose = ClientTransport->Close();
            EXPECT_TRUE(ClientClose);
            (void)co_await ServerDone->async_receive(Net::use_awaitable);
            const auto ClientDrain = co_await ClientTransport->Activity()->Drain();
            EXPECT_TRUE(ClientDrain);
            const auto ServerDrain = co_await ServerTransport->Activity()->Drain();
            EXPECT_TRUE(ServerDrain);
            co_return;
        }
        std::vector<std::uint8_t> Payload(Request.BlockSize, 0x6D);
        std::size_t Sent = 0;
        std::size_t YieldCount = 0;
        while (Sent < Request.TotalBytes)
        {
            if ((++YieldCount % 16) == 0)
            {
                co_await Net::post(Request.IoContext.get_executor(), Net::use_awaitable);
            }
            const auto ChunkSize = (std::min)(Request.BlockSize, Request.TotalBytes - Sent);
            std::size_t WrittenTotal = 0;
            while (WrittenTotal < ChunkSize)
            {
                const auto PayloadBuffer = std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(Payload.data() + WrittenTotal),
                    ChunkSize - WrittenTotal);
                const auto Write = co_await Client->WriteSome(PayloadBuffer);
                if (Write.Bytes != 0U)
                {
                    WrittenTotal += Write.Bytes;
                    const auto WrittenBytes = PayloadBuffer.first(Write.Bytes);
                    UpdateHash(Observation->ClientSentHash, WrittenBytes);
                    Observation->ClientSentValid =
                        Observation->ClientSentValid && ValidatePattern(WrittenBytes, std::byte{0x6D});
                    Observation->ClientSentBytes += Write.Bytes;
                }
                if (Write.Failure.Failed() || Write.Bytes == 0U)
                {
                    break;
                }
            }
            if (WrittenTotal < ChunkSize)
            {
                break;
            }
            Sent += ChunkSize;
        }
        EXPECT_EQ(Sent, Request.TotalBytes);
        const auto Shutdown = co_await Client->WriteShutdown();
        EXPECT_TRUE(Shutdown);
        if (!Shutdown)
        {
            const auto Close = Client->Close();
            EXPECT_TRUE(Close);
        }
        const auto ServerCompleted = co_await ServerDone->async_receive(Net::use_awaitable);
        EXPECT_TRUE(ServerCompleted);
        const auto ServerDrain = co_await ServerTransport->Activity()->Drain();
        EXPECT_TRUE(ServerDrain);
        std::array<std::byte, 1> Tail{};
        const auto TailRead = co_await Client->ReadSome(Tail);
        Observation->ClientPeerEof = TailRead.Bytes == 0U &&
            TailRead.Failure.Code == Preview::Fault::Code::Eof;
        const auto Close = Client->Close();
        EXPECT_TRUE(Close);
        const auto ConnectionDrain = co_await Client->Activity()->Drain();
        EXPECT_TRUE(ConnectionDrain);
        const auto TransportDrain = co_await ClientTransport->Activity()->Drain();
        EXPECT_TRUE(TransportDrain);
        AssertTransferObservation(*Observation, Request.TotalBytes);
    }

    struct BenchPassRequest final
    {
        Net::io_context &IoContext;
        std::shared_ptr<MemoryStream> ClientMemory;
        std::shared_ptr<MemoryStream> ServerMemory;
        BenchReport &Report;
        std::size_t TotalBytes;
        std::size_t BlockSize;
    };

    struct EchoServerRequest final
    {
        std::shared_ptr<MemoryStream> Transport;
        std::size_t TotalBytes;
        std::shared_ptr<StreamObservation> Observation;
    };

    struct BenchClientProbe final
    {
        Socks5::SharedConn Connection;
        std::shared_ptr<StreamObservation> Observation;

        auto ReadSome(std::span<std::byte> Buffer) -> Net::awaitable<Preview::IoResult>
        {
            const auto Read = co_await Connection->ReadSome(Buffer);
            if (Read.Bytes != 0U)
            {
                const auto ReadBytes = std::span<const std::byte>(Buffer.data(), Read.Bytes);
                UpdateHash(Observation->ClientReceivedHash, ReadBytes);
                Observation->ClientReceivedValid =
                    Observation->ClientReceivedValid && ValidatePattern(ReadBytes, BenchByte);
                Observation->ClientReceivedBytes += Read.Bytes;
            }
            co_return Read;
        }

        auto WriteSome(std::span<const std::byte> Buffer) -> Net::awaitable<Preview::IoResult>
        {
            const auto Write = co_await Connection->WriteSome(Buffer);
            if (Write.Bytes != 0U)
            {
                const auto WrittenBytes = Buffer.first(Write.Bytes);
                UpdateHash(Observation->ClientSentHash, WrittenBytes);
                Observation->ClientSentValid =
                    Observation->ClientSentValid && ValidatePattern(WrittenBytes, BenchByte);
                Observation->ClientSentBytes += Write.Bytes;
            }
            co_return Write;
        }
    };

    auto RunEchoServer(EchoServerRequest ServerRequest) -> Net::awaitable<void>
    {
        const auto ServerTransport = ServerRequest.Transport;
        Socks5::ServerConfig ServerConfig{};
        auto [AcceptError, HandshakeRequest, Connection] = co_await Socks5::Accept(
            std::move(ServerRequest.Transport), ServerConfig);
        (void)HandshakeRequest;
        if (AcceptError != Error::None || !Connection)
        {
            co_return;
        }
        auto &Observation = *ServerRequest.Observation;
        std::array<std::byte, 128 * 1024> Buffer{};
        while (true)
        {
            const auto Read = co_await Connection->ReadSome(Buffer);
            if (Read.Bytes != 0U)
            {
                const auto ReadBytes = std::span<const std::byte>(Buffer.data(), Read.Bytes);
                UpdateHash(Observation.ServerReceivedHash, ReadBytes);
                Observation.ServerReceivedValid =
                    Observation.ServerReceivedValid && ValidatePattern(ReadBytes, BenchByte);
                Observation.ServerReceivedBytes += Read.Bytes;
            }
            if (Read.Failure.Failed())
            {
                Observation.ServerReadEof = Read.Failure.Code == Preview::Fault::Code::Eof;
                Observation.ServerReadError = !Observation.ServerReadEof;
                break;
            }
            if (Read.Bytes == 0U)
            {
                Observation.ServerReadError = true;
                break;
            }
            const auto Response = std::span<const std::byte>(Buffer.data(), Read.Bytes);
            std::size_t WrittenTotal = 0;
            while (WrittenTotal < Response.size())
            {
                const auto Write = co_await Connection->WriteSome(Response.subspan(WrittenTotal));
                if (Write.Bytes != 0U)
                {
                    const auto WrittenBytes = Response.subspan(WrittenTotal, Write.Bytes);
                    UpdateHash(Observation.ServerSentHash, WrittenBytes);
                    Observation.ServerSentValid =
                        Observation.ServerSentValid && ValidatePattern(WrittenBytes, BenchByte);
                    Observation.ServerSentBytes += Write.Bytes;
                    WrittenTotal += Write.Bytes;
                }
                if (Write.Failure.Failed() || Write.Bytes == 0U)
                {
                    Observation.ServerWriteError = true;
                    break;
                }
            }
            if (Observation.ServerWriteError)
            {
                break;
            }
        }
        Observation.ServerSucceeded =
            Observation.ServerReceivedBytes == ServerRequest.TotalBytes &&
            Observation.ServerSentBytes == ServerRequest.TotalBytes &&
            Observation.ServerReceivedValid && Observation.ServerSentValid &&
            Observation.ServerReadEof && !Observation.ServerReadError &&
            !Observation.ServerWriteError;
        const auto Close = Connection->Close();
        EXPECT_TRUE(Close);
        const auto ConnectionDrain = co_await Connection->Activity()->Drain();
        EXPECT_TRUE(ConnectionDrain);
        const auto TransportDrain = co_await ServerTransport->Activity()->Drain();
        EXPECT_TRUE(TransportDrain);
    }

    inline auto AssertEchoObservation(
        const StreamObservation &Observation, const std::size_t TotalBytes) -> void
    {
        EXPECT_FALSE(Observation.ServerException);
        EXPECT_TRUE(Observation.ServerSucceeded);
        EXPECT_EQ(Observation.ClientSentBytes, TotalBytes);
        EXPECT_EQ(Observation.ClientReceivedBytes, TotalBytes);
        EXPECT_EQ(Observation.ServerReceivedBytes, TotalBytes);
        EXPECT_EQ(Observation.ServerSentBytes, TotalBytes);
        EXPECT_EQ(Observation.ClientSentHash, Observation.ServerReceivedHash);
        EXPECT_EQ(Observation.ServerSentHash, Observation.ClientReceivedHash);
        EXPECT_TRUE(Observation.ClientSentValid);
        EXPECT_TRUE(Observation.ClientReceivedValid);
        EXPECT_TRUE(Observation.ServerReceivedValid);
        EXPECT_TRUE(Observation.ServerSentValid);
        EXPECT_TRUE(Observation.ServerReadEof);
        EXPECT_TRUE(Observation.ClientPeerEof);
        EXPECT_FALSE(Observation.ServerReadError);
        EXPECT_FALSE(Observation.ServerWriteError);
    }

    auto RunBenchPass(BenchPassRequest Request) -> Net::awaitable<void>
    {
        auto ServerDone = std::make_shared<CompletionChannel>(
            Request.IoContext.get_executor(), 1);
        auto Observation = std::make_shared<StreamObservation>();
        const auto ServerTransport = Request.ServerMemory;
        auto ServerCompletion = [Completion = ServerSessionCompletion{
                                     ServerDone, Observation, ServerTransport}](
                                    std::exception_ptr Exception) mutable -> void
        {
            Completion.Complete(Exception);
        };
        const auto ClientTransport = Request.ClientMemory;
        Net::co_spawn(Request.IoContext.get_executor(),
                      RunEchoServer(EchoServerRequest{
                          std::move(Request.ServerMemory), Request.TotalBytes, Observation}),
                      std::move(ServerCompletion));

        Socks5::ClientConfig ClientConfig{};
        auto [ConnectError, Client] = co_await Socks5::Connect(
            std::move(Request.ClientMemory), ClientConfig, MakeDestination());
        if (ConnectError != Error::None || !Client)
        {
            const auto ClientClose = ClientTransport->Close();
            EXPECT_TRUE(ClientClose);
            const auto ServerCompleted = co_await ServerDone->async_receive(Net::use_awaitable);
            EXPECT_FALSE(ServerCompleted);
            const auto ClientDrain = co_await ClientTransport->Activity()->Drain();
            EXPECT_TRUE(ClientDrain);
            const auto ServerDrain = co_await ServerTransport->Activity()->Drain();
            EXPECT_TRUE(ServerDrain);
            co_return;
        }
        BenchOptions Options;
        Options.Total = Request.TotalBytes;
        Options.Block = Request.BlockSize;
        // 校验 probe 在 typed 基准的 I/O 计时回调内运行，当前报告包含校验开销。
        BenchClientProbe Probe{Client, Observation};
        const auto BenchResult = co_await Preview::BenchPreviewThroughput(Probe, Probe, Options);
        Request.Report = BenchResult.Report;
        EXPECT_FALSE(BenchResult.Failure.Failed())
            << Preview::Fault::ToNative(BenchResult.Failure).message();
        EXPECT_EQ(BenchResult.BytesWritten, Request.TotalBytes);
        EXPECT_EQ(BenchResult.BytesRead, Request.TotalBytes);
        const auto Shutdown = co_await Client->WriteShutdown();
        EXPECT_TRUE(Shutdown);
        if (!Shutdown)
        {
            const auto ClientClose = Client->Close();
            EXPECT_TRUE(ClientClose);
        }
        const auto ServerCompleted = co_await ServerDone->async_receive(Net::use_awaitable);
        EXPECT_TRUE(ServerCompleted);
        const auto ServerDrain = co_await ServerTransport->Activity()->Drain();
        EXPECT_TRUE(ServerDrain);
        std::array<std::byte, 1> Tail{};
        const auto TailRead = co_await Probe.ReadSome(Tail);
        Observation->ClientPeerEof = TailRead.Bytes == 0U &&
            TailRead.Failure.Code == Preview::Fault::Code::Eof;
        const auto Close = Client->Close();
        EXPECT_TRUE(Close);
        const auto ConnectionDrain = co_await Client->Activity()->Drain();
        EXPECT_TRUE(ConnectionDrain);
        const auto TransportDrain = co_await ClientTransport->Activity()->Drain();
        EXPECT_TRUE(TransportDrain);
        AssertEchoObservation(*Observation, Request.TotalBytes);
    }

    struct ThroughputLatencyRequest final
    {
        Net::io_context &IoContext;
        std::shared_ptr<MemoryStream> ClientMemory;
        std::shared_ptr<MemoryStream> ServerMemory;
        BenchReport &ThroughputReport;
        BenchReport &LatencyReport;
    };

    auto RunThroughputLatency(ThroughputLatencyRequest Request)
        -> Net::awaitable<void>
    {
        co_await RunBenchPass(BenchPassRequest{
            Request.IoContext, std::move(Request.ClientMemory),
            std::move(Request.ServerMemory), Request.ThroughputReport,
            64 * 1024 * 1024, 64 * 1024});

        auto [LatencyClientMemory, LatencyServerMemory] = MakeMemoryPair(
            Request.IoContext.get_executor());
        co_await RunBenchPass(BenchPassRequest{
            Request.IoContext, std::make_shared<MemoryStream>(std::move(LatencyClientMemory)),
            std::make_shared<MemoryStream>(std::move(LatencyServerMemory)), Request.LatencyReport,
            1000 * 4 * 1024, 4 * 1024});
    }

    TEST(Socks5ClientServer, HandshakeAndTransfer100MB)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());

        RunCoro(IoContext, RunHandshakeAndTransfer(TransferRequest{
                          IoContext,
                          std::make_shared<MemoryStream>(std::move(ClientMemory)),
                          std::make_shared<MemoryStream>(std::move(ServerMemory)),
                          100 * 1024 * 1024,
                          64 * 1024}));
    }

    TEST(Socks5ClientServer, ThroughputLatency)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());

        BenchReport ThroughputReport{};
        BenchReport LatencyReport{};
        RunCoro(IoContext, RunThroughputLatency(ThroughputLatencyRequest{
                          IoContext,
                          std::make_shared<MemoryStream>(std::move(ClientMemory)),
                          std::make_shared<MemoryStream>(std::move(ServerMemory)),
                          ThroughputReport,
                          LatencyReport}));

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
        std::puts("socks5 validation_boundary=BenchPreviewThroughput I/O callbacks include payload/hash validation; no historical raw comparison");
    }

} // namespace
