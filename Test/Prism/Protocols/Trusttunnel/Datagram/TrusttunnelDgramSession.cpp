/**
 * @file TrusttunnelDgramSession.cpp
 * @brief TrustTunnel Dgram 包连接双向测试（Client + Server 视角）
 * @details 覆盖 ConnectPacket / AcceptPacket、数据报往返、错误分支与装饰器链行为。
 * @note 使用 MakeMemoryPair 建立内存传输对，同一进程内双向互操作。
 */

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Trusttunnel/Codec.hpp>
#include <Prism/Protocols/Trusttunnel/TransportTypes.hpp>
#include <Prism/Protocols/Trusttunnel/Trusttunnel.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Trusttunnel = Prism::Trusttunnel;
    using Prism::AsU8Span;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    using Prism::PrismMockTransport;

    class TerminalHandshakeTransmission final : public Prism::Transmission
    {
    public:
        TerminalHandshakeTransmission(
            ExecutorType Executor,
            std::vector<std::byte> Input,
            Prism::Fault::Failure ReadFailure)
            : Transmission(Executor), Ex_(std::move(Executor)), Input_(std::move(Input)),
              ReadFailure_(ReadFailure)
        {
        }

        [[nodiscard]] auto ReadCount() const noexcept -> std::size_t
        {
            return ReadCount_;
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadCount_;
            if (ReadCount_ != 1U)
            {
                Prism::Transmission::PostResult(
                    Executor(), std::move(Handler),
                    {0, {Prism::Fault::Code::WouldBlock}});
                return;
            }
            const auto Count = (std::min)(Buffer.size(), Input_.size());
            std::copy_n(Input_.begin(), Count, Buffer.begin());
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {Count, ReadFailure_});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {Buffer.size(), {}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        ExecutorType Ex_;
        std::vector<std::byte> Input_;
        Prism::Fault::Failure ReadFailure_;
        std::size_t ReadCount_{0};
    };

    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    /** @brief 运行协程直至完成，并在测试线程重抛异常。 */
    template <typename Awaitable>
    auto RunCoro(Net::io_context &IoContext, Awaitable Operation) -> void
    {
        std::exception_ptr Exception;
        auto Completion = [&](std::exception_ptr ErrorValue) -> void
        {
            Exception = ErrorValue;
            IoContext.stop();
        };
        Net::co_spawn(IoContext, std::move(Operation), std::move(Completion));
        IoContext.run();
        if (Exception) std::rethrow_exception(Exception);
    }

    [[nodiscard]] auto CloseAndDrainTransport(Prism::SharedTransmission Transport)
        -> Net::awaitable<void>
    {
        EXPECT_TRUE(Transport);
        if (!Transport) co_return;
        const auto Closed = Transport->Close();
        const auto Activity = Transport->Activity();
        EXPECT_TRUE(Activity);
        if (!Activity) co_return;
        const auto Drained = co_await Activity->Drain();
        EXPECT_TRUE(Closed);
        if (!Closed)
        {
            ADD_FAILURE() << "Close failed code="
                          << static_cast<unsigned>(Closed.error().Code)
                          << " native=" << Closed.error().Native.category().name()
                          << ':' << Closed.error().Native.value();
        }
        EXPECT_TRUE(Drained);
        if (!Drained)
        {
            ADD_FAILURE() << "Drain failed transport="
                          << static_cast<unsigned>(Transport->TransportType())
                          << " open=" << Transport->IsOpen()
                          << " code="
                          << static_cast<unsigned>(Drained.error().Code)
                          << " native=" << Drained.error().Native.category().name()
                          << ':' << Drained.error().Native.value();
        }
        EXPECT_TRUE(Activity->IsRetired());
    }

    struct TrusttunnelTerminalHandshakeOutcome final
    {
        Prism::Fault::Failure HandshakeFailure{};
        std::string Target;
        std::string Tail;
        std::size_t TailBytes{0};
        Prism::Fault::Failure TailFailure{};
        std::size_t TerminalBytes{0};
        Prism::Fault::Failure TerminalFailure{};
        std::size_t StickyBytes{0};
        Prism::Fault::Failure StickyFailure{};
    };

    struct TrusttunnelTerminalHandshakeRequest final
    {
        std::shared_ptr<TerminalHandshakeTransmission> Transport;
        TrusttunnelTerminalHandshakeOutcome *Outcome;
    };

    [[nodiscard]] auto MakeTerminalHandshakeWire() -> std::vector<std::byte>
    {
        std::string Input = "CONNECT example.com:443 HTTP/2\r\nProxy-Authorization: ";
        Input += Trusttunnel::BasicAuth("admin", "Secret");
        Input += "\r\n\r\ntunnel-tail";
        std::vector<std::byte> Wire;
        Wire.reserve(Input.size());
        for (const auto Character : Input)
        {
            Wire.push_back(static_cast<std::byte>(Character));
        }
        return Wire;
    }

    auto RunTrusttunnelTerminalHandshake(
        TrusttunnelTerminalHandshakeRequest Request) -> Net::awaitable<void>
    {
        Trusttunnel::ServerConfig Configuration;
        Configuration.username = "admin";
        Configuration.password = "Secret";
        auto Accepted = co_await Trusttunnel::Accept(Request.Transport, Configuration);
        if (!Accepted)
        {
            Request.Outcome->HandshakeFailure = Accepted.error();
            co_return;
        }

        auto Connection = Accepted->Connection;
        Request.Outcome->Target = Accepted->Target;
        std::array<std::byte, 32> Buffer{};
        const auto Tail = co_await Connection->ReadSome(Buffer);
        Request.Outcome->TailBytes = Tail.Bytes;
        Request.Outcome->TailFailure = Tail.Failure;
        if (Tail.Bytes <= Buffer.size())
        {
            Request.Outcome->Tail.assign(
                reinterpret_cast<const char *>(Buffer.data()), Tail.Bytes);
        }
        const auto Terminal = co_await Connection->ReadSome(Buffer);
        Request.Outcome->TerminalBytes = Terminal.Bytes;
        Request.Outcome->TerminalFailure = Terminal.Failure;
        const auto StickyTerminal = co_await Connection->ReadSome(Buffer);
        Request.Outcome->StickyBytes = StickyTerminal.Bytes;
        Request.Outcome->StickyFailure = StickyTerminal.Failure;
        co_await CloseAndDrainTransport(std::static_pointer_cast<Prism::Transmission>(
            std::move(Connection)));
    }

    /** @brief 服务端接收测试 datagram 并验证双向业务与底层装饰器。 */
    auto RunServerRoundtrip(std::shared_ptr<MemoryStream> ServerTransport) -> Net::awaitable<void>
    {
        Trusttunnel::ServerConfig ServerConfig;
        ServerConfig.username = "admin";
        ServerConfig.password = "Secret";
        auto Accepted = co_await Trusttunnel::AcceptPacket(
            std::move(ServerTransport), ServerConfig);
        if (!Accepted)
        {
            EXPECT_TRUE(false) << "AcceptPacket Failed";
            co_return;
        }
        auto Target = std::move(Accepted->Target);
        auto Datagram = std::move(Accepted->Datagram);
        EXPECT_EQ(Target, "example.com");
        EXPECT_EQ(Datagram->TransportType(), Prism::Transmission::Type::Udp);
        std::string Host;
        std::uint16_t Port = 0;
        std::vector<std::uint8_t> Payload;
        const auto ReceiveResult = co_await Datagram->AsyncReceiveFrom(Host, Port, Payload);
        EXPECT_TRUE(ReceiveResult);
        EXPECT_EQ(Host, "dns.google");
        EXPECT_EQ(Port, 53u);
        EXPECT_EQ(std::string(Payload.begin(), Payload.end()), "Dgram hello");
        const auto SendResult = co_await Datagram->AsyncSendTo(Host, Port, Payload);
        EXPECT_TRUE(SendResult);

        std::array<std::byte, 8> RawBuffer{};
        const auto RawWriteBuffer = std::span<const std::byte>(RawBuffer.data(), 4);
        const auto Written = co_await Datagram->WriteSome(RawWriteBuffer);
        EXPECT_FALSE(Written.Failure.Failed());
        EXPECT_EQ(Written.Bytes, 4u);
        const auto ReadResult = co_await Datagram->ReadSome(RawBuffer);
        EXPECT_FALSE(ReadResult.Failure.Failed());
        EXPECT_GT(ReadResult.Bytes, 0u);
        EXPECT_TRUE(Datagram->Stream());
        EXPECT_NE(Datagram->NextLayer(), nullptr);
        const Trusttunnel::Dgram *ConstDatagram = Datagram.get();
        EXPECT_NE(ConstDatagram->NextLayer(), nullptr);
        auto InnerStream = Datagram->Stream();
        const auto *ConstConnection = dynamic_cast<const Trusttunnel::Detail::Conn<> *>(InnerStream.get());
        EXPECT_NE(ConstConnection, nullptr);
        if (ConstConnection) EXPECT_NE(ConstConnection->NextLayer(), nullptr);
        co_await CloseAndDrainTransport(Datagram);
    }

    /** @brief 驱动客户端和服务端的数据报往返场景。 */
    auto RunSendReceiveRoundtrip(
        Net::any_io_executor Executor,
        MemoryStream ClientMemory,
        MemoryStream ServerMemory) -> Net::awaitable<void>
    {
        auto ServerDone = std::make_shared<CompletionChannel>(Executor, 1);
        auto ServerTransport = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto ServerCompletion = [ServerDone](std::exception_ptr)
        {
            (void)ServerDone->try_send(boost::system::error_code{});
        };
        Net::co_spawn(Executor, RunServerRoundtrip(ServerTransport),
                      std::move(ServerCompletion));

        Trusttunnel::ClientConfig ClientConfig;
        ClientConfig.username = "admin";
        ClientConfig.password = "Secret";
        auto ClientTransport = std::make_shared<MemoryStream>(std::move(ClientMemory));
        Trusttunnel::ConnectParameters ConnectParams{
            std::move(ClientTransport), ClientConfig, "example.com", 443};
        auto Connected = co_await Trusttunnel::ConnectPacket(std::move(ConnectParams));
        EXPECT_TRUE(Connected);
        if (!Connected)
        {
            ADD_FAILURE() << "ConnectPacket failed code="
                          << static_cast<unsigned>(Connected.error().Code)
                          << " native=" << Connected.error().Native.category().name()
                          << ':' << Connected.error().Native.value();
            EXPECT_TRUE(ServerTransport->Close());
            co_await ServerDone->async_receive(Net::use_awaitable);
            co_return;
        }
        auto Datagram = std::move(*Connected);
        EXPECT_TRUE(Datagram->Executor());
        const std::string Message = "Dgram hello";
        const auto MessageBytes = AsU8Span(Message);
        const auto SendResult = co_await Datagram->AsyncSendTo("dns.google", 53, MessageBytes);
        EXPECT_TRUE(SendResult);
        std::string Host;
        std::uint16_t Port = 0;
        std::vector<std::uint8_t> Response;
        const auto ReceiveResult = co_await Datagram->AsyncReceiveFrom(Host, Port, Response);
        EXPECT_TRUE(ReceiveResult);
        EXPECT_EQ(Host, "dns.google");
        EXPECT_EQ(Port, 53u);
        EXPECT_EQ(std::string(Response.begin(), Response.end()), "Dgram hello");

        const std::array<std::byte, 8> RawBuffer{};
        const auto RawWriteBuffer = std::span<const std::byte>(RawBuffer.data(), 4);
        const auto Written = co_await Datagram->WriteSome(RawWriteBuffer);
        EXPECT_FALSE(Written.Failure.Failed());
        EXPECT_EQ(Written.Bytes, 4u);
        auto Released = Datagram->Release();
        EXPECT_TRUE(Released);
        EXPECT_EQ(Datagram->NextLayer(), nullptr);
        const auto Closed = Datagram->Close();
        const auto Canceled = Datagram->Cancel();
        EXPECT_TRUE(Closed);
        EXPECT_TRUE(Canceled);
        co_await CloseAndDrainTransport(Released);
        co_await CloseAndDrainTransport(Datagram);
        co_await ServerDone->async_receive(Net::use_awaitable);
    }

    /** @brief 服务端验证错误密码并保留认证失败断言。 */
    auto RunBadAuthServer(std::shared_ptr<MemoryStream> ServerTransport) -> Net::awaitable<void>
    {
        Trusttunnel::ServerConfig ServerConfig;
        ServerConfig.username = "admin";
        ServerConfig.password = "Secret";
        auto Accepted = co_await Trusttunnel::AcceptPacket(
            std::move(ServerTransport), ServerConfig);
        EXPECT_FALSE(Accepted);
        if (!Accepted) EXPECT_EQ(Accepted.error().Code, Prism::Fault::Code::AuthFailed);
    }

    /** @brief 驱动错误密码的客户端及服务端认证拒绝场景。 */
    auto RunBadAuthRejected(
        Net::any_io_executor Executor,
        MemoryStream ClientMemory,
        MemoryStream ServerMemory) -> Net::awaitable<void>
    {
        auto ServerDone = std::make_shared<CompletionChannel>(Executor, 1);
        auto ServerTransport = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto ServerCompletion = [ServerDone](std::exception_ptr)
        {
            (void)ServerDone->try_send(boost::system::error_code{});
        };
        Net::co_spawn(Executor, RunBadAuthServer(std::move(ServerTransport)),
                      std::move(ServerCompletion));

        Trusttunnel::ClientConfig ClientConfig;
        ClientConfig.username = "admin";
        ClientConfig.password = "wrong";
        auto ClientTransport = std::make_shared<MemoryStream>(std::move(ClientMemory));
        Trusttunnel::ConnectParameters ConnectParams{
            std::move(ClientTransport), ClientConfig, "example.com", 443};
        auto Connected = co_await Trusttunnel::ConnectPacket(std::move(ConnectParams));
        EXPECT_TRUE(Connected);
        if (Connected)
            co_await CloseAndDrainTransport(*Connected);
        co_await ServerDone->async_receive(Net::use_awaitable);
    }

    /** @brief 向已关闭的内存对端发送数据报并验证 typed I/O 错误。 */
    auto RunSendToClosedPeer(MemoryStream ClientMemory, MemoryStream ServerMemory)
        -> Net::awaitable<void>
    {
        auto Peer = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto Created = Trusttunnel::Dgram::Create(Trusttunnel::DgramRequest{
            std::make_shared<MemoryStream>(std::move(ClientMemory))});
        EXPECT_TRUE(Created);
        if (!Created) co_return;
        auto Datagram = std::move(*Created);
        const auto PeerActivity = Peer->Activity();
        const auto PeerClosed = Peer->Close();
        EXPECT_TRUE(PeerClosed);
        const auto PeerDrained = co_await PeerActivity->Drain();
        EXPECT_TRUE(PeerDrained);
        const std::string Message = "x";
        const auto MessageBytes = AsU8Span(Message);
        const auto SendResult = co_await Datagram->AsyncSendTo(
            "example.com", 80, MessageBytes);
        EXPECT_FALSE(SendResult);
        if (!SendResult)
            EXPECT_EQ(SendResult.error().Code, Prism::Fault::Code::ConnectionAborted);
        co_await CloseAndDrainTransport(Datagram);
    }

    /** @brief 对端关闭后接收并验证 EOF 类型。 */
    auto RunPeerClosedEof(MemoryStream ClientMemory, MemoryStream ServerMemory)
        -> Net::awaitable<void>
    {
        auto Peer = std::make_shared<MemoryStream>(std::move(ClientMemory));
        auto Created = Trusttunnel::Dgram::Create(Trusttunnel::DgramRequest{
            std::make_shared<MemoryStream>(std::move(ServerMemory))});
        EXPECT_TRUE(Created);
        if (!Created) co_return;
        auto Datagram = std::move(*Created);
        const auto PeerActivity = Peer->Activity();
        const auto PeerClosed = Peer->Close();
        EXPECT_TRUE(PeerClosed);
        const auto PeerDrained = co_await PeerActivity->Drain();
        EXPECT_TRUE(PeerDrained);
        std::string Host;
        std::uint16_t Port = 0;
        std::vector<std::uint8_t> Payload;
        const auto ReceiveResult = co_await Datagram->AsyncReceiveFrom(Host, Port, Payload);
        EXPECT_FALSE(ReceiveResult);
        if (!ReceiveResult) EXPECT_EQ(ReceiveResult.error().Code, Prism::Fault::Code::Eof);
        co_await CloseAndDrainTransport(Datagram);
    }

    /** @brief 验证 datagram 拒绝底层过量写入。 */
    auto RunRejectsOverreportedWrite(std::shared_ptr<Trusttunnel::Dgram> Datagram)
        -> Net::awaitable<void>
    {
        const auto Payload = AsU8Span(std::string_view{"overreport"});
        const auto SendResult = co_await Datagram->AsyncSendTo("example.com", 443, Payload);
        EXPECT_FALSE(SendResult);
        if (!SendResult)
            EXPECT_EQ(SendResult.error().Code, Prism::Fault::Code::InvalidArgument);
        co_await CloseAndDrainTransport(Datagram);
    }

    /** @brief 验证 datagram 拒绝底层过量读取。 */
    auto RunRejectsOverreportedRead(std::shared_ptr<Trusttunnel::Dgram> Datagram)
        -> Net::awaitable<void>
    {
        std::string Host;
        std::uint16_t Port = 0;
        std::vector<std::uint8_t> Payload;
        const auto ReceiveResult = co_await Datagram->AsyncReceiveFrom(Host, Port, Payload);
        EXPECT_FALSE(ReceiveResult);
        if (!ReceiveResult)
            EXPECT_EQ(ReceiveResult.error().Code, Prism::Fault::Code::InvalidArgument);
        co_await CloseAndDrainTransport(Datagram);
    }

    TEST(TrusttunnelDgramSession, SendReceiveRoundtrip)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, RunSendReceiveRoundtrip(
            IoContext.get_executor(), std::move(ClientMemory), std::move(ServerMemory)));
    }

    TEST(TrusttunnelDgramSession, BadAuthRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, RunBadAuthRejected(
            IoContext.get_executor(), std::move(ClientMemory), std::move(ServerMemory)));
    }

    TEST(TrusttunnelDgramSession, SendToClosedPeer)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, RunSendToClosedPeer(std::move(ClientMemory), std::move(ServerMemory)));
    }

    TEST(TrusttunnelDgramSession, PeerClosedEof)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, RunPeerClosedEof(std::move(ClientMemory), std::move(ServerMemory)));
    }

    TEST(TrusttunnelDgramSession, ReadHandshakeDeliversTailBeforeSameReadEof)
    {
        Net::io_context IoContext;
        auto RawTransport = std::make_shared<TerminalHandshakeTransmission>(
            IoContext.get_executor(), MakeTerminalHandshakeWire(),
            Prism::Fault::Failure{Prism::Fault::Code::Eof});
        TrusttunnelTerminalHandshakeOutcome Outcome;

        RunCoro(IoContext, RunTrusttunnelTerminalHandshake({RawTransport, &Outcome}));

        EXPECT_TRUE(Outcome.HandshakeFailure.Succeeded());
        EXPECT_EQ(Outcome.Target, "example.com");
        EXPECT_EQ(Outcome.Tail, "tunnel-tail");
        EXPECT_EQ(Outcome.TailBytes, std::string_view{"tunnel-tail"}.size());
        EXPECT_TRUE(Outcome.TailFailure.Succeeded());
        EXPECT_EQ(Outcome.TerminalBytes, 0U);
        EXPECT_EQ(Outcome.TerminalFailure.Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(Outcome.StickyBytes, 0U);
        EXPECT_EQ(Outcome.StickyFailure.Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(RawTransport->ReadCount(), 1U);
    }

    TEST(TrusttunnelDgramSession, ReadHandshakeDeliversTailBeforeSameReadNativeFailure)
    {
        Net::io_context IoContext;
        const auto Native = std::make_error_code(std::errc::connection_reset);
        auto RawTransport = std::make_shared<TerminalHandshakeTransmission>(
            IoContext.get_executor(), MakeTerminalHandshakeWire(),
            Prism::Fault::Failure{Prism::Fault::Code::IoError, Native});
        TrusttunnelTerminalHandshakeOutcome Outcome;

        RunCoro(IoContext, RunTrusttunnelTerminalHandshake({RawTransport, &Outcome}));

        EXPECT_TRUE(Outcome.HandshakeFailure.Succeeded());
        EXPECT_EQ(Outcome.Target, "example.com");
        EXPECT_EQ(Outcome.Tail, "tunnel-tail");
        EXPECT_EQ(Outcome.TailBytes, std::string_view{"tunnel-tail"}.size());
        EXPECT_TRUE(Outcome.TailFailure.Succeeded());
        EXPECT_EQ(Outcome.TerminalBytes, 0U);
        EXPECT_EQ(Outcome.TerminalFailure.Code, Prism::Fault::Code::IoError);
        EXPECT_EQ(Outcome.TerminalFailure.Native, Native);
        EXPECT_EQ(Outcome.StickyBytes, 0U);
        EXPECT_EQ(Outcome.StickyFailure.Code, Prism::Fault::Code::IoError);
        EXPECT_EQ(Outcome.StickyFailure.Native, Native);
        EXPECT_EQ(RawTransport->ReadCount(), 1U);
    }

    TEST(TrusttunnelDgramSession, RejectsOverreportedWrite)
    {
        Net::io_context IoContext;
        auto RawTransport = std::make_shared<PrismMockTransport>(IoContext.get_executor());
        RawTransport->OverreportWrite = true;
        auto Created = Trusttunnel::Dgram::Create(
            Trusttunnel::DgramRequest{RawTransport});
        ASSERT_TRUE(Created);
        auto Datagram = std::move(*Created);
        RunCoro(IoContext, RunRejectsOverreportedWrite(std::move(Datagram)));
    }

    TEST(TrusttunnelDgramSession, RejectsOverreportedRead)
    {
        Net::io_context IoContext;
        auto RawTransport = std::make_shared<PrismMockTransport>(IoContext.get_executor());
        RawTransport->OverreportRead = true;
        auto Created = Trusttunnel::Dgram::Create(
            Trusttunnel::DgramRequest{RawTransport});
        ASSERT_TRUE(Created);
        auto Datagram = std::move(*Created);
        RunCoro(IoContext, RunRejectsOverreportedRead(std::move(Datagram)));
    }

} // namespace
