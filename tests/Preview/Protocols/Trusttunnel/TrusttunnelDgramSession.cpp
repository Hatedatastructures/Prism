/**
 * @file TrusttunnelDgramSession.cpp
 * @brief TrustTunnel Dgram 包连接双向测试（Client + Server 视角）
 * @details 覆盖 ConnectPacket / AcceptPacket、数据报往返、错误分支与装饰器链行为。
 * @note 使用 MakeMemoryPair 建立内存传输对，同一进程内双向互操作。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Protocols/Trusttunnel/Trusttunnel.hpp>
#include <Preview/Protocols/Trusttunnel/Detail/Conn.hpp>
#include <Preview/Protocols/Trusttunnel/Detail/Dgram.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Trusttunnel = Preview::Trusttunnel;
    using Preview::AsU8Span;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::PreviewMockTransport;

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

    [[nodiscard]] auto CloseAndDrainTransport(Preview::SharedTransmission Transport)
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
        EXPECT_TRUE(Drained);
        EXPECT_TRUE(Activity->IsRetired());
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
        EXPECT_EQ(Datagram->TransportType(), Preview::Transmission::Type::Udp);
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
        std::error_code ErrorCode;
        const auto RawWriteBuffer = std::span<const std::byte>(RawBuffer.data(), 4);
        const auto Written = co_await Datagram->async_write_some(RawWriteBuffer, ErrorCode);
        EXPECT_EQ(Written, 4u);
        const auto ReadSize = co_await Datagram->async_read_some(RawBuffer, ErrorCode);
        EXPECT_GT(ReadSize, 0u);
        EXPECT_TRUE(Datagram->Stream());
        EXPECT_NE(Datagram->NextLayer(), nullptr);
        const Trusttunnel::Detail::Dgram *ConstDatagram = Datagram.get();
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
        Net::co_spawn(Executor, RunServerRoundtrip(std::move(ServerTransport)),
                      std::move(ServerCompletion));

        Trusttunnel::ClientConfig ClientConfig;
        ClientConfig.username = "admin";
        ClientConfig.password = "Secret";
        auto ClientTransport = std::make_shared<MemoryStream>(std::move(ClientMemory));
        Trusttunnel::ConnectParameters ConnectParams{
            std::move(ClientTransport), ClientConfig, "example.com", 443};
        auto Connected = co_await Trusttunnel::ConnectPacket(std::move(ConnectParams));
        EXPECT_TRUE(Connected);
        if (!Connected) co_return;
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
        std::error_code ErrorCode;
        const auto RawWriteBuffer = std::span<const std::byte>(RawBuffer.data(), 4);
        const auto Written = co_await Datagram->async_write_some(RawWriteBuffer, ErrorCode);
        EXPECT_EQ(Written, 4u);
        const auto Closed = Datagram->Close();
        const auto Canceled = Datagram->Cancel();
        EXPECT_TRUE(Closed);
        EXPECT_TRUE(Canceled);
        auto Released = Datagram->Release();
        EXPECT_TRUE(Released);
        EXPECT_EQ(Datagram->NextLayer(), nullptr);
        co_await CloseAndDrainTransport(Datagram);
        co_await CloseAndDrainTransport(Released);
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
        if (!Accepted) EXPECT_EQ(Accepted.error().Code, Preview::Fault::Code::AuthFailed);
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
        auto Datagram = std::make_shared<Trusttunnel::Detail::Dgram>(
            std::make_shared<MemoryStream>(std::move(ClientMemory)));
        const auto PeerClosed = ServerMemory.Close();
        EXPECT_TRUE(PeerClosed);
        const std::string Message = "x";
        const auto MessageBytes = AsU8Span(Message);
        const auto SendResult = co_await Datagram->AsyncSendTo(
            "example.com", 80, MessageBytes);
        EXPECT_FALSE(SendResult);
        if (!SendResult) EXPECT_EQ(SendResult.error().Code, Preview::Fault::Code::IoError);
        co_await CloseAndDrainTransport(Datagram);
    }

    /** @brief 对端关闭后接收并验证 EOF 类型。 */
    auto RunPeerClosedEof(MemoryStream ClientMemory, MemoryStream ServerMemory)
        -> Net::awaitable<void>
    {
        auto Datagram = std::make_shared<Trusttunnel::Detail::Dgram>(
            std::make_shared<MemoryStream>(std::move(ServerMemory)));
        const auto PeerClosed = ClientMemory.Close();
        EXPECT_TRUE(PeerClosed);
        std::string Host;
        std::uint16_t Port = 0;
        std::vector<std::uint8_t> Payload;
        const auto ReceiveResult = co_await Datagram->AsyncReceiveFrom(Host, Port, Payload);
        EXPECT_FALSE(ReceiveResult);
        if (!ReceiveResult) EXPECT_EQ(ReceiveResult.error().Code, Preview::Fault::Code::Eof);
        co_await CloseAndDrainTransport(Datagram);
    }

    /** @brief 验证 datagram 拒绝底层过量写入。 */
    auto RunRejectsOverreportedWrite(std::shared_ptr<Trusttunnel::Detail::Dgram> Datagram)
        -> Net::awaitable<void>
    {
        const auto Payload = AsU8Span(std::string_view{"overreport"});
        const auto SendResult = co_await Datagram->AsyncSendTo("example.com", 443, Payload);
        EXPECT_FALSE(SendResult);
        if (!SendResult) EXPECT_EQ(SendResult.error().Code, Preview::Fault::Code::BadMessage);
        co_await CloseAndDrainTransport(Datagram);
    }

    /** @brief 验证 datagram 拒绝底层过量读取。 */
    auto RunRejectsOverreportedRead(std::shared_ptr<Trusttunnel::Detail::Dgram> Datagram)
        -> Net::awaitable<void>
    {
        std::string Host;
        std::uint16_t Port = 0;
        std::vector<std::uint8_t> Payload;
        const auto ReceiveResult = co_await Datagram->AsyncReceiveFrom(Host, Port, Payload);
        EXPECT_FALSE(ReceiveResult);
        if (!ReceiveResult) EXPECT_EQ(ReceiveResult.error().Code, Preview::Fault::Code::BadMessage);
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

    TEST(TrusttunnelDgramSession, RejectsOverreportedWrite)
    {
        Net::io_context IoContext;
        auto RawTransport = std::make_shared<PreviewMockTransport>(IoContext.get_executor());
        RawTransport->OverreportWrite = true;
        auto Datagram = std::make_shared<Trusttunnel::Detail::Dgram>(RawTransport);
        RunCoro(IoContext, RunRejectsOverreportedWrite(std::move(Datagram)));
    }

    TEST(TrusttunnelDgramSession, RejectsOverreportedRead)
    {
        Net::io_context IoContext;
        auto RawTransport = std::make_shared<PreviewMockTransport>(IoContext.get_executor());
        RawTransport->OverreportRead = true;
        auto Datagram = std::make_shared<Trusttunnel::Detail::Dgram>(RawTransport);
        RunCoro(IoContext, RunRejectsOverreportedRead(std::move(Datagram)));
    }

} // namespace