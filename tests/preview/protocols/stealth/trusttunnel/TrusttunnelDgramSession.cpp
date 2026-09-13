/**
 * @file TrusttunnelDgramSession.cpp
 * @brief TrustTunnel Dgram 包连接双向测试（Client + Server 视角）
 * @details 覆盖：
 * 1. 客户端 ConnectPacket / 服务端 AcceptPacket（CONNECT 认证握手）→ 数据报往返
 * 2. 错误分支：io_error（对端关闭）/ unexpected_eof（读 EOF）
 * 3. 装饰器链方法：Executor / TransportType / NextLayer / Stream / Release / Close / Cancel
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

#include <preview/Transport/MemoryStream.hpp>
#include <preview/Protocols/Trusttunnel/Trusttunnel.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Trusttunnel = Preview::Trusttunnel;
    using Preview::AsU8Span;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::PreviewMockTransport;

    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    /// 运行协程直至完成（异常重抛）
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

    TEST(TrusttunnelDgramSession, SendReceiveRoundtrip)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());

        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                {
                    auto ServerDone = std::make_shared<CompletionChannel>(
                        IoContext.get_executor(), 1);
                    auto ServerTransport = std::make_shared<MemoryStream>(std::move(ServerMemory));
                    auto ServerCoroutine = [ServerDone,
                                            ServerTransport = std::move(ServerTransport)]() mutable
                        -> Net::awaitable<void>
                    {
                        Trusttunnel::ServerConfig ServerConfig;
                        ServerConfig.username = "admin";
                        ServerConfig.password = "Secret";
                        auto [AcceptError, Target, Datagram] = co_await Trusttunnel::AcceptPacket(
                            std::move(ServerTransport), ServerConfig);
                        if (AcceptError != Error::None || !Datagram)
                        {
                            EXPECT_TRUE(false) << "AcceptPacket Failed";
                            co_return;
                        }
                        EXPECT_EQ(Target, "example.com");
                        EXPECT_EQ(Datagram->TransportType(), Preview::Transmission::Type::Udp);
                        std::string Host;
                        std::uint16_t Port = 0;
                        std::vector<std::uint8_t> Payload;
                        const auto ReceiveError = co_await Datagram->AsyncReceiveFrom(Host, Port, Payload);
                        EXPECT_EQ(ReceiveError, Error::None);
                        EXPECT_EQ(Host, "dns.google");
                        EXPECT_EQ(Port, 53u);
                        EXPECT_EQ(std::string(Payload.begin(), Payload.end()), "Dgram hello");
                        const auto SendError = co_await Datagram->AsyncSendTo(Host, Port, Payload);
                        EXPECT_EQ(SendError, Error::None);

                        std::array<std::byte, 8> RawBuffer{};
                        std::error_code ErrorCode;
                        const auto RawWriteBuffer = std::span<const std::byte>(RawBuffer.data(), 4);
                        const auto Written = co_await Datagram->async_write_some(
                            RawWriteBuffer, ErrorCode);
                        EXPECT_EQ(Written, 4u);
                        const auto ReadSize = co_await Datagram->async_read_some(RawBuffer, ErrorCode);
                        EXPECT_GT(ReadSize, 0u);
                        EXPECT_TRUE(Datagram->Stream());
                        EXPECT_NE(Datagram->NextLayer(), nullptr);
                        const Trusttunnel::Dgram *ConstDatagram = Datagram.get();
                        EXPECT_NE(ConstDatagram->NextLayer(), nullptr);
                        auto InnerStream = Datagram->Stream();
                        const auto *ConstConnection = dynamic_cast<const Trusttunnel::Conn<> *>(
                            InnerStream.get());
                        EXPECT_NE(ConstConnection, nullptr);
                        if (ConstConnection)
                        {
                            EXPECT_NE(ConstConnection->NextLayer(), nullptr);
                        }
                        Datagram->Close();
                    };
                    auto ServerCompletion = [ServerDone](std::exception_ptr) -> void
                    {
                        (void)ServerDone->try_send(boost::system::error_code{});
                    };
                    Net::co_spawn(
                        IoContext.get_executor(), std::move(ServerCoroutine), std::move(ServerCompletion));

                    Trusttunnel::ClientConfig ClientConfig;
                    ClientConfig.username = "admin";
                    ClientConfig.password = "Secret";
                    auto ClientTransport = std::make_shared<MemoryStream>(std::move(ClientMemory));
                    Trusttunnel::ConnectParameters ConnectParams{
                        std::move(ClientTransport), ClientConfig, "example.com", 443};
                    auto [ConnectError, Datagram] = co_await Trusttunnel::ConnectPacket(
                        std::move(ConnectParams));
                    EXPECT_EQ(ConnectError, Error::None);
                    if (!Datagram)
                    {
                        co_return;
                    }
                    EXPECT_TRUE(Datagram->Executor());
                    const std::string Message = "Dgram hello";
                    const auto MessageBytes = AsU8Span(Message);
                    const auto SendError = co_await Datagram->AsyncSendTo(
                        "dns.google", 53, MessageBytes);
                    EXPECT_EQ(SendError, Error::None);
                    std::string Host;
                    std::uint16_t Port = 0;
                    std::vector<std::uint8_t> Response;
                    const auto ReceiveError = co_await Datagram->AsyncReceiveFrom(Host, Port, Response);
                    EXPECT_EQ(ReceiveError, Error::None);
                    EXPECT_EQ(Host, "dns.google");
                    EXPECT_EQ(Port, 53u);
                    EXPECT_EQ(std::string(Response.begin(), Response.end()), "Dgram hello");

                    const std::array<std::byte, 8> RawBuffer{};
                    std::error_code ErrorCode;
                    const auto RawWriteBuffer = std::span<const std::byte>(RawBuffer.data(), 4);
                    const auto Written = co_await Datagram->async_write_some(RawWriteBuffer, ErrorCode);
                    EXPECT_EQ(Written, 4u);
                    Datagram->Close();
                    Datagram->Cancel();
                    auto Released = Datagram->Release();
                    EXPECT_TRUE(Released);
                    EXPECT_EQ(Datagram->NextLayer(), nullptr);
                    co_await ServerDone->async_receive(Net::use_awaitable);
                });
    }

    TEST(TrusttunnelDgramSession, BadAuthRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());

        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                {
                    auto ServerDone = std::make_shared<CompletionChannel>(
                        IoContext.get_executor(), 1);
                    auto ServerTransport = std::make_shared<MemoryStream>(std::move(ServerMemory));
                    auto ServerCoroutine = [ServerTransport = std::move(ServerTransport)]() mutable
                        -> Net::awaitable<void>
                    {
                        Trusttunnel::ServerConfig ServerConfig;
                        ServerConfig.username = "admin";
                        ServerConfig.password = "Secret";
                        auto [AcceptError, Target, Datagram] = co_await Trusttunnel::AcceptPacket(
                            std::move(ServerTransport), ServerConfig);
                        EXPECT_EQ(AcceptError, Error::BadAuth);
                        EXPECT_FALSE(Datagram);
                        (void)Target;
                    };
                    auto ServerCompletion = [ServerDone](std::exception_ptr) -> void
                    {
                        (void)ServerDone->try_send(boost::system::error_code{});
                    };
                    Net::co_spawn(
                        IoContext.get_executor(), std::move(ServerCoroutine), std::move(ServerCompletion));

                    Trusttunnel::ClientConfig ClientConfig;
                    ClientConfig.username = "admin";
                    ClientConfig.password = "wrong";
                    auto ClientTransport = std::make_shared<MemoryStream>(std::move(ClientMemory));
                    Trusttunnel::ConnectParameters ConnectParams{
                        std::move(ClientTransport), ClientConfig, "example.com", 443};
                    auto [ConnectError, Datagram] = co_await Trusttunnel::ConnectPacket(
                        std::move(ConnectParams));
                    EXPECT_EQ(ConnectError, Error::None);
                    if (Datagram)
                    {
                        Datagram->Close();
                    }
                    co_await ServerDone->async_receive(Net::use_awaitable);
                });
    }

    TEST(TrusttunnelDgramSession, SendToClosedPeer)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());

        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                {
                    auto Datagram = std::make_shared<Trusttunnel::Dgram>(
                        std::make_shared<MemoryStream>(std::move(ClientMemory)));
                    ServerMemory.Close();
                    const std::string Message = "x";
                    const auto MessageBytes = AsU8Span(Message);
                    const auto SendError = co_await Datagram->AsyncSendTo(
                        "example.com", 80, MessageBytes);
                    EXPECT_EQ(SendError, Error::IoError);
                    Datagram->Close();
                });
    }

    TEST(TrusttunnelDgramSession, PeerClosedEof)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());

        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                {
                    auto Datagram = std::make_shared<Trusttunnel::Dgram>(
                        std::make_shared<MemoryStream>(std::move(ServerMemory)));
                    ClientMemory.Close();
                    std::string Host;
                    std::uint16_t Port = 0;
                    std::vector<std::uint8_t> Payload;
                    const auto ReceiveError = co_await Datagram->AsyncReceiveFrom(Host, Port, Payload);
                    EXPECT_EQ(ReceiveError, Error::UnexpectedEof);
                    Datagram->Close();
                });
    }

    TEST(TrusttunnelDgramSession, RejectsOverreportedWrite)
    {
        Net::io_context IoContext;
        auto RawTransport = std::make_shared<PreviewMockTransport>(IoContext.get_executor());
        RawTransport->OverreportWrite = true;
        auto Datagram = std::make_shared<Trusttunnel::Dgram>(RawTransport);

        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                {
                    const auto Payload = AsU8Span(std::string_view{"overreport"});
                    const auto SendError = co_await Datagram->AsyncSendTo(
                        "example.com", 443, Payload);
                    EXPECT_EQ(SendError, Error::BadLength);
                });
    }

    TEST(TrusttunnelDgramSession, RejectsOverreportedRead)
    {
        Net::io_context IoContext;
        auto RawTransport = std::make_shared<PreviewMockTransport>(IoContext.get_executor());
        RawTransport->OverreportRead = true;
        auto Datagram = std::make_shared<Trusttunnel::Dgram>(RawTransport);

        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                {
                    std::string Host;
                    std::uint16_t Port = 0;
                    std::vector<std::uint8_t> Payload;
                    const auto ReceiveError = co_await Datagram->AsyncReceiveFrom(
                        Host, Port, Payload);
                    EXPECT_EQ(ReceiveError, Error::BadLength);
                });
    }

} // namespace
