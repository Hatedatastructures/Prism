/**
 * @file VlessDatagramErrorTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Contract/Services/Datagram.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include <Preview/Protocols/Vless/Vless.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Vless = Preview::Vless;
    namespace Fault = Preview::Fault;
    using Preview::AsBytes;
    using Preview::AsU8Span;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::PreviewMockTransport;
    using Preview::Transmission;

    /// 运行协程直至完成（异常重抛）
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
    /// dgram 错误矩阵使用有限注入流，耗尽后按旧桩契约显式返回 EOF。
    auto MakeMock(Net::any_io_executor Executor) -> std::shared_ptr<PreviewMockTransport>
    {
        auto Mock = std::make_shared<PreviewMockTransport>(Executor);
        Mock->EofOnDrain = true;
        Mock->TransportKind = Preview::Transmission::Type::Udp;
        return Mock;
    }

    auto RunSendWriteFail(Net::io_context& Io) -> Net::awaitable<void>
    {
        auto Raw = MakeMock(Io.get_executor());
        Raw->FailNextWrite = true;
        auto Datagram = std::make_shared<Vless::Dgram<>>(Raw);
        const std::string Payload = "x";
        const auto Result = co_await Datagram->AsyncSendDatagram(AsU8Span(Payload));
        EXPECT_TRUE(Result.Failure.Failed());
        EXPECT_EQ(Result.Failure.Code, Fault::Code::IoError);
        EXPECT_EQ(Result.WireBytes, 0U);
    }

    auto RunReceiveHeadEof(Net::io_context& Io) -> Net::awaitable<void>
    {
        auto Raw = MakeMock(Io.get_executor());
        auto Datagram = std::make_shared<Vless::Dgram<>>(Raw);
        std::vector<std::uint8_t> Payload;
        const auto Result = co_await Datagram->AsyncReceiveDatagram(Payload);
        EXPECT_TRUE(Result.Failure.Failed());
        EXPECT_EQ(Result.Failure.Code, Fault::Code::Eof);
        EXPECT_EQ(Result.WireBytes, 0U);
    }

    auto RunReceiveTruncatedLengthPrefix(Net::io_context& Io) -> Net::awaitable<void>
    {
        auto Raw = MakeMock(Io.get_executor());
        Raw->ToRead = {0x00};
        auto Datagram = std::make_shared<Vless::Dgram<>>(Raw);
        std::vector<std::uint8_t> Payload;
        const auto Result = co_await Datagram->AsyncReceiveDatagram(Payload);
        EXPECT_TRUE(Result.Failure.Failed());
        EXPECT_EQ(Result.Failure.Code, Fault::Code::BadMessage);
        EXPECT_EQ(Result.WireBytes, 1U);
    }

    auto RunReceiveTruncatedPayload(Net::io_context& Io) -> Net::awaitable<void>
    {
        auto Raw = MakeMock(Io.get_executor());
        Raw->ToRead = {0x00, 0x02, 'a'};
        auto Datagram = std::make_shared<Vless::Dgram<>>(Raw);
        std::vector<std::uint8_t> Payload;
        const auto Result = co_await Datagram->AsyncReceiveDatagram(Payload);
        EXPECT_TRUE(Result.Failure.Failed());
        EXPECT_EQ(Result.Failure.Code, Fault::Code::BadMessage);
        EXPECT_EQ(Result.WireBytes, 3U);
    }

    auto RunReceiveLengthWithoutPayload(Net::io_context& Io) -> Net::awaitable<void>
    {
        auto Raw = MakeMock(Io.get_executor());
        Raw->ToRead = {0x00, 0x01};
        auto Datagram = std::make_shared<Vless::Dgram<>>(Raw);
        std::vector<std::uint8_t> Payload;
        const auto Result = co_await Datagram->AsyncReceiveDatagram(Payload);
        EXPECT_TRUE(Result.Failure.Failed());
        EXPECT_EQ(Result.Failure.Code, Fault::Code::BadMessage);
        EXPECT_EQ(Result.WireBytes, 2U);
    }

    auto RunReceivePayloadIoError(Net::io_context& Io) -> Net::awaitable<void>
    {
        auto Raw = MakeMock(Io.get_executor());
        Raw->ToRead = {0x00, 0x01};
        Raw->ReadFailAt = 1;
        auto Datagram = std::make_shared<Vless::Dgram<>>(Raw);
        std::vector<std::uint8_t> Payload;
        const auto Result = co_await Datagram->AsyncReceiveDatagram(Payload);
        EXPECT_TRUE(Result.Failure.Failed());
        EXPECT_EQ(Result.Failure.Code, Fault::Code::IoError);
        EXPECT_EQ(Result.WireBytes, 2U);
    }

    auto RunReceivePayloadEof(Net::io_context& Io) -> Net::awaitable<void>
    {
        auto Raw = MakeMock(Io.get_executor());
        Raw->ToRead = {0x00, 0x01};
        auto Datagram = std::make_shared<Vless::Dgram<>>(Raw);
        std::vector<std::uint8_t> Payload;
        const auto Result = co_await Datagram->AsyncReceiveDatagram(Payload);
        EXPECT_TRUE(Result.Failure.Failed());
        EXPECT_EQ(Result.Failure.Code, Fault::Code::BadMessage);
        EXPECT_EQ(Result.WireBytes, 2U);
    }

    auto RunReceivePartialHeaderNative(Net::io_context& Io) -> Net::awaitable<void>
    {
        auto Raw = MakeMock(Io.get_executor());
        Raw->ToRead = {0x00, 0x04, 0x21, 0x22};
        const auto Native = std::make_error_code(std::errc::connection_reset);
        Raw->SetReadError(Native);
        Raw->ReadErrorBytes = 1;
        auto Datagram = std::make_shared<Vless::Dgram<>>(Raw);
        std::vector<std::uint8_t> Payload;
        const auto Result = co_await Datagram->AsyncReceiveDatagram(Payload);
        EXPECT_TRUE(Result.Failure.Failed());
        EXPECT_EQ(Result.Failure.Code, Fault::Code::ConnectionReset);
        EXPECT_EQ(Result.Failure.Native, Native);
        EXPECT_EQ(Result.WireBytes, 3U);
    }

    struct UdpTunnelResolverFailureRequest final
    {
        std::shared_ptr<Vless::UdpTunnel> Tunnel;
        MemoryStream PeerMemory;
        std::error_code Native;
    };

    auto RunUdpTunnelResolverFailure(UdpTunnelResolverFailureRequest Request)
        -> Net::awaitable<void>
    {
        const auto RunResult = co_await Request.Tunnel->Run();
        EXPECT_FALSE(RunResult);
        if (!RunResult) EXPECT_EQ(RunResult.error().Code, Fault::Code::ConnectionReset);
        const auto Drained = co_await Request.Tunnel->Drain();
        EXPECT_FALSE(Drained);
        if (!Drained)
        {
            EXPECT_EQ(Drained.error().Code, Fault::Code::ConnectionReset);
            EXPECT_EQ(Drained.error().Native, Request.Native);
        }
        (void)Request.PeerMemory.Close();
    }

    /** @brief 验证关闭后的 VLESS 数据报发送与接收均返回状态错误。 */
    auto RunClosedStateOperations(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto Raw = MakeMock(IoContext.get_executor());
        auto Datagram = std::make_shared<Vless::Dgram<>>(Raw);
        Datagram->Close();
        const std::string Payload = "x";
        const auto Send = co_await Datagram->AsyncSendDatagram(AsU8Span(Payload));
        EXPECT_TRUE(Send.Failure.Failed());
        std::vector<std::uint8_t> Output;
        const auto Receive = co_await Datagram->AsyncReceiveDatagram(Output);
        EXPECT_TRUE(Receive.Failure.Failed());
    }
} // namespace

TEST(VlessDgramErr, SendWriteFail)
    {
        Net::io_context ioc;
        RunCoroutine(ioc, RunSendWriteFail(ioc));
    }

TEST(VlessDgramErr, ReceiveHeadEof)
    {
        Net::io_context ioc;

        RunCoroutine(ioc, RunReceiveHeadEof(ioc));
    }

TEST(VlessDgramErr, ReceiveTruncatedLengthPrefix)
    {
        Net::io_context ioc;

        RunCoroutine(ioc, RunReceiveTruncatedLengthPrefix(ioc));
    }

TEST(VlessDgramErr, ReceiveTruncatedPayload)
    {
        Net::io_context ioc;

        RunCoroutine(ioc, RunReceiveTruncatedPayload(ioc));
    }

TEST(VlessDgramErr, ReceiveLengthWithoutPayload)
    {
        Net::io_context ioc;

        RunCoroutine(ioc, RunReceiveLengthWithoutPayload(ioc));
    }

TEST(VlessDgramErr, ReceivePayloadIoError)
    {
        Net::io_context ioc;

        RunCoroutine(ioc, RunReceivePayloadIoError(ioc));
    }

TEST(VlessDgramErr, ReceivePayloadEof)
    {
        Net::io_context ioc;

        RunCoroutine(ioc, RunReceivePayloadEof(ioc));
    }

TEST(VlessDgramErr, ReceivePartialHeaderPreservesNative)
    {
        Net::io_context ioc;

        RunCoroutine(ioc, RunReceivePartialHeaderNative(ioc));
    }

TEST(VlessDgramErr, ClosedStateOperations)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunClosedStateOperations(IoContext));
    }

TEST(VlessDgramErr, UdpTunnelCleanFrameBoundaryEofDrainsSuccessfully)
{
    Net::io_context Ioc;
    auto [ClientMemory, PeerMemory] = MakeMemoryPair(Ioc.get_executor());
    auto Connection = std::make_shared<Vless::Conn<>>(
        std::make_shared<MemoryStream>(std::move(ClientMemory)),
        std::array<std::uint8_t, Vless::UuidLen>{});
    Vless::UdpTunnelOptions Options;
    Options.Target = Vless::Address{Vless::AddressType::Ipv4, "127.0.0.1", 53};
    auto Tunnel = std::make_shared<Vless::UdpTunnel>(
        std::move(Connection), std::move(Options));

    RunCoroutine(Ioc, [&]() -> Net::awaitable<void>
    {
        (void)PeerMemory.Close();
        EXPECT_TRUE((co_await Tunnel->Run()).has_value());
        const auto Drained = co_await Tunnel->Drain();
        EXPECT_TRUE(Drained);
    });
}

TEST(VlessDgramErr, UdpTunnelResolverFailurePreservesNativeThroughDrain)
{
    Net::io_context Ioc;
    auto [ClientMemory, PeerMemory] = MakeMemoryPair(Ioc.get_executor());
    auto Connection = std::make_shared<Vless::Conn<>>(
        std::make_shared<MemoryStream>(std::move(ClientMemory)),
        std::array<std::uint8_t, Vless::UuidLen>{});
    Vless::UdpTunnelOptions Options;
    Options.Target = Vless::Address{
        Vless::AddressType::Domain, "resolver.invalid", 53};
    const auto Native = std::make_error_code(std::errc::connection_reset);
    Options.Services.Resolve = [Native](Preview::Network::Target)
        -> Net::awaitable<std::expected<Net::ip::udp::endpoint, Fault::Failure>>
    {
        co_return std::unexpected(Fault::Failure{Fault::Code::ConnectionReset, Native});
    };
    auto Tunnel = std::make_shared<Vless::UdpTunnel>(
        std::move(Connection), std::move(Options));

    RunCoroutine(Ioc, RunUdpTunnelResolverFailure(
        UdpTunnelResolverFailureRequest{Tunnel, std::move(PeerMemory), Native}));
}

