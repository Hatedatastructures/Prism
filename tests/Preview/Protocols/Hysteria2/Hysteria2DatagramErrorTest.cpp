/**
 * @file Hysteria2DatagramErrorTest.cpp
 * @brief Hysteria2 datagram 错误、截断和关闭状态测试。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Hysteria2/Hysteria2.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Hysteria2 = Preview::Hysteria2;
    using Preview::AsU8Span;
    using Preview::Error;
    using Preview::PreviewMockTransport;

    /** @brief 运行顶层协程并保留异常。 */
    template <typename Awaitable>
    auto RunCoroutine(Net::io_context &IoContext, Awaitable Operation) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(
            IoContext,
            std::move(Operation),
            [&Failure, &IoContext](std::exception_ptr ErrorValue)
            {
                Failure = ErrorValue;
                IoContext.stop();
            });
        IoContext.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    /** @brief 构造 Hysteria2 datagram mock。 */
    auto MakeMock(Net::any_io_executor Executor)
        -> std::shared_ptr<PreviewMockTransport>
    {
        auto Mock = std::make_shared<PreviewMockTransport>(Executor);
        Mock->EofOnDrain = true;
        Mock->TransportKind = Preview::Transmission::Type::Udp;
        return Mock;
    }

    /** @brief 构造固定 IPv4 目标。 */
    auto MakeHysteria2Address() -> Hysteria2::Address
    {
        Hysteria2::Address Address{};
        Address.Type = Hysteria2::AddressType::Ipv4;
        Address.Host = "1.2.3.4";
        Address.Port = 80;
        return Address;
    }

    /** @brief 构造 Hysteria2 datagram 头。 */
    auto MakeHysteria2Head(const std::uint8_t Atyp)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Head{0x02, 0, 0, 0, 0, 0, 0, 0, 0};
        Head.push_back(Atyp);
        return Head;
    }

    struct DgramErrorRequest final
    {
        Net::io_context &IoContext;
        std::vector<std::uint8_t> Wire;
        Error Expected;
        bool FailRead{false};
        bool FailWrite{false};
        bool Send{false};
        bool ExpectEmpty{false};
    };

    /** @brief 执行一次 datagram wire 错误场景并验证真实结果。 */
    auto RunDgramError(DgramErrorRequest Request) -> Net::awaitable<void>
    {
        auto Raw = MakeMock(Request.IoContext.get_executor());
        Raw->ToRead = std::move(Request.Wire);
        Raw->FailNextRead = Request.FailRead;
        Raw->FailNextWrite = Request.FailWrite;
        auto Datagram = std::make_shared<Hysteria2::Dgram<>>(Raw);
        if (Request.Send)
        {
            const std::string Payload = "x";
            const auto ErrorValue = co_await Datagram->AsyncSendTo(
                MakeHysteria2Address(), AsU8Span(Payload));
            EXPECT_EQ(ErrorValue, Request.Expected);
            co_return;
        }

        Hysteria2::Address Source;
        std::vector<std::uint8_t> Payload;
        const auto ErrorValue =
            co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(ErrorValue, Request.Expected);
        if (Request.ExpectEmpty)
        {
            EXPECT_TRUE(Payload.empty());
        }
    }

    /** @brief 验证关闭后的发送与接收错误。 */
    auto RunClosedStateOperations(Net::io_context &IoContext)
        -> Net::awaitable<void>
    {
        auto Datagram = std::make_shared<Hysteria2::Dgram<>>(
            MakeMock(IoContext.get_executor()));
        Datagram->Close();
        const std::string Payload = "x";
        const auto SendError = co_await Datagram->AsyncSendTo(
            MakeHysteria2Address(), AsU8Span(Payload));
        EXPECT_EQ(SendError, Error::IoError);
        Hysteria2::Address Source;
        std::vector<std::uint8_t> Received;
        const auto ReceiveError =
            co_await Datagram->AsyncReceiveFrom(Source, Received);
        EXPECT_EQ(ReceiveError, Error::UnexpectedEof);
    }

    TEST(Hysteria2DgramErr, SendWriteFail)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramError(DgramErrorRequest{
            IoContext, {}, Error::IoError, false, true, true, false}));
    }

    TEST(Hysteria2DgramErr, ReceiveHeadEof)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramError(DgramErrorRequest{
            IoContext, {}, Error::UnexpectedEof}));
    }

    TEST(Hysteria2DgramErr, ReceiveShortHead)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramError(DgramErrorRequest{
            IoContext, {0x02, 0, 0, 0, 0}, Error::NeedMore}));
    }

    TEST(Hysteria2DgramErr, ReceiveBadKind)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramError(DgramErrorRequest{
            IoContext, {0x01, 0, 0, 0, 0, 0, 0, 0, 0x01},
            Error::BadMessage}));
    }

    TEST(Hysteria2DgramErr, ReceiveBadAtyp)
    {
        Net::io_context IoContext;
        auto Wire = MakeHysteria2Head(0x99);
        RunCoroutine(IoContext, RunDgramError(DgramErrorRequest{
            IoContext, std::move(Wire), Error::BadMessage}));
    }

    TEST(Hysteria2DgramErr, ReceiveDomainTruncated)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramError(DgramErrorRequest{
            IoContext, {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x05, 'a', 'b'},
            Error::NeedMore}));
    }

    TEST(Hysteria2DgramErr, ReceivePortEof)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramError(DgramErrorRequest{
            IoContext, {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4},
            Error::NeedMore}));
    }

    TEST(Hysteria2DgramErr, ReceivePayloadIoError)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramError(DgramErrorRequest{
            IoContext,
            {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50},
            Error::IoError, true}));
    }

    TEST(Hysteria2DgramErr, ReceiveEmptyPayloadAccepted)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramError(DgramErrorRequest{
            IoContext,
            {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50},
            Error::None, false, false, false, true}));
    }

    TEST(Hysteria2DgramErr, ReceiveIpv6Truncated)
    {
        Net::io_context IoContext;
        auto Wire = MakeHysteria2Head(0x03);
        Wire.insert(Wire.end(), 8, 0x21);
        RunCoroutine(IoContext, RunDgramError(DgramErrorRequest{
            IoContext, std::move(Wire), Error::NeedMore}));
    }

    TEST(Hysteria2DgramErr, ClosedStateOperations)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunClosedStateOperations(IoContext));
    }
}
