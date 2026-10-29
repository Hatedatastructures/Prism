/**
 * @file ErrorTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Prism/MockTransport.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Socks5 = Prism::Socks5;
    using Prism::AsBytes;
    using Prism::AsU8Span;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    using Prism::PrismMockTransport;
    using Prism::Transmission;

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
    auto MakeMock(Net::any_io_executor Executor) -> std::shared_ptr<PrismMockTransport>
    {
        auto Mock = std::make_shared<PrismMockTransport>(Executor);
        Mock->EofOnDrain = true;
        Mock->TransportKind = Prism::Transmission::Type::Udp;
        return Mock;
    }
    /// 构造 socks5 目标地址
    auto MakeSocks5Address() -> Socks5::Address
    {
        Socks5::Address Address{};
        Address.Type = Socks5::AddressType::Ipv4;
        Address.Host = "1.2.3.4";
        Address.Port = 80;
        return Address;
    }

    /** @brief 注入下一次写失败并验证 SOCKS5 datagram 错误。 */
    auto RunSendWriteFail(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto Raw = MakeMock(IoContext.get_executor());
        Raw->FailNextWrite = true;
        auto Datagram = std::make_shared<Socks5::Dgram<>>(Raw);
        const std::string Payload = "x";
        const auto ErrorValue = co_await Datagram->AsyncSendTo(
            MakeSocks5Address(), AsU8Span(Payload));
        EXPECT_EQ(ErrorValue, Error::IoError);
    }

    /** @brief 验证空 datagram 头的 EOF 错误。 */
    auto RunReceiveHeadEof(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto Raw = MakeMock(IoContext.get_executor());
        auto Datagram = std::make_shared<Socks5::Dgram<>>(Raw);
        Socks5::Address Source;
        std::vector<std::uint8_t> Payload;
        const auto ErrorValue =
            co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(ErrorValue, Error::IoError);
    }

    /** @brief 验证非零 RSV 字段被拒绝。 */
    auto RunReceiveBadRsv(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto Raw = MakeMock(IoContext.get_executor());
        Raw->ToRead = {0x01, 0x00, 0x00};
        auto Datagram = std::make_shared<Socks5::Dgram<>>(Raw);
        Socks5::Address Source;
        std::vector<std::uint8_t> Payload;
        const auto ErrorValue =
            co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(ErrorValue, Error::BadMessage);
    }

    /** @brief 验证未知 ATYP 被拒绝。 */
    auto RunReceiveBadAtyp(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto Raw = MakeMock(IoContext.get_executor());
        Raw->ToRead = {0x00, 0x00, 0x00, 0x99};
        auto Datagram = std::make_shared<Socks5::Dgram<>>(Raw);
        Socks5::Address Source;
        std::vector<std::uint8_t> Payload;
        const auto ErrorValue =
            co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(ErrorValue, Error::BadMessage);
    }

    /** @brief 验证域名长度超过实际 wire 的截断错误。 */
    auto RunReceiveDomainTruncated(Net::io_context &IoContext)
        -> Net::awaitable<void>
    {
        auto Raw = MakeMock(IoContext.get_executor());
        Raw->ToRead = {0x00, 0x00, 0x00, 0x03, 0x05, 'a', 'b'};
        auto Datagram = std::make_shared<Socks5::Dgram<>>(Raw);
        Socks5::Address Source;
        std::vector<std::uint8_t> Payload;
        const auto ErrorValue =
            co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(ErrorValue, Error::IoError);
    }

    /** @brief 验证 IPv4 地址完整但端口缺失的 EOF。 */
    auto RunReceivePortEof(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto Raw = MakeMock(IoContext.get_executor());
        Raw->ToRead = {0x00, 0x00, 0x00, 0x01, 1, 2, 3, 4};
        auto Datagram = std::make_shared<Socks5::Dgram<>>(Raw);
        Socks5::Address Source;
        std::vector<std::uint8_t> Payload;
        const auto ErrorValue =
            co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(ErrorValue, Error::IoError);
    }

    /** @brief 验证完整帧的载荷读取注入错误。 */
    auto RunReceivePayloadIoError(Net::io_context &IoContext)
        -> Net::awaitable<void>
    {
        auto Raw = MakeMock(IoContext.get_executor());
        Raw->ToRead = {0x00, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50};
        Raw->ReadFailAt = 5;
        auto Datagram = std::make_shared<Socks5::Dgram<>>(Raw);
        Socks5::Address Source;
        std::vector<std::uint8_t> Payload;
        const auto ErrorValue =
            co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(ErrorValue, Error::IoError);
    }

    /** @brief 验证完整帧但缺失载荷时返回 unexpected EOF。 */
    auto RunReceivePayloadEof(Net::io_context &IoContext)
        -> Net::awaitable<void>
    {
        auto Raw = MakeMock(IoContext.get_executor());
        Raw->ToRead = {0x00, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50};
        auto Datagram = std::make_shared<Socks5::Dgram<>>(Raw);
        Socks5::Address Source;
        std::vector<std::uint8_t> Payload;
        const auto ErrorValue =
            co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(ErrorValue, Error::UnexpectedEof);
    }

    /** @brief 验证 IPv6 地址体截断的 IO 错误。 */
    auto RunReceiveIpv6Truncated(Net::io_context &IoContext)
        -> Net::awaitable<void>
    {
        auto Raw = MakeMock(IoContext.get_executor());
        std::vector<std::uint8_t> Wire{0x00, 0x00, 0x00, 0x04};
        Wire.insert(Wire.end(), 8, 0x21);
        Raw->ToRead = std::move(Wire);
        auto Datagram = std::make_shared<Socks5::Dgram<>>(Raw);
        Socks5::Address Source;
        std::vector<std::uint8_t> Payload;
        const auto ErrorValue =
            co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(ErrorValue, Error::IoError);
    }

    /** @brief 验证关闭后的发送和接收均返回 IO 错误。 */
    auto RunClosedStateOperations(Net::io_context &IoContext)
        -> Net::awaitable<void>
    {
        auto Raw = MakeMock(IoContext.get_executor());
        auto Datagram = std::make_shared<Socks5::Dgram<>>(Raw);
        Datagram->Close();
        const std::string Payload = "x";
        const auto SendError = co_await Datagram->AsyncSendTo(
            MakeSocks5Address(), AsU8Span(Payload));
        EXPECT_EQ(SendError, Error::IoError);
        Socks5::Address Source;
        std::vector<std::uint8_t> Received;
        const auto ReceiveError =
            co_await Datagram->AsyncReceiveFrom(Source, Received);
        EXPECT_EQ(ReceiveError, Error::IoError);
        const auto Drain = co_await Datagram->Activity()->Drain();
        EXPECT_TRUE(Drain);
    }

} // namespace

TEST(Socks5DgramErr, SendWriteFail)
    {
        Net::io_context IoContext;

        RunCoroutine(IoContext, RunSendWriteFail(IoContext));
    }

TEST(Socks5DgramErr, ReceiveHeadEof)
    {
        Net::io_context IoContext;

        RunCoroutine(IoContext, RunReceiveHeadEof(IoContext));
    }

TEST(Socks5DgramErr, ReceiveBadRsv)
    {
        Net::io_context IoContext;

        RunCoroutine(IoContext, RunReceiveBadRsv(IoContext));
    }

TEST(Socks5DgramErr, ReceiveBadAtyp)
    {
        Net::io_context IoContext;

        RunCoroutine(IoContext, RunReceiveBadAtyp(IoContext));
    }

TEST(Socks5DgramErr, ReceiveDomainTruncated)
    {
        Net::io_context IoContext;

        RunCoroutine(IoContext, RunReceiveDomainTruncated(IoContext));
    }

TEST(Socks5DgramErr, ReceivePortEof)
    {
        Net::io_context IoContext;

        RunCoroutine(IoContext, RunReceivePortEof(IoContext));
    }

TEST(Socks5DgramErr, ReceivePayloadIoError)
    {
        Net::io_context IoContext;

        RunCoroutine(IoContext, RunReceivePayloadIoError(IoContext));
    }

TEST(Socks5DgramErr, ReceivePayloadEof)
    {
        Net::io_context IoContext;

        RunCoroutine(IoContext, RunReceivePayloadEof(IoContext));
    }

TEST(Socks5DgramErr, ReceiveIpv6Truncated)
    {
        Net::io_context IoContext;

        RunCoroutine(IoContext, RunReceiveIpv6Truncated(IoContext));
    }

TEST(Socks5DgramErr, ClosedStateOperations)
    {
        Net::io_context IoContext;

        RunCoroutine(IoContext, RunClosedStateOperations(IoContext));
    }
