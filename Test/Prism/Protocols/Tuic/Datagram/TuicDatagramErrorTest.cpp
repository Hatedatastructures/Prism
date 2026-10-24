/**
 * @file TuicDatagramErrorTest.cpp
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
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>
#include <Prism/Protocols/Tuic/Tuic.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Tuic = Prism::Tuic;
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
    /// 构造 tuic 目标地址
    auto MakeTuicAddress() -> Tuic::Address
    {
        Tuic::Address Address{};
        Address.Type = Tuic::AddressType::Ipv4;
        Address.Host = "1.2.3.4";
        Address.Port = 80;
        return Address;
    }
    /// TUIC v5 packet 帧：Ver(0x05) Cmd(0x02) + 2B Assoc/Pkt + 分片字段 + Size + ATYP。
    auto MakeTuicHead(std::uint8_t atyp) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> head{0x05, 0x02, 0, 0, 0, 0, 1, 0, 0, 0};
        head.push_back(atyp);
        return head;
    }

} // namespace

namespace
{
    auto RunReceiveBadAtyp(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto Raw = MakeMock(IoContext.get_executor());
        const auto Head = MakeTuicHead(0x99);
        Raw->ToRead.assign(Head.begin(), Head.end());
        auto Datagram = std::make_shared<Tuic::Dgram<>>(Raw);
        Tuic::Address Source;
        std::vector<std::uint8_t> Payload;
        const auto Result = co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(Result, Error::BadMessage);
    }

    auto RunReceivePayloadIoError(Net::io_context &IoContext)
        -> Net::awaitable<void>
    {
        auto Raw = MakeMock(IoContext.get_executor());
        Raw->ToRead = {
            0x05, 0x02, 0, 0, 0, 0, 1, 0, 0, 1,
            0x01, 1, 2, 3, 4, 0x00, 0x50};
        Raw->FailNextRead = true;
        auto Datagram = std::make_shared<Tuic::Dgram<>>(Raw);
        Tuic::Address Source;
        std::vector<std::uint8_t> Payload;
        const auto Result = co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(Result, Error::IoError);
    }

    auto RunReceiveIpv6Truncated(Net::io_context &IoContext)
        -> Net::awaitable<void>
    {
        auto Raw = MakeMock(IoContext.get_executor());
        const auto Head = MakeTuicHead(0x02);
        std::vector<std::uint8_t> Wire(Head.begin(), Head.end());
        Wire.insert(Wire.end(), 8, 0x21);
        Raw->ToRead = std::move(Wire);
        auto Datagram = std::make_shared<Tuic::Dgram<>>(Raw);
        Tuic::Address Source;
        std::vector<std::uint8_t> Payload;
        const auto Result = co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(Result, Error::NeedMore);
    }

    auto RunClosedStateOperations(Net::io_context &IoContext)
        -> Net::awaitable<void>
    {
        auto Raw = MakeMock(IoContext.get_executor());
        auto Datagram = std::make_shared<Tuic::Dgram<>>(Raw);
        const auto Close = Datagram->Close();
        EXPECT_TRUE(Close);
        if (!Close)
        {
            co_return;
        }
        const auto Activity = Datagram->Activity();
        EXPECT_TRUE(Activity);
        if (!Activity)
        {
            co_return;
        }
        const auto Drained = co_await Activity->Drain();
        EXPECT_TRUE(Drained);
        if (!Drained)
        {
            co_return;
        }
        const std::string PayloadText = "x";
        const auto SendResult = co_await Datagram->AsyncSendTo(
            MakeTuicAddress(),
            AsU8Span(PayloadText));
        EXPECT_EQ(SendResult, Error::IoError);
        Tuic::Address Source;
        std::vector<std::uint8_t> Payload;
        const auto ReceiveResult =
            co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(ReceiveResult, Error::IoError);
    }
}

TEST(TuicDgramErr, SendWriteFail)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->FailNextWrite = true;
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     const std::string p = "x";
                     const auto err = co_await dg->AsyncSendTo(MakeTuicAddress(), AsU8Span(p));
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

TEST(TuicDgramErr, ReceiveHeadEof)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     Tuic::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::UnexpectedEof);
                 });
    }

TEST(TuicDgramErr, ReceiveShortHead)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x05, 0x02, 0, 0, 0};
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     Tuic::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::NeedMore);
                 });
    }

TEST(TuicDgramErr, ReceiveBadVersion)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x04, 0x02, 0, 0, 0, 0, 1, 0, 0, 0, 0x01};
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     Tuic::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::BadMagic);
                 });
    }

TEST(TuicDgramErr, ReceiveBadCommand)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0};
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     Tuic::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::BadMessage);
                 });
    }

TEST(TuicDgramErr, ReceiveBadAtyp)
    {
        Net::io_context ioc;
        RunCoroutine(ioc, RunReceiveBadAtyp(ioc));
    }

TEST(TuicDgramErr, ReceiveDomainTruncated)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x05, 0x02, 0, 0, 0, 0, 1, 0, 0, 0, 0x00, 0x05, 'a', 'b'};
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     Tuic::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::NeedMore);
                 });
    }

TEST(TuicDgramErr, ReceivePortEof)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x05, 0x02, 0, 0, 0, 0, 1, 0, 0, 0, 0x01, 1, 2, 3, 4};
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     Tuic::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::NeedMore);
                 });
    }

TEST(TuicDgramErr, ReceivePayloadIoError)
    {
        Net::io_context ioc;
        RunCoroutine(ioc, RunReceivePayloadIoError(ioc));
    }

TEST(TuicDgramErr, ReceivePayloadEof)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x05, 0x02, 0, 0, 0, 0, 1, 0, 0, 1, 0x01, 1, 2, 3, 4, 0x00, 0x50};
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     Tuic::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::NeedMore);
                 });
    }

TEST(TuicDgramErr, ReceiveIpv6Truncated)
    {
        Net::io_context ioc;
        RunCoroutine(ioc, RunReceiveIpv6Truncated(ioc));
    }

TEST(TuicDgramErr, ClosedStateOperations)
    {
        Net::io_context ioc;
        RunCoroutine(ioc, RunClosedStateOperations(ioc));
    }

