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

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include <Preview/Protocols/Tuic/Tuic.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Tuic = Preview::Tuic;
    using Preview::AsBytes;
    using Preview::AsU8Span;
    using Preview::Error;
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

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     const auto head = MakeTuicHead(0x99);
                     raw->ToRead.assign(head.begin(), head.end());
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     Tuic::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::BadMessage);
                 });
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

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x05, 0x02, 0, 0, 0, 0, 1, 0, 0, 1, 0x01, 1, 2, 3, 4, 0x00, 0x50};
                     raw->FailNextRead = true;
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     Tuic::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::IoError);
                 });
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

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     const auto head = MakeTuicHead(0x02);
                     std::vector<std::uint8_t> wire(head.begin(), head.end());
                     wire.insert(wire.end(), 8, 0x21);
                     raw->ToRead = wire;
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     Tuic::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::NeedMore);
                 });
    }

TEST(TuicDgramErr, ClosedStateOperations)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     dg->Close();
                     const std::string p = "x";
                     const auto serr = co_await dg->AsyncSendTo(MakeTuicAddress(), AsU8Span(p));
                     EXPECT_EQ(serr, Error::IoError);
                     Tuic::Address src;
                     std::vector<std::uint8_t> out;
                     const auto rerr = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(rerr, Error::UnexpectedEof);
                 });
    }

