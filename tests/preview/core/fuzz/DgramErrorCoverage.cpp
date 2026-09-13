/**
 * @file DgramErrorCoverage.cpp
 * @brief 各协议 Dgram（UDP 数据面）错误路径覆盖测试
 * @details 使用共享的可编程传输桩（PreviewMockTransport）直接构造
 * Dgram（绕过握手），对 7 个协议（socks5/trojan/vless/tuic/vmess/
 * hysteria2/shadowsocks2022）覆盖错误分支：
 * 1. AsyncSendTo：底层写失败 → io_error（ss2022 另覆盖半包写）
 * 2. AsyncReceiveFrom：半包截断（域名长度声明比实际大）→ io_error
 * 3. AsyncReceiveFrom：非法 ATYP → bad_message
 * 4. AsyncReceiveFrom：EOF → io_error / unexpected_eof
 * 5. 未连接/已关闭状态下操作（Close 后读写 → io_error；vmess 未握手
 *    → not_open）
 * @note 所有用例采用 co_spawn + ioc.run() 模式驱动。
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
#include <memory>
#include <string>
#include <vector>

#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Foundation/Error.hpp>
#include <preview/Transport/MemoryStream.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include <preview/Protocols/Hysteria2/Hysteria2.hpp>
#include <preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <preview/Protocols/Socks5/Socks5.hpp>
#include <preview/Protocols/Trojan/Trojan.hpp>
#include <preview/Protocols/Tuic/Tuic.hpp>
#include <preview/Protocols/Vless/Vless.hpp>
#include <preview/Protocols/Vmess/Vmess.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Hysteria2 = Preview::Hysteria2;
    namespace Shadowsocks2022 = Preview::Shadowsocks2022;
    namespace Socks5 = Preview::Socks5;
    namespace Trojan = Preview::Trojan;
    namespace Tuic = Preview::Tuic;
    namespace Vless = Preview::Vless;
    namespace Vmess = Preview::Vmess;
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

    /// 构造 socks5 目标地址
    auto MakeSocks5Address() -> Socks5::Address
    {
        Socks5::Address Address{};
        Address.Type = Socks5::AddressType::Ipv4;
        Address.Host = "1.2.3.4";
        Address.Port = 80;
        return Address;
    }

    /// 构造 trojan 目标地址
    auto MakeTrojanAddress() -> Trojan::Address
    {
        Trojan::Address Address{};
        Address.Type = Trojan::AddressType::Ipv4;
        Address.Host = "1.2.3.4";
        Address.Port = 80;
        return Address;
    }

    /// 构造 vless 目标地址
    auto MakeVlessAddress() -> Vless::Address
    {
        Vless::Address Address{};
        Address.Type = Vless::AddressType::Ipv4;
        Address.Host = "1.2.3.4";
        Address.Port = 80;
        return Address;
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

    /// 构造 hysteria2 目标地址
    auto MakeHysteria2Address() -> Hysteria2::Address
    {
        Hysteria2::Address Address{};
        Address.Type = Hysteria2::AddressType::Ipv4;
        Address.Host = "1.2.3.4";
        Address.Port = 80;
        return Address;
    }

    /// 构造 ss2022 目标地址
    auto MakeShadowsocks2022Address() -> Shadowsocks2022::Address
    {
        Shadowsocks2022::Address Address{};
        Address.Type = Shadowsocks2022::AddressType::Ipv4;
        Address.Host = "1.2.3.4";
        Address.Port = 80;
        return Address;
    }

    /// 构造 vmess 目标地址
    auto MakeVmessAddress() -> Vmess::Address
    {
        Vmess::Address Address{};
        Address.Type = Vmess::AddressType::Domain;
        Address.Host = "example.com";
        Address.Port = 53;
        return Address;
    }

    /// 构造 16 字节测试 UUID
    auto MakeUuid() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> Uuid{};
        for (std::size_t Index = 0; Index < Uuid.size(); ++Index)
        {
            Uuid[Index] = static_cast<std::uint8_t>(0x11 * (Index + 1));
        }
        return Uuid;
    }

    /// dgram 错误矩阵使用有限注入流，耗尽后按旧桩契约显式返回 EOF。
    auto MakeMock(Net::any_io_executor Executor) -> std::shared_ptr<PreviewMockTransport>
    {
        auto Mock = std::make_shared<PreviewMockTransport>(Executor);
        Mock->EofOnDrain = true;
        Mock->TransportKind = Preview::Transmission::Type::Udp;
        return Mock;
    }

    // ──────────────────────────── SOCKS5 ────────────────────────────

    TEST(Socks5DgramErr, SendWriteFail)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->FailNextWrite = true;
                     auto dg = std::make_shared<Socks5::Dgram<>>(raw);
                     const std::string p = "x";
                     const auto err = co_await dg->AsyncSendTo(MakeSocks5Address(), AsU8Span(p));
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(Socks5DgramErr, ReceiveHeadEof)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     auto dg = std::make_shared<Socks5::Dgram<>>(raw);
                     Socks5::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(Socks5DgramErr, ReceiveBadRsv)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x01, 0x00, 0x00};
                     auto dg = std::make_shared<Socks5::Dgram<>>(raw);
                     Socks5::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::BadMessage);
                 });
    }

    TEST(Socks5DgramErr, ReceiveBadAtyp)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x00, 0x00, 0x00, 0x99};
                     auto dg = std::make_shared<Socks5::Dgram<>>(raw);
                     Socks5::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::BadMessage);
                 });
    }

    TEST(Socks5DgramErr, ReceiveDomainTruncated)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 域名长度声明 5，实际仅 2 字节 → 半包截断 io_error
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x00, 0x00, 0x00, 0x03, 0x05, 'a', 'b'};
                     auto dg = std::make_shared<Socks5::Dgram<>>(raw);
                     Socks5::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(Socks5DgramErr, ReceivePortEof)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 地址体完整，端口缺失 → io_error
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x00, 0x00, 0x00, 0x01, 1, 2, 3, 4};
                     auto dg = std::make_shared<Socks5::Dgram<>>(raw);
                     Socks5::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(Socks5DgramErr, ReceivePayloadIoError)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 帧头完整，载荷读取注入错误 → io_error
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x00, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50};
                     raw->ReadFailAt = 5; // 第 5 次读取 = 载荷读取
                     auto dg = std::make_shared<Socks5::Dgram<>>(raw);
                     Socks5::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(Socks5DgramErr, ReceivePayloadEof)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 帧头完整，载荷缺失（EOF）→ unexpected_eof
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x00, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50};
                     auto dg = std::make_shared<Socks5::Dgram<>>(raw);
                     Socks5::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::UnexpectedEof);
                 });
    }

    TEST(Socks5DgramErr, ReceiveIpv6Truncated)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // IPv6 地址体截断（16 字节仅注入 8）→ io_error
                     auto raw = MakeMock(ioc.get_executor());
                     std::vector<std::uint8_t> wire{0x00, 0x00, 0x00, 0x04};
                     wire.insert(wire.end(), 8, 0x21);
                     raw->ToRead = wire;
                     auto dg = std::make_shared<Socks5::Dgram<>>(raw);
                     Socks5::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(Socks5DgramErr, ClosedStateOperations)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     auto dg = std::make_shared<Socks5::Dgram<>>(raw);
                     dg->Close();
                     const std::string p = "x";
                     const auto serr = co_await dg->AsyncSendTo(MakeSocks5Address(), AsU8Span(p));
                     EXPECT_EQ(serr, Error::IoError);
                     Socks5::Address src;
                     std::vector<std::uint8_t> out;
                     const auto rerr = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(rerr, Error::IoError);
                 });
    }

    // ──────────────────────────── Trojan ────────────────────────────

    TEST(TrojanDgramErr, SendWriteFail)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->FailNextWrite = true;
                     auto dg = std::make_shared<Trojan::Dgram<>>(raw);
                     const std::string p = "x";
                     const auto err = co_await dg->AsyncSendTo(MakeTrojanAddress(), AsU8Span(p));
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(TrojanDgramErr, ReceiveHeadEof)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     auto dg = std::make_shared<Trojan::Dgram<>>(raw);
                     Trojan::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(TrojanDgramErr, ReceiveBadAtyp)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x99};
                     auto dg = std::make_shared<Trojan::Dgram<>>(raw);
                     Trojan::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::BadMessage);
                 });
    }

    TEST(TrojanDgramErr, ReceiveDomainTruncated)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x03, 0x05, 'a', 'b'};
                     auto dg = std::make_shared<Trojan::Dgram<>>(raw);
                     Trojan::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(TrojanDgramErr, ReceivePortEof)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x01, 1, 2, 3, 4};
                     auto dg = std::make_shared<Trojan::Dgram<>>(raw);
                     Trojan::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(TrojanDgramErr, ReceiveLenHeadEof)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // LEN(2) + CRLF(2) 头部缺失 → io_error
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x01, 1, 2, 3, 4, 0x00, 0x50};
                     auto dg = std::make_shared<Trojan::Dgram<>>(raw);
                     Trojan::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(TrojanDgramErr, ReceiveBadCrlf)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // CRLF 魔数非法 → bad_magic
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x01, 1, 2, 3, 4, 0x00, 0x50, 0x00, 0x05, 'X', 'Y'};
                     auto dg = std::make_shared<Trojan::Dgram<>>(raw);
                     Trojan::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::BadMagic);
                 });
    }

    TEST(TrojanDgramErr, ReceivePayloadTruncated)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // LEN 声明 5，实际仅 2 字节载荷 → io_error
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x01, 1, 2, 3, 4, 0x00, 0x50, 0x00, 0x05, '\r', '\n', 'h', 'e'};
                     auto dg = std::make_shared<Trojan::Dgram<>>(raw);
                     Trojan::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(TrojanDgramErr, ReceivePayloadIoError)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x01, 1, 2, 3, 4, 0x00, 0x50, 0x00, 0x05, '\r', '\n'};
                     raw->ReadFailAt = 5; // 第 5 次读取 = 载荷读取
                     auto dg = std::make_shared<Trojan::Dgram<>>(raw);
                     Trojan::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(TrojanDgramErr, ClosedStateOperations)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     auto dg = std::make_shared<Trojan::Dgram<>>(raw);
                     dg->Close();
                     const std::string p = "x";
                     const auto serr = co_await dg->AsyncSendTo(MakeTrojanAddress(), AsU8Span(p));
                     EXPECT_EQ(serr, Error::IoError);
                     Trojan::Address src;
                     std::vector<std::uint8_t> out;
                     const auto rerr = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(rerr, Error::IoError);
                 });
    }

    // ──────────────────────────── VLESS ────────────────────────────

    TEST(VlessDgramErr, SendWriteFail)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->FailNextWrite = true;
                     auto dg = std::make_shared<Vless::Dgram<>>(raw);
                     const std::string p = "x";
                     const auto err = co_await dg->AsyncSendTo(MakeVlessAddress(), AsU8Span(p));
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(VlessDgramErr, ReceiveHeadEof)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     auto dg = std::make_shared<Vless::Dgram<>>(raw);
                     Vless::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(VlessDgramErr, ReceiveBadAtyp)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x99};
                     auto dg = std::make_shared<Vless::Dgram<>>(raw);
                     Vless::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::BadMessage);
                 });
    }

    TEST(VlessDgramErr, ReceiveDomainTruncated)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x02, 0x05, 'a', 'b'}; // VLESS domain = 0x02
                     auto dg = std::make_shared<Vless::Dgram<>>(raw);
                     Vless::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(VlessDgramErr, ReceivePortEof)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x01, 1, 2, 3, 4};
                     auto dg = std::make_shared<Vless::Dgram<>>(raw);
                     Vless::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(VlessDgramErr, ReceivePayloadIoError)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x01, 1, 2, 3, 4, 0x00, 0x50};
                     raw->ReadFailAt = 4; // 第 4 次读取 = 载荷读取
                     auto dg = std::make_shared<Vless::Dgram<>>(raw);
                     Vless::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(VlessDgramErr, ReceivePayloadEof)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x01, 1, 2, 3, 4, 0x00, 0x50};
                     auto dg = std::make_shared<Vless::Dgram<>>(raw);
                     Vless::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::UnexpectedEof);
                 });
    }

    TEST(VlessDgramErr, ReceiveIpv6Truncated)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     std::vector<std::uint8_t> wire{0x03}; // VLESS ipv6 = 0x03
                     wire.insert(wire.end(), 8, 0x21);
                     raw->ToRead = wire;
                     auto dg = std::make_shared<Vless::Dgram<>>(raw);
                     Vless::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(VlessDgramErr, ClosedStateOperations)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     auto dg = std::make_shared<Vless::Dgram<>>(raw);
                     dg->Close();
                     const std::string p = "x";
                     const auto serr = co_await dg->AsyncSendTo(MakeVlessAddress(), AsU8Span(p));
                     EXPECT_EQ(serr, Error::IoError);
                     Vless::Address src;
                     std::vector<std::uint8_t> out;
                     const auto rerr = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(rerr, Error::IoError);
                 });
    }

    // ──────────────────────────── TUIC ────────────────────────────

    /// TUIC v5 packet 帧：Ver(0x05) Cmd(0x02) + 2B Assoc/Pkt + 分片字段 + Size + ATYP。
    auto MakeTuicHead(std::uint8_t atyp) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> head{0x05, 0x02, 0, 0, 0, 0, 1, 0, 0, 0};
        head.push_back(atyp);
        return head;
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

    // ──────────────────────────── Hysteria2 ────────────────────────────

    /// hysteria2 帧：Kind(0x02) SessionID(4 LE) PacketID(4 LE) 9 字节头 + ATYP 单独一字节
    auto MakeHysteria2Head(std::uint8_t atyp) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> head{0x02, 0, 0, 0, 0, 0, 0, 0, 0};
        head.push_back(atyp);
        return head;
    }

    TEST(Hysteria2DgramErr, SendWriteFail)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->FailNextWrite = true;
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     const std::string p = "x";
                     const auto err = co_await dg->AsyncSendTo(MakeHysteria2Address(), AsU8Span(p));
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(Hysteria2DgramErr, ReceiveHeadEof)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::UnexpectedEof);
                 });
    }

    TEST(Hysteria2DgramErr, ReceiveShortHead)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x02, 0, 0, 0, 0};
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::NeedMore);
                 });
    }

    TEST(Hysteria2DgramErr, ReceiveBadKind)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x01, 0, 0, 0, 0, 0, 0, 0, 0x01};
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::BadMessage);
                 });
    }

    TEST(Hysteria2DgramErr, ReceiveBadAtyp)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     const auto head = MakeHysteria2Head(0x99);
                     raw->ToRead.assign(head.begin(), head.end());
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::BadMessage);
                 });
    }

    TEST(Hysteria2DgramErr, ReceiveDomainTruncated)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x05, 'a', 'b'};
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::NeedMore);
                 });
    }

    TEST(Hysteria2DgramErr, ReceivePortEof)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4};
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::NeedMore);
                 });
    }

    TEST(Hysteria2DgramErr, ReceivePayloadIoError)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50};
                     raw->FailNextRead = true;
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(Hysteria2DgramErr, ReceiveEmptyPayloadAccepted)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50};
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::None);
                     EXPECT_TRUE(out.empty());
                 });
    }

    TEST(Hysteria2DgramErr, ReceiveIpv6Truncated)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     const auto head = MakeHysteria2Head(0x03); // hysteria2 ipv6 = 0x03
                     std::vector<std::uint8_t> wire(head.begin(), head.end());
                     wire.insert(wire.end(), 8, 0x21);
                     raw->ToRead = wire;
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::NeedMore);
                 });
    }

    TEST(Hysteria2DgramErr, ClosedStateOperations)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     dg->Close();
                     const std::string p = "x";
                     const auto serr = co_await dg->AsyncSendTo(MakeHysteria2Address(), AsU8Span(p));
                     EXPECT_EQ(serr, Error::IoError);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto rerr = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(rerr, Error::UnexpectedEof);
                 });
    }

    // ──────────────────────────── Shadowsocks 2022 ────────────────────────────

    /// ss2022 UDP 会话密钥（16 字节）
    auto MakeShadowsocks2022Key() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> key{};
        for (std::size_t i = 0; i < key.size(); ++i)
        {
            key[i] = static_cast<std::uint8_t>(0xA0 + i);
        }
        return key;
    }

    /// 构造带合法 AEAD 的 ss2022 UDP 数据报，供字段错误路径测试使用。
    auto MakeShadowsocks2022Packet(const std::array<std::uint8_t, 16> &key, std::uint8_t Type,
                        const std::vector<std::uint8_t> &Address = {0x01, 1, 2, 3, 4, 0x00, 0x50})
        -> std::vector<std::uint8_t>
    {
        std::array<std::uint8_t, 16> SeparatePlain{};
        std::copy_n(key.begin(), 8, SeparatePlain.begin());
        SeparatePlain.back() = 1;
        const auto Separate = Shadowsocks2022::detail::CryptSeparate(
            key, std::span<const std::uint8_t, Shadowsocks2022::SeparateHdrLen>(SeparatePlain), true);
        if (!Separate)
        {
            return {};
        }

        const auto SessionId = std::span<const std::uint8_t>(SeparatePlain.data(),
                                                              Shadowsocks2022::SessionIdLen);
        const auto Subkey = Shadowsocks2022::SessionKey(key, SessionId, Shadowsocks2022::AeadKeyLen);
        std::array<std::uint8_t, 12> Nonce{};
        std::memcpy(Nonce.data(), SeparatePlain.data() + Shadowsocks2022::SessionIdLen / 2,
                    Shadowsocks2022::SessionIdLen / 2);
        std::memcpy(Nonce.data() + Shadowsocks2022::SessionIdLen / 2,
                    SeparatePlain.data() + Shadowsocks2022::SessionIdLen,
                    Shadowsocks2022::PacketIdLen);

        std::vector<std::uint8_t> Plain{Type};
        Plain.insert(Plain.end(), 8, 0);
        Plain.insert(Plain.end(), Address.begin(), Address.end());
        Plain.insert(Plain.end(), {0, 0});
        const auto Body = Shadowsocks2022::detail::UdpSeal(
            Shadowsocks2022::detail::UdpSealInput{Subkey, Nonce, Plain, {}});
        if (Body.empty())
        {
            return {};
        }
        std::vector<std::uint8_t> Packet(Separate->begin(), Separate->end());
        Packet.insert(Packet.end(), Body.begin(), Body.end());
        return Packet;
    }

    TEST(Ss2022DgramErr, SendWriteFail)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->FailNextWrite = true;
                     auto dg = std::make_shared<Shadowsocks2022::Dgram<>>(raw, MakeShadowsocks2022Key());
                     const std::string p = "x";
                     const auto err = co_await dg->AsyncSendTo(MakeShadowsocks2022Address(), AsU8Span(p));
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(Ss2022DgramErr, SendPartialWrite)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 单次写入仅返回 8 字节（半包写）→ n != 帧长 → io_error
                     auto raw = MakeMock(ioc.get_executor());
                     raw->MaxWrite = 8;
                     auto dg = std::make_shared<Shadowsocks2022::Dgram<>>(raw, MakeShadowsocks2022Key());
                     const std::string p = "x";
                     const auto err = co_await dg->AsyncSendTo(MakeShadowsocks2022Address(), AsU8Span(p));
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(Ss2022DgramErr, ReceiveIoError)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     raw->FailNextRead = true;
                     auto dg = std::make_shared<Shadowsocks2022::Dgram<>>(raw, MakeShadowsocks2022Key());
                     Shadowsocks2022::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(Ss2022DgramErr, ReceiveEof)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     auto dg = std::make_shared<Shadowsocks2022::Dgram<>>(raw, MakeShadowsocks2022Key());
                     Shadowsocks2022::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::UnexpectedEof);
                 });
    }

    TEST(Ss2022DgramErr, ReceiveTooShort)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 不足最小长度（SeparateHeader + 头部 + tag）→ bad_length
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
                     auto dg = std::make_shared<Shadowsocks2022::Dgram<>>(raw, MakeShadowsocks2022Key());
                     Shadowsocks2022::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::BadLength);
                 });
    }

    TEST(Ss2022DgramErr, ReceiveBadSessionId)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // SessionID 前 8 字节与密钥不一致 → bad_auth
                     auto raw = MakeMock(ioc.get_executor());
                     auto packet = MakeShadowsocks2022Packet(MakeShadowsocks2022Key(), 0x01);
                     packet[0] ^= 0xFF;
                     raw->ToRead = packet;
                     auto dg = std::make_shared<Shadowsocks2022::Dgram<>>(raw, MakeShadowsocks2022Key());
                     Shadowsocks2022::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::BadAuth);
                 });
    }

    TEST(Ss2022DgramErr, ReceiveBadType)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 合法 AEAD 内的类型字节非法 → bad_message
                     auto raw = MakeMock(ioc.get_executor());
                     raw->ToRead = MakeShadowsocks2022Packet(MakeShadowsocks2022Key(), 0x02);
                     auto dg = std::make_shared<Shadowsocks2022::Dgram<>>(raw, MakeShadowsocks2022Key());
                     Shadowsocks2022::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::BadMessage);
                 });
    }

    TEST(Ss2022DgramErr, ReceiveDomainTruncated)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 合法 AEAD 内的域名长度声明 0xFF 但包内无足够字节 → need_more
                     auto raw = MakeMock(ioc.get_executor());
                     const std::vector<std::uint8_t> TruncatedDomain{0x03, 0xFF};
                     const auto packet = MakeShadowsocks2022Packet(MakeShadowsocks2022Key(), 0x00, TruncatedDomain);
                     raw->ToRead = packet;
                     auto dg = std::make_shared<Shadowsocks2022::Dgram<>>(raw, MakeShadowsocks2022Key());
                     Shadowsocks2022::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::BadMessage);
                 });
    }

    TEST(Ss2022DgramErr, ClosedStateOperations)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto raw = MakeMock(ioc.get_executor());
                     auto dg = std::make_shared<Shadowsocks2022::Dgram<>>(raw, MakeShadowsocks2022Key());
                     dg->Close();
                     const std::string p = "x";
                     const auto serr = co_await dg->AsyncSendTo(MakeShadowsocks2022Address(), AsU8Span(p));
                     EXPECT_EQ(serr, Error::NotOpen);
                     Shadowsocks2022::Address src;
                     std::vector<std::uint8_t> out;
                     const auto rerr = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(rerr, Error::UnexpectedEof);
                 });
    }

    // ──────────────────────────── VMess ────────────────────────────

    TEST(VmessDgramErr, NotHandshakenOperations)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 底层 Conn 未握手 → 收发均 not_open
                     auto c = std::make_shared<Vmess::Conn<>>(MakeUuid());
                     auto dg = std::make_shared<Vmess::Dgram<>>(c);
                     const std::string p = "x";
                     const auto serr = co_await dg->AsyncSendTo(AsU8Span(p));
                     EXPECT_EQ(serr, Error::NotOpen);
                     std::vector<std::uint8_t> out;
                     const auto rerr = co_await dg->AsyncReceiveFrom(out);
                     EXPECT_EQ(rerr, Error::NotOpen);
                 });
    }

    TEST(VmessDgramErr, PeerClosedOperations)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = MakeUuid();

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 服务端 AcceptPacket 完成握手后关闭 → 客户端收发失败
                     Net::experimental::channel<void(boost::system::error_code)> server_closed(
                         ioc.get_executor(), 1);
                     Net::co_spawn(ioc.get_executor(),
                                   [&]() -> Net::awaitable<void>
                                   {
                                       Vmess::ServerConfig cfg;
                                       cfg.uuid = uuid;
                                       auto [err, req, dg] = co_await Vmess::AcceptPacket(
                                           std::make_shared<MemoryStream>(std::move(b)), cfg);
                                       EXPECT_EQ(err, Error::None);
                                       (void)req;
                                       dg->Close();
                                       server_closed.try_send(boost::system::error_code{});
                                   },
                                   Net::detached);

                     Vmess::ClientConfig cfg;
                     cfg.uuid = uuid;
                     auto [herr, dg] = co_await Vmess::ConnectPacket(
                         std::make_shared<MemoryStream>(std::move(a)), cfg, MakeVmessAddress());
                     EXPECT_EQ(herr, Error::None);
                     co_await server_closed.async_receive(Net::use_awaitable);

                     const std::string p = "x";
                     const auto serr = co_await dg->AsyncSendTo(AsU8Span(p));
                     EXPECT_EQ(serr, Error::IoError);
                     std::vector<std::uint8_t> out;
                     const auto rerr = co_await dg->AsyncReceiveFrom(out);
                     EXPECT_EQ(rerr, Error::UnexpectedEof);
                 });
    }

} // namespace
