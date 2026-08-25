/**
 * @file DgramErrorCoverage.cpp
 * @brief 各协议 Dgram（UDP 数据面）错误路径覆盖测试
 * @details 使用共享的可编程传输桩（ProgrammableTransport）直接构造
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

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <common/Core/ByteSpan.hpp>
#include <common/Core/Error.hpp>
#include <common/Core/Transport/MemoryStream.hpp>
#include <common/ProgrammableTransport.hpp>
#include <common/Protocols/Hysteria2/Hysteria2.hpp>
#include <common/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <common/Protocols/Socks5/Socks5.hpp>
#include <common/Protocols/Trojan/Trojan.hpp>
#include <common/Protocols/Tuic/Tuic.hpp>
#include <common/Protocols/Vless/Vless.hpp>
#include <common/Protocols/Vmess/Vmess.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;
    namespace net = boost::asio;

    /// 运行协程直至完成（异常重抛）
    template <typename A>
    auto run_coro(net::io_context &ioc, A coro) -> void
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          ioc.stop();
                      });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    /// 构造 socks5 目标地址
    auto make_s5_addr() -> Socks5::Address
    {
        Socks5::Address addr{};
        addr.Type = Socks5::AddressType::Ipv4;
        addr.Host = "1.2.3.4";
        addr.Port = 80;
        return addr;
    }

    /// 构造 trojan 目标地址
    auto make_trojan_addr() -> Trojan::Address
    {
        Trojan::Address addr{};
        addr.Type = Trojan::AddressType::Ipv4;
        addr.Host = "1.2.3.4";
        addr.Port = 80;
        return addr;
    }

    /// 构造 vless 目标地址
    auto make_vless_addr() -> Vless::Address
    {
        Vless::Address addr{};
        addr.Type = Vless::AddressType::Ipv4;
        addr.Host = "1.2.3.4";
        addr.Port = 80;
        return addr;
    }

    /// 构造 tuic 目标地址
    auto make_tuic_addr() -> Tuic::Address
    {
        Tuic::Address addr{};
        addr.Type = Tuic::AddressType::Ipv4;
        addr.Host = "1.2.3.4";
        addr.Port = 80;
        return addr;
    }

    /// 构造 hysteria2 目标地址
    auto make_hy2_addr() -> Hysteria2::Address
    {
        Hysteria2::Address addr{};
        addr.Type = Hysteria2::AddressType::Ipv4;
        addr.Host = "1.2.3.4";
        addr.Port = 80;
        return addr;
    }

    /// 构造 ss2022 目标地址
    auto make_ss_addr() -> Shadowsocks2022::Address
    {
        Shadowsocks2022::Address addr{};
        addr.Type = Shadowsocks2022::AddressType::Ipv4;
        addr.Host = "1.2.3.4";
        addr.Port = 80;
        return addr;
    }

    /// 构造 vmess 目标地址
    auto make_vmess_addr() -> Vmess::Address
    {
        Vmess::Address addr{};
        addr.Type = Vmess::AddressType::Domain;
        addr.Host = "example.com";
        addr.Port = 53;
        return addr;
    }

    /// 构造 16 字节测试 UUID
    auto make_uuid() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> uuid{};
        for (std::size_t i = 0; i < uuid.size(); ++i)
        {
            uuid[i] = static_cast<std::uint8_t>(0x11 * (i + 1));
        }
        return uuid;
    }

    // ──────────────────────────── SOCKS5 ────────────────────────────

    TEST(Socks5DgramErr, SendWriteFail)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->FailNextWrite = true;
                     auto dg = std::make_shared<Socks5::Dgram<>>(raw);
                     const std::string p = "x";
                     const auto err = co_await dg->AsyncSendTo(make_s5_addr(), AsU8Span(p));
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(Socks5DgramErr, ReceiveHeadEof)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     auto dg = std::make_shared<Socks5::Dgram<>>(raw);
                     Socks5::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(Socks5DgramErr, ReceiveBadRsv)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x01, 0x00, 0x00};
                     auto dg = std::make_shared<Socks5::Dgram<>>(raw);
                     Socks5::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::bad_message);
                 });
    }

    TEST(Socks5DgramErr, ReceiveBadAtyp)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x00, 0x00, 0x00, 0x99};
                     auto dg = std::make_shared<Socks5::Dgram<>>(raw);
                     Socks5::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::bad_message);
                 });
    }

    TEST(Socks5DgramErr, ReceiveDomainTruncated)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 域名长度声明 5，实际仅 2 字节 → 半包截断 io_error
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x00, 0x00, 0x00, 0x03, 0x05, 'a', 'b'};
                     auto dg = std::make_shared<Socks5::Dgram<>>(raw);
                     Socks5::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(Socks5DgramErr, ReceivePortEof)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 地址体完整，端口缺失 → io_error
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x00, 0x00, 0x00, 0x01, 1, 2, 3, 4};
                     auto dg = std::make_shared<Socks5::Dgram<>>(raw);
                     Socks5::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(Socks5DgramErr, ReceivePayloadIoError)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 帧头完整，载荷读取注入错误 → io_error
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x00, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50};
                     raw->ReadFailAt = 5; // 第 5 次读取 = 载荷读取
                     auto dg = std::make_shared<Socks5::Dgram<>>(raw);
                     Socks5::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(Socks5DgramErr, ReceivePayloadEof)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 帧头完整，载荷缺失（EOF）→ unexpected_eof
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x00, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50};
                     auto dg = std::make_shared<Socks5::Dgram<>>(raw);
                     Socks5::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::unexpected_eof);
                 });
    }

    TEST(Socks5DgramErr, ReceiveIpv6Truncated)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // IPv6 地址体截断（16 字节仅注入 8）→ io_error
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     std::vector<std::uint8_t> wire{0x00, 0x00, 0x00, 0x04};
                     wire.insert(wire.end(), 8, 0x21);
                     raw->ToRead = wire;
                     auto dg = std::make_shared<Socks5::Dgram<>>(raw);
                     Socks5::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(Socks5DgramErr, ClosedStateOperations)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     auto dg = std::make_shared<Socks5::Dgram<>>(raw);
                     dg->Close();
                     const std::string p = "x";
                     const auto serr = co_await dg->AsyncSendTo(make_s5_addr(), AsU8Span(p));
                     EXPECT_EQ(serr, Error::io_error);
                     Socks5::Address src;
                     std::vector<std::uint8_t> out;
                     const auto rerr = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(rerr, Error::io_error);
                 });
    }

    // ──────────────────────────── Trojan ────────────────────────────

    TEST(TrojanDgramErr, SendWriteFail)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->FailNextWrite = true;
                     auto dg = std::make_shared<Trojan::Dgram<>>(raw);
                     const std::string p = "x";
                     const auto err = co_await dg->AsyncSendTo(make_trojan_addr(), AsU8Span(p));
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(TrojanDgramErr, ReceiveHeadEof)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     auto dg = std::make_shared<Trojan::Dgram<>>(raw);
                     Trojan::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(TrojanDgramErr, ReceiveBadAtyp)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x99};
                     auto dg = std::make_shared<Trojan::Dgram<>>(raw);
                     Trojan::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::bad_message);
                 });
    }

    TEST(TrojanDgramErr, ReceiveDomainTruncated)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x03, 0x05, 'a', 'b'};
                     auto dg = std::make_shared<Trojan::Dgram<>>(raw);
                     Trojan::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(TrojanDgramErr, ReceivePortEof)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x01, 1, 2, 3, 4};
                     auto dg = std::make_shared<Trojan::Dgram<>>(raw);
                     Trojan::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(TrojanDgramErr, ReceiveLenHeadEof)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // LEN(2) + CRLF(2) 头部缺失 → io_error
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x01, 1, 2, 3, 4, 0x00, 0x50};
                     auto dg = std::make_shared<Trojan::Dgram<>>(raw);
                     Trojan::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(TrojanDgramErr, ReceiveBadCrlf)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // CRLF 魔数非法 → bad_magic
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x01, 1, 2, 3, 4, 0x00, 0x50, 0x00, 0x05, 'X', 'Y'};
                     auto dg = std::make_shared<Trojan::Dgram<>>(raw);
                     Trojan::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::bad_magic);
                 });
    }

    TEST(TrojanDgramErr, ReceivePayloadTruncated)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // LEN 声明 5，实际仅 2 字节载荷 → io_error
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x01, 1, 2, 3, 4, 0x00, 0x50, 0x00, 0x05, '\r', '\n', 'h', 'e'};
                     auto dg = std::make_shared<Trojan::Dgram<>>(raw);
                     Trojan::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(TrojanDgramErr, ReceivePayloadIoError)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x01, 1, 2, 3, 4, 0x00, 0x50, 0x00, 0x05, '\r', '\n'};
                     raw->ReadFailAt = 5; // 第 5 次读取 = 载荷读取
                     auto dg = std::make_shared<Trojan::Dgram<>>(raw);
                     Trojan::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(TrojanDgramErr, ClosedStateOperations)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     auto dg = std::make_shared<Trojan::Dgram<>>(raw);
                     dg->Close();
                     const std::string p = "x";
                     const auto serr = co_await dg->AsyncSendTo(make_trojan_addr(), AsU8Span(p));
                     EXPECT_EQ(serr, Error::io_error);
                     Trojan::Address src;
                     std::vector<std::uint8_t> out;
                     const auto rerr = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(rerr, Error::io_error);
                 });
    }

    // ──────────────────────────── VLESS ────────────────────────────

    TEST(VlessDgramErr, SendWriteFail)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->FailNextWrite = true;
                     auto dg = std::make_shared<Vless::Dgram<>>(raw);
                     const std::string p = "x";
                     const auto err = co_await dg->AsyncSendTo(make_vless_addr(), AsU8Span(p));
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(VlessDgramErr, ReceiveHeadEof)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     auto dg = std::make_shared<Vless::Dgram<>>(raw);
                     Vless::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(VlessDgramErr, ReceiveBadAtyp)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x99};
                     auto dg = std::make_shared<Vless::Dgram<>>(raw);
                     Vless::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::bad_message);
                 });
    }

    TEST(VlessDgramErr, ReceiveDomainTruncated)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x02, 0x05, 'a', 'b'}; // VLESS domain = 0x02
                     auto dg = std::make_shared<Vless::Dgram<>>(raw);
                     Vless::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(VlessDgramErr, ReceivePortEof)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x01, 1, 2, 3, 4};
                     auto dg = std::make_shared<Vless::Dgram<>>(raw);
                     Vless::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(VlessDgramErr, ReceivePayloadIoError)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x01, 1, 2, 3, 4, 0x00, 0x50};
                     raw->ReadFailAt = 4; // 第 4 次读取 = 载荷读取
                     auto dg = std::make_shared<Vless::Dgram<>>(raw);
                     Vless::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(VlessDgramErr, ReceivePayloadEof)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x01, 1, 2, 3, 4, 0x00, 0x50};
                     auto dg = std::make_shared<Vless::Dgram<>>(raw);
                     Vless::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::unexpected_eof);
                 });
    }

    TEST(VlessDgramErr, ReceiveIpv6Truncated)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     std::vector<std::uint8_t> wire{0x03}; // VLESS ipv6 = 0x03
                     wire.insert(wire.end(), 8, 0x21);
                     raw->ToRead = wire;
                     auto dg = std::make_shared<Vless::Dgram<>>(raw);
                     Vless::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(VlessDgramErr, ClosedStateOperations)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     auto dg = std::make_shared<Vless::Dgram<>>(raw);
                     dg->Close();
                     const std::string p = "x";
                     const auto serr = co_await dg->AsyncSendTo(make_vless_addr(), AsU8Span(p));
                     EXPECT_EQ(serr, Error::io_error);
                     Vless::Address src;
                     std::vector<std::uint8_t> out;
                     const auto rerr = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(rerr, Error::io_error);
                 });
    }

    // ──────────────────────────── TUIC ────────────────────────────

    /// tuic 帧头：Ver(0x04) Cmd(0x07) AssocID(4 LE) PktID(4 LE)（10 字节，head[9] = ATYP）
    auto make_tuic_head(std::uint8_t atyp) -> std::array<std::uint8_t, 10>
    {
        std::array<std::uint8_t, 10> head{0x04, 0x07, 0, 0, 0, 0, 0, 0, 0, atyp};
        return head;
    }

    TEST(TuicDgramErr, SendWriteFail)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->FailNextWrite = true;
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     const std::string p = "x";
                     const auto err = co_await dg->AsyncSendTo(make_tuic_addr(), AsU8Span(p));
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(TuicDgramErr, ReceiveHeadEof)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     Tuic::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::unexpected_eof);
                 });
    }

    TEST(TuicDgramErr, ReceiveShortHead)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x04, 0x07, 0, 0, 0};
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     Tuic::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::unexpected_eof);
                 });
    }

    TEST(TuicDgramErr, ReceiveBadVersion)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x05, 0x07, 0, 0, 0, 0, 0, 0, 0, 0x01};
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     Tuic::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::bad_message);
                 });
    }

    TEST(TuicDgramErr, ReceiveBadCommand)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x04, 0x06, 0, 0, 0, 0, 0, 0, 0, 0x01};
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     Tuic::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::bad_message);
                 });
    }

    TEST(TuicDgramErr, ReceiveBadAtyp)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     const auto head = make_tuic_head(0x99);
                     raw->ToRead.assign(head.begin(), head.end());
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     Tuic::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::bad_message);
                 });
    }

    TEST(TuicDgramErr, ReceiveDomainTruncated)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x04, 0x07, 0, 0, 0, 0, 0, 0, 0, 0x03, 0x05, 'a', 'b'};
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     Tuic::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(TuicDgramErr, ReceivePortEof)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x04, 0x07, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4};
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     Tuic::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::unexpected_eof);
                 });
    }

    TEST(TuicDgramErr, ReceivePayloadIoError)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x04, 0x07, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50};
                     raw->ReadFailAt = 4; // 第 4 次读取 = 载荷读取
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     Tuic::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(TuicDgramErr, ReceivePayloadEof)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x04, 0x07, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50};
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     Tuic::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::unexpected_eof);
                 });
    }

    TEST(TuicDgramErr, ReceiveIpv6Truncated)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     const auto head = make_tuic_head(0x04);
                     std::vector<std::uint8_t> wire(head.begin(), head.end());
                     wire.insert(wire.end(), 8, 0x21);
                     raw->ToRead = wire;
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     Tuic::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(TuicDgramErr, ClosedStateOperations)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     auto dg = std::make_shared<Tuic::Dgram<>>(raw);
                     dg->Close();
                     const std::string p = "x";
                     const auto serr = co_await dg->AsyncSendTo(make_tuic_addr(), AsU8Span(p));
                     EXPECT_EQ(serr, Error::io_error);
                     Tuic::Address src;
                     std::vector<std::uint8_t> out;
                     const auto rerr = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(rerr, Error::unexpected_eof);
                 });
    }

    // ──────────────────────────── Hysteria2 ────────────────────────────

    /// hysteria2 帧头：Kind(0x02) SessionID(4 LE) PacketID(4 LE)（9 字节，head[8] = ATYP）
    auto make_hy2_head(std::uint8_t atyp) -> std::array<std::uint8_t, 9>
    {
        std::array<std::uint8_t, 9> head{0x02, 0, 0, 0, 0, 0, 0, 0, atyp};
        return head;
    }

    TEST(Hysteria2DgramErr, SendWriteFail)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->FailNextWrite = true;
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     const std::string p = "x";
                     const auto err = co_await dg->AsyncSendTo(make_hy2_addr(), AsU8Span(p));
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(Hysteria2DgramErr, ReceiveHeadEof)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::unexpected_eof);
                 });
    }

    TEST(Hysteria2DgramErr, ReceiveShortHead)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x02, 0, 0, 0, 0};
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::unexpected_eof);
                 });
    }

    TEST(Hysteria2DgramErr, ReceiveBadKind)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x01, 0, 0, 0, 0, 0, 0, 0, 0x01};
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::bad_message);
                 });
    }

    TEST(Hysteria2DgramErr, ReceiveBadAtyp)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     const auto head = make_hy2_head(0x99);
                     raw->ToRead.assign(head.begin(), head.end());
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::bad_message);
                 });
    }

    TEST(Hysteria2DgramErr, ReceiveDomainTruncated)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x02, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x05, 'a', 'b'};
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(Hysteria2DgramErr, ReceivePortEof)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x02, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4};
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::unexpected_eof);
                 });
    }

    TEST(Hysteria2DgramErr, ReceivePayloadIoError)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x02, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50};
                     raw->ReadFailAt = 4; // 第 4 次读取 = 载荷读取
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(Hysteria2DgramErr, ReceivePayloadEof)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0x02, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50};
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::unexpected_eof);
                 });
    }

    TEST(Hysteria2DgramErr, ReceiveIpv6Truncated)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     const auto head = make_hy2_head(0x03); // hysteria2 ipv6 = 0x03
                     std::vector<std::uint8_t> wire(head.begin(), head.end());
                     wire.insert(wire.end(), 8, 0x21);
                     raw->ToRead = wire;
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(Hysteria2DgramErr, ClosedStateOperations)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     dg->Close();
                     const std::string p = "x";
                     const auto serr = co_await dg->AsyncSendTo(make_hy2_addr(), AsU8Span(p));
                     EXPECT_EQ(serr, Error::io_error);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto rerr = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(rerr, Error::unexpected_eof);
                 });
    }

    // ──────────────────────────── Shadowsocks 2022 ────────────────────────────

    /// ss2022 UDP 会话密钥（16 字节）
    auto make_ss_key() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> key{};
        for (std::size_t i = 0; i < key.size(); ++i)
        {
            key[i] = static_cast<std::uint8_t>(0xA0 + i);
        }
        return key;
    }

    /// 构造合法长度的 ss2022 UDP 数据报（SeparateHeader 16 + Type 1 + TS 8 +
    /// ATYP + ADDR + PORT 2 + tag 16），SessionID 取自密钥
    auto make_ss_packet(const std::array<std::uint8_t, 16> &key, std::uint8_t Type) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> packet(key.begin(), key.end());
        packet.push_back(Type);
        packet.insert(packet.end(), 8, 0);
        packet.push_back(0x01); // ipv4
        packet.insert(packet.end(), {1, 2, 3, 4, 0x00, 0x50});
        packet.insert(packet.end(), 16, 0); // tag
        return packet;
    }

    TEST(Ss2022DgramErr, SendWriteFail)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->FailNextWrite = true;
                     auto dg = std::make_shared<Shadowsocks2022::Dgram<>>(raw, make_ss_key());
                     const std::string p = "x";
                     const auto err = co_await dg->AsyncSendTo(make_ss_addr(), AsU8Span(p));
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(Ss2022DgramErr, SendPartialWrite)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 单次写入仅返回 8 字节（半包写）→ n != 帧长 → io_error
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->MaxWrite = 8;
                     auto dg = std::make_shared<Shadowsocks2022::Dgram<>>(raw, make_ss_key());
                     const std::string p = "x";
                     const auto err = co_await dg->AsyncSendTo(make_ss_addr(), AsU8Span(p));
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(Ss2022DgramErr, ReceiveIoError)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->FailNextRead = true;
                     auto dg = std::make_shared<Shadowsocks2022::Dgram<>>(raw, make_ss_key());
                     Shadowsocks2022::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(Ss2022DgramErr, ReceiveEof)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     auto dg = std::make_shared<Shadowsocks2022::Dgram<>>(raw, make_ss_key());
                     Shadowsocks2022::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::unexpected_eof);
                 });
    }

    TEST(Ss2022DgramErr, ReceiveTooShort)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 不足最小长度（SeparateHeader + 头部 + tag）→ bad_length
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
                     auto dg = std::make_shared<Shadowsocks2022::Dgram<>>(raw, make_ss_key());
                     Shadowsocks2022::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::bad_length);
                 });
    }

    TEST(Ss2022DgramErr, ReceiveBadSessionId)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // SessionID 前 8 字节与密钥不一致 → bad_auth
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     auto packet = make_ss_packet(make_ss_key(), 0x01);
                     packet[0] ^= 0xFF;
                     raw->ToRead = packet;
                     auto dg = std::make_shared<Shadowsocks2022::Dgram<>>(raw, make_ss_key());
                     Shadowsocks2022::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::bad_auth);
                 });
    }

    TEST(Ss2022DgramErr, ReceiveBadType)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 类型字节非 udp_type(0x01) → bad_message
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     raw->ToRead = make_ss_packet(make_ss_key(), 0x02);
                     auto dg = std::make_shared<Shadowsocks2022::Dgram<>>(raw, make_ss_key());
                     Shadowsocks2022::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::bad_message);
                 });
    }

    TEST(Ss2022DgramErr, ReceiveDomainTruncated)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 域名长度声明 0xFF 但包内无足够字节 → need_more
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     std::vector<std::uint8_t> packet = make_ss_packet(make_ss_key(), 0x01);
                     packet[25] = 0x03; // ATYP = domain
                     packet[26] = 0xFF; // 域名长度声明
                     raw->ToRead = packet;
                     auto dg = std::make_shared<Shadowsocks2022::Dgram<>>(raw, make_ss_key());
                     Shadowsocks2022::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(err, Error::need_more);
                 });
    }

    TEST(Ss2022DgramErr, ClosedStateOperations)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<ProgrammableTransport>(ioc.get_executor());
                     auto dg = std::make_shared<Shadowsocks2022::Dgram<>>(raw, make_ss_key());
                     dg->Close();
                     const std::string p = "x";
                     const auto serr = co_await dg->AsyncSendTo(make_ss_addr(), AsU8Span(p));
                     EXPECT_EQ(serr, Error::io_error);
                     Shadowsocks2022::Address src;
                     std::vector<std::uint8_t> out;
                     const auto rerr = co_await dg->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(rerr, Error::unexpected_eof);
                 });
    }

    // ──────────────────────────── VMess ────────────────────────────

    TEST(VmessDgramErr, NotHandshakenOperations)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 底层 Conn 未握手 → 收发均 not_open
                     auto c = std::make_shared<Vmess::Conn<>>(make_uuid());
                     auto dg = std::make_shared<Vmess::Dgram<>>(c);
                     const std::string p = "x";
                     const auto serr = co_await dg->AsyncSendTo(AsU8Span(p));
                     EXPECT_EQ(serr, Error::not_open);
                     std::vector<std::uint8_t> out;
                     const auto rerr = co_await dg->AsyncReceiveFrom(out);
                     EXPECT_EQ(rerr, Error::not_open);
                 });
    }

    TEST(VmessDgramErr, PeerClosedOperations)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto uuid = make_uuid();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端 AcceptPacket 完成握手后关闭 → 客户端收发失败
                     net::experimental::channel<void(boost::system::error_code)> server_closed(
                         ioc.get_executor(), 1);
                     net::co_spawn(ioc.get_executor(),
                                   [&]() -> net::awaitable<void>
                                   {
                                       Vmess::ServerConfig cfg;
                                       cfg.uuid = uuid;
                                       auto [err, req, dg] = co_await Vmess::AcceptPacket(
                                           std::make_shared<MemoryStream>(std::move(b)), cfg);
                                       EXPECT_EQ(err, Error::none);
                                       (void)req;
                                       dg->Close();
                                       server_closed.try_send(boost::system::error_code{});
                                   },
                                   net::detached);

                     Vmess::ClientConfig cfg;
                     cfg.uuid = uuid;
                     auto [herr, dg] = co_await Vmess::ConnectPacket(
                         std::make_shared<MemoryStream>(std::move(a)), cfg, make_vmess_addr());
                     EXPECT_EQ(herr, Error::none);
                     co_await server_closed.async_receive(net::use_awaitable);

                     const std::string p = "x";
                     const auto serr = co_await dg->AsyncSendTo(AsU8Span(p));
                     EXPECT_EQ(serr, Error::io_error);
                     std::vector<std::uint8_t> out;
                     const auto rerr = co_await dg->AsyncReceiveFrom(out);
                     EXPECT_EQ(rerr, Error::unexpected_eof);
                 });
    }

} // namespace
