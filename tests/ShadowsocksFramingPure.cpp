/**
 * @file ShadowsocksFramingPure.cpp
 * @brief Shadowsocks framing 纯函数测试
 * @details 测试 parse_addr_port/decode_psk/resolve_method 全分支
 */

#include <prism/memory.hpp>
#include <prism/protocol/shadowsocks/framing.hpp>
#include <prism/protocol/shadowsocks/constants.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    using psm::protocol::shadowsocks::format::parse_addr_port;
    using psm::protocol::shadowsocks::format::decode_psk;
    using psm::protocol::shadowsocks::format::resolve_method;
    using psm::protocol::shadowsocks::format::keysalt_len;
    using psm::protocol::shadowsocks::format::addr_parse_result;
    using psm::protocol::shadowsocks::cipher_method;

    void TestParseAddrPortEmpty(TestRunner &runner)
    {
        auto [ec, result] = parse_addr_port({});
        runner.Check(ec == psm::fault::code::bad_message, "parse_addr_port: empty buffer");
    }

    void TestParseAddrPortIPv4(TestRunner &runner)
    {
        // ATYP=0x01, 127.0.0.1, port=80 (0x0050)
        std::array<std::uint8_t, 7> buf = {0x01, 127, 0, 0, 1, 0x00, 0x50};
        auto [ec, result] = parse_addr_port(buf);
        runner.Check(ec == psm::fault::code::success, "parse_addr_port IPv4: success");
        runner.Check(result.port == 80, "parse_addr_port IPv4: port=80");
        runner.Check(result.offset == 7, "parse_addr_port IPv4: offset=7");

        auto *ipv4 = std::get_if<psm::protocol::common::ipv4_address>(&result.addr);
        runner.Check(ipv4 != nullptr, "parse_addr_port IPv4: variant");
        runner.Check(ipv4->bytes[0] == 127, "parse_addr_port IPv4: byte[0]=127");
        runner.Check(ipv4->bytes[3] == 1, "parse_addr_port IPv4: byte[3]=1");
    }

    void TestParseAddrPortIPv4Truncated(TestRunner &runner)
    {
        std::array<std::uint8_t, 4> buf = {0x01, 127, 0, 0};
        auto [ec, result] = parse_addr_port(buf);
        runner.Check(ec == psm::fault::code::bad_message, "parse_addr_port IPv4: truncated");
    }

    void TestParseAddrPortDomain(TestRunner &runner)
    {
        // ATYP=0x03, len=11, "example.com", port=443
        std::array<std::uint8_t, 16> buf = {
            0x03, 11,
            'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
            0x01, 0xBB};
        auto [ec, result] = parse_addr_port(buf);
        runner.Check(ec == psm::fault::code::success, "parse_addr_port domain: success");
        runner.Check(result.port == 443, "parse_addr_port domain: port=443");
        runner.Check(result.offset == 15, "parse_addr_port domain: offset=15");

        auto *domain = std::get_if<psm::protocol::common::domain_address>(&result.addr);
        runner.Check(domain != nullptr, "parse_addr_port domain: variant");
        runner.Check(domain->length == 11, "parse_addr_port domain: len=11");
    }

    void TestParseAddrPortDomainTruncated(TestRunner &runner)
    {
        std::array<std::uint8_t, 1> buf = {0x03};
        auto [ec, result] = parse_addr_port(buf);
        runner.Check(ec == psm::fault::code::bad_message, "parse_addr_port domain: truncated");
    }

    void TestParseAddrPortIPv6(TestRunner &runner)
    {
        // ATYP=0x04, ::1 (15 zeros + 1), port=4433
        std::array<std::uint8_t, 19> buf{};
        buf[0] = 0x04;
        buf[16] = 1;
        buf[17] = 0x11;
        buf[18] = 0x51;
        auto [ec, result] = parse_addr_port(buf);
        runner.Check(ec == psm::fault::code::success, "parse_addr_port IPv6: success");
        runner.Check(result.port == 4433, "parse_addr_port IPv6: port=4433");
        runner.Check(result.offset == 19, "parse_addr_port IPv6: offset=19");

        auto *ipv6 = std::get_if<psm::protocol::common::ipv6_address>(&result.addr);
        runner.Check(ipv6 != nullptr, "parse_addr_port IPv6: variant");
        runner.Check(ipv6->bytes[15] == 1, "parse_addr_port IPv6: last byte=1");
    }

    void TestParseAddrPortIPv6Truncated(TestRunner &runner)
    {
        std::array<std::uint8_t, 10> buf{};
        buf[0] = 0x04;
        auto [ec, result] = parse_addr_port(buf);
        runner.Check(ec == psm::fault::code::bad_message, "parse_addr_port IPv6: truncated");
    }

    void TestParseAddrPortUnknownAtyp(TestRunner &runner)
    {
        std::array<std::uint8_t, 10> buf{};
        buf[0] = 0xFF;
        auto [ec, result] = parse_addr_port(buf);
        runner.Check(ec == psm::fault::code::unsupported_address, "parse_addr_port: unknown atyp");
    }

    void TestDecodePskEmpty(TestRunner &runner)
    {
        auto [ec, psk] = decode_psk("");
        runner.Check(ec == psm::fault::code::invalid_psk, "decode_psk: empty -> invalid");
        runner.Check(psk.empty(), "decode_psk: empty -> no data");
    }

    void TestDecodePskInvalidLength(TestRunner &runner)
    {
        // base64 of 8 bytes (invalid PSK length)
        auto [ec, psk] = decode_psk("AAAAAAAAAAA=");
        runner.Check(ec == psm::fault::code::invalid_psk, "decode_psk: 8 bytes -> invalid");
    }

    void TestDecodePsk16Bytes(TestRunner &runner)
    {
        // base64 of 16 zero bytes
        auto [ec, psk] = decode_psk("AAAAAAAAAAAAAAAAAAAAAA==");
        runner.Check(ec == psm::fault::code::success, "decode_psk: 16 bytes -> success");
        runner.Check(psk.size() == 16, "decode_psk: 16 bytes size");
    }

    void TestDecodePsk32Bytes(TestRunner &runner)
    {
        // base64 of 32 zero bytes
        auto [ec, psk] = decode_psk("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        runner.Check(ec == psm::fault::code::success, "decode_psk: 32 bytes -> success");
        runner.Check(psk.size() == 32, "decode_psk: 32 bytes size");
    }

    void TestResolveMethodExplicit(TestRunner &runner)
    {
        runner.Check(resolve_method("2022-blake3-aes-128-gcm", 0) == cipher_method::aes_128_gcm, "resolve: aes-128-gcm");
        runner.Check(resolve_method("2022-blake3-aes-256-gcm", 0) == cipher_method::aes_256_gcm, "resolve: aes-256-gcm");
        runner.Check(resolve_method("2022-blake3-chacha20-poly1305", 0) == cipher_method::chacha20_poly1305, "resolve: chacha20");
    }

    void TestResolveMethodAutoInfer(TestRunner &runner)
    {
        runner.Check(resolve_method("", 16) == cipher_method::aes_128_gcm, "resolve: auto 16B -> aes-128");
        runner.Check(resolve_method("", 32) == cipher_method::aes_256_gcm, "resolve: auto 32B -> aes-256");
        runner.Check(resolve_method("", 0) == cipher_method::aes_256_gcm, "resolve: auto 0B -> aes-256");
    }

    void TestKeysaltLen(TestRunner &runner)
    {
        runner.Check(keysalt_len(cipher_method::aes_128_gcm) == 16, "keysalt: aes-128 = 16");
        runner.Check(keysalt_len(cipher_method::aes_256_gcm) == 32, "keysalt: aes-256 = 32");
        runner.Check(keysalt_len(cipher_method::chacha20_poly1305) == 32, "keysalt: chacha20 = 32");
    }
} // namespace

auto main() -> int
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("ShadowsocksFramingPure");

    TestParseAddrPortEmpty(runner);
    TestParseAddrPortIPv4(runner);
    TestParseAddrPortIPv4Truncated(runner);
    TestParseAddrPortDomain(runner);
    TestParseAddrPortDomainTruncated(runner);
    TestParseAddrPortIPv6(runner);
    TestParseAddrPortIPv6Truncated(runner);
    TestParseAddrPortUnknownAtyp(runner);
    TestDecodePskEmpty(runner);
    TestDecodePskInvalidLength(runner);
    TestDecodePsk16Bytes(runner);
    TestDecodePsk32Bytes(runner);
    TestResolveMethodExplicit(runner);
    TestResolveMethodAutoInfer(runner);
    TestKeysaltLen(runner);

    return runner.Summary();
}
