/**
 * @file TrojanConnPure2.cpp
 * @brief Trojan conn 纯函数单元测试
 * @details 测试 trojan::conn 中的纯同步函数：validate_command、
 *          parse_address_from_buffer、verify_credential、parse_request_target。
 *          通过 #include 源文件覆盖编译行。
 */

#include <prism/core/core.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/proto/protocol/trojan/constants.hpp>


#include <gtest/gtest.h>

// #include 源文件增加覆盖率计数
#include "../../src/prism/proto/protocol/trojan/conn.cpp"

namespace
{
    using namespace psm::protocol::trojan;
    using psm::protocol::form;

    // ─── validate_command ───────────────────────────

    TEST(TrojanConnPure2, ValidateCommandConnect)
    {
        config cfg;
        cfg.enable_tcp = true;
        cfg.enable_udp = true;

        auto [ec, f] = validate_command(command::connect, cfg);
        EXPECT_TRUE(ec == psm::fault::code::success) << "validate: connect -> success";
        EXPECT_TRUE(f == form::stream) << "validate: connect -> stream";
    }

    TEST(TrojanConnPure2, ValidateCommandConnectDisabled)
    {
        config cfg;
        cfg.enable_tcp = false;
        cfg.enable_udp = true;

        auto [ec, f] = validate_command(command::connect, cfg);
        EXPECT_TRUE(ec == psm::fault::code::forbidden) << "validate: connect disabled -> forbidden";
    }

    TEST(TrojanConnPure2, ValidateCommandUdp)
    {
        config cfg;
        cfg.enable_tcp = true;
        cfg.enable_udp = true;

        auto [ec, f] = validate_command(command::udp_associate, cfg);
        EXPECT_TRUE(ec == psm::fault::code::success) << "validate: udp -> success";
        EXPECT_TRUE(f == form::datagram) << "validate: udp -> datagram";
    }

    TEST(TrojanConnPure2, ValidateCommandUdpDisabled)
    {
        config cfg;
        cfg.enable_tcp = true;
        cfg.enable_udp = false;

        auto [ec, f] = validate_command(command::udp_associate, cfg);
        EXPECT_TRUE(ec == psm::fault::code::forbidden) << "validate: udp disabled -> forbidden";
    }

    TEST(TrojanConnPure2, ValidateCommandMux)
    {
        config cfg;
        auto [ec, f] = validate_command(command::mux, cfg);
        EXPECT_TRUE(ec == psm::fault::code::success) << "validate: mux -> success";
        EXPECT_TRUE(f == form::stream) << "validate: mux -> stream";
    }

    TEST(TrojanConnPure2, ValidateCommandUnknown)
    {
        config cfg;
        auto [ec, f] = validate_command(static_cast<command>(0xFF), cfg);
        EXPECT_TRUE(ec == psm::fault::code::unsupported_command) << "validate: unknown -> unsupported";
    }

    // ─── parse_address_from_buffer: IPv4 ────────────

    TEST(TrojanConnPure2, ParseAddressIPv4)
    {
        std::array<std::uint8_t, 4> ip_bytes = {127, 0, 0, 1};
        std::span<const std::uint8_t> buf(ip_bytes.data(), 4);

        auto [ec, addr, size] = parse_address_from_buffer(buf, 0, address_type::ipv4);
        EXPECT_TRUE(ec == psm::fault::code::success) << "parse addr ipv4: success";
        EXPECT_TRUE(size == 4) << "parse addr ipv4: size=4";
    }

    TEST(TrojanConnPure2, ParseAddressIPv4Truncated)
    {
        std::array<std::uint8_t, 2> ip_bytes = {127, 0};
        std::span<const std::uint8_t> buf(ip_bytes.data(), 2);

        auto [ec, addr, size] = parse_address_from_buffer(buf, 0, address_type::ipv4);
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "parse addr ipv4: truncated -> bad_message";
    }

    // ─── parse_address_from_buffer: IPv6 ────────────

    TEST(TrojanConnPure2, ParseAddressIPv6)
    {
        std::array<std::uint8_t, 16> ip6_bytes{};
        ip6_bytes[15] = 1; // ::1
        std::span<const std::uint8_t> buf(ip6_bytes.data(), 16);

        auto [ec, addr, size] = parse_address_from_buffer(buf, 0, address_type::ipv6);
        EXPECT_TRUE(ec == psm::fault::code::success) << "parse addr ipv6: success";
        EXPECT_TRUE(size == 16) << "parse addr ipv6: size=16";
    }

    TEST(TrojanConnPure2, ParseAddressIPv6Truncated)
    {
        std::array<std::uint8_t, 8> ip6_bytes{};
        std::span<const std::uint8_t> buf(ip6_bytes.data(), 8);

        auto [ec, addr, size] = parse_address_from_buffer(buf, 0, address_type::ipv6);
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "parse addr ipv6: truncated -> bad_message";
    }

    // ─── parse_address_from_buffer: Domain ──────────

    TEST(TrojanConnPure2, ParseAddressDomain)
    {
        std::array<std::uint8_t, 16> buf{};
        buf[0] = 11; // "example.com"
        const char *domain = "example.com";
        std::memcpy(buf.data() + 1, domain, 11);

        auto [ec, addr, size] = parse_address_from_buffer(buf, 0, address_type::domain);
        EXPECT_TRUE(ec == psm::fault::code::success) << "parse addr domain: success";
        EXPECT_TRUE(size == 12) << "parse addr domain: size=12 (1+11)";
    }

    TEST(TrojanConnPure2, ParseAddressDomainTruncated)
    {
        std::array<std::uint8_t, 1> buf{};
        buf[0] = 20;

        auto [ec, addr, size] = parse_address_from_buffer(buf, 0, address_type::domain);
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "parse addr domain: truncated -> bad_message";
    }

    TEST(TrojanConnPure2, ParseAddressUnknown)
    {
        std::array<std::uint8_t, 4> buf{};
        auto [ec, addr, size] = parse_address_from_buffer(buf, 0, static_cast<address_type>(0xFF));
        EXPECT_TRUE(ec == psm::fault::code::unsupported_address) << "parse addr: unknown atyp -> unsupported";
    }

    // ─── parse_address_from_buffer: offset ──────────

    TEST(TrojanConnPure2, ParseAddressWithOffset)
    {
        std::array<std::uint8_t, 8> buf{};
        buf[4] = 127; buf[5] = 0; buf[6] = 0; buf[7] = 1;

        auto [ec, addr, size] = parse_address_from_buffer(buf, 4, address_type::ipv4);
        EXPECT_TRUE(ec == psm::fault::code::success) << "parse addr offset: success";
        EXPECT_TRUE(size == 4) << "parse addr offset: size=4";
    }

    // ─── verify_credential ──────────────────────────

    TEST(TrojanConnPure2, VerifyCredentialValid)
    {
        std::array<std::uint8_t, 58> data{};
        for (std::size_t i = 0; i < 56; ++i) data[i] = 'a';
        data[56] = '\r';
        data[57] = '\n';

        std::array<char, 56> credential{};
        auto ec = verify_credential(data, nullptr, credential);
        EXPECT_TRUE(ec == psm::fault::code::success) << "verify cred: valid hex + CRLF -> success";
    }

    TEST(TrojanConnPure2, VerifyCredentialVerifierRejects)
    {
        std::array<std::uint8_t, 58> data{};
        for (std::size_t i = 0; i < 56; ++i) data[i] = 'a';
        data[56] = '\r';
        data[57] = '\n';

        std::array<char, 56> credential{};
        auto verifier = [](std::string_view) -> bool { return false; };
        auto ec = verify_credential(data, verifier, credential);
        EXPECT_TRUE(ec == psm::fault::code::auth_failed) << "verify cred: verifier rejects -> auth_failed";
    }

    TEST(TrojanConnPure2, VerifyCredentialVerifierAccepts)
    {
        std::array<std::uint8_t, 58> data{};
        for (std::size_t i = 0; i < 56; ++i) data[i] = 'a';
        data[56] = '\r';
        data[57] = '\n';

        std::array<char, 56> credential{};
        auto verifier = [](std::string_view) -> bool { return true; };
        auto ec = verify_credential(data, verifier, credential);
        EXPECT_TRUE(ec == psm::fault::code::success) << "verify cred: verifier accepts -> success";
    }

    TEST(TrojanConnPure2, VerifyCredentialBadCRLF)
    {
        std::array<std::uint8_t, 58> data{};
        for (std::size_t i = 0; i < 56; ++i) data[i] = 'a';
        data[56] = 'X';
        data[57] = 'Y';

        std::array<char, 56> credential{};
        auto ec = verify_credential(data, nullptr, credential);
        EXPECT_TRUE(ec != psm::fault::code::success) << "verify cred: bad CRLF -> error";
    }

    // ─── parse_request_target: IPv4 + Port + CRLF ──

    TEST(TrojanConnPure2, ParseRequestTargetIPv4)
    {
        std::array<std::uint8_t, 8> buf{};
        buf[0] = 127; buf[1] = 0; buf[2] = 0; buf[3] = 1;
        buf[4] = 0x00; buf[5] = 0x50; // port 80
        buf[6] = '\r'; buf[7] = '\n';

        auto [ec, addr, port] = parse_request_target(buf, 0, address_type::ipv4, 8);
        EXPECT_TRUE(ec == psm::fault::code::success) << "parse target ipv4: success";
        EXPECT_TRUE(port == 80) << "parse target ipv4: port=80";
    }

    TEST(TrojanConnPure2, ParseRequestTargetTruncatedPort)
    {
        std::array<std::uint8_t, 4> buf{};
        buf[0] = 127; buf[1] = 0; buf[2] = 0; buf[3] = 1;

        auto [ec, addr, port] = parse_request_target(buf, 0, address_type::ipv4, 4);
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "parse target: truncated port -> bad_message";
    }

    TEST(TrojanConnPure2, ParseRequestTargetMissingCRLF)
    {
        std::array<std::uint8_t, 6> buf{};
        buf[0] = 127; buf[1] = 0; buf[2] = 0; buf[3] = 1;
        buf[4] = 0x00; buf[5] = 0x50;

        auto [ec, addr, port] = parse_request_target(buf, 0, address_type::ipv4, 6);
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "parse target: missing CRLF -> bad_message";
    }

} // namespace
