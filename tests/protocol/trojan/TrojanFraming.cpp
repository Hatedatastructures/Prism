/**
 * @file TrojanFraming.cpp
 * @brief Trojan 协议格式编解码单元测试
 * @details 测试 parse_credential、parse_crlf、parse_cmd_atyp、build_udp_pkt、parse_udp_pkt。
 */

#include <prism/memory.hpp>
#include <prism/protocol/trojan/framing.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/fault.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>


#include <gtest/gtest.h>

namespace
{
    TEST(TrojanFraming, ParseCredentialValid)
    {
        // 56 hex chars
        const std::string hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        std::array<std::uint8_t, 56> buf{};
        std::memcpy(buf.data(), hex.data(), 56);

        auto [ec, cred] = psm::protocol::trojan::format::parse_credential(buf);
        EXPECT_TRUE(ec == psm::fault::code::success) << "credential valid: success";
        EXPECT_TRUE(std::memcmp(cred.data(), hex.data(), 56) == 0) << "credential valid: content match";
    }

    TEST(TrojanFraming, ParseCredentialShort)
    {
        std::array<std::uint8_t, 10> short_buf{};
        auto [ec, cred] = psm::protocol::trojan::format::parse_credential(short_buf);
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "credential short: bad_message";
    }

    TEST(TrojanFraming, ParseCredentialInvalidChar)
    {
        std::array<std::uint8_t, 56> buf{};
        std::memset(buf.data(), 'a', 56);
        buf[10] = 'g'; // invalid hex
        auto [ec, cred] = psm::protocol::trojan::format::parse_credential(buf);
        EXPECT_TRUE(ec == psm::fault::code::protocol_error) << "credential invalid char: protocol_error";
    }

    TEST(TrojanFraming, ParseCrlfValid)
    {
        const std::uint8_t buf[] = {'\r', '\n'};
        auto ec = psm::protocol::trojan::format::parse_crlf(buf);
        EXPECT_TRUE(ec == psm::fault::code::success) << "crlf valid: success";
    }

    TEST(TrojanFraming, ParseCrlfShort)
    {
        const std::uint8_t buf[] = {'\r'};
        auto ec = psm::protocol::trojan::format::parse_crlf(buf);
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "crlf short: bad_message";
    }

    TEST(TrojanFraming, ParseCrlfWrong)
    {
        const std::uint8_t buf[] = {'\n', '\r'};
        auto ec = psm::protocol::trojan::format::parse_crlf(buf);
        EXPECT_TRUE(ec == psm::fault::code::protocol_error) << "crlf wrong: protocol_error";
    }

    TEST(TrojanFraming, ParseCmdAtypValid)
    {
        const std::uint8_t buf[] = {0x01, 0x03}; // connect + domain
        auto [ec, result] = psm::protocol::trojan::format::parse_cmd_atyp(buf);
        EXPECT_TRUE(ec == psm::fault::code::success) << "cmd_atyp valid: success";
        EXPECT_TRUE(result.cmd == psm::protocol::trojan::command::connect) << "cmd_atyp cmd=connect";
        EXPECT_TRUE(result.atyp == psm::protocol::trojan::address_type::domain) << "cmd_atyp atyp=domain";
    }

    TEST(TrojanFraming, ParseCmdAtypShort)
    {
        const std::uint8_t buf[] = {0x01};
        auto [ec, result] = psm::protocol::trojan::format::parse_cmd_atyp(buf);
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "cmd_atyp short: bad_message";
    }

    TEST(TrojanFraming, BuildParseUdpIpv4)
    {
        psm::memory::vector<std::byte> out(psm::memory::current_resource());
        psm::protocol::trojan::format::udp_routed frame;
        frame.destination_address = psm::protocol::common::ipv4_address{{{192, 168, 1, 1}}};
        frame.destination_port = 443;

        const std::byte payload[] = {std::byte{0xAA}, std::byte{0xBB}};
        auto ec = psm::protocol::trojan::format::build_udp_pkt(frame, payload, out);
        EXPECT_TRUE(ec == psm::fault::code::success) << "build udp ipv4: success";

        auto [pec, result] = psm::protocol::trojan::format::parse_udp_pkt(out);
        EXPECT_TRUE(pec == psm::fault::code::success) << "parse udp ipv4: success";
        EXPECT_TRUE(result.destination_port == 443) << "parse udp ipv4: port=443";
        EXPECT_TRUE(result.payload_size == 2) << "parse udp ipv4: payload_size=2";
    }

    TEST(TrojanFraming, BuildParseUdpIpv6)
    {
        psm::memory::vector<std::byte> out(psm::memory::current_resource());
        psm::protocol::trojan::format::udp_routed frame;
        psm::protocol::common::ipv6_address addr{};
        addr.bytes = {{0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1}}; // ::1
        frame.destination_address = addr;
        frame.destination_port = 8080;

        const std::byte payload[] = {std::byte{0xCC}};
        auto ec = psm::protocol::trojan::format::build_udp_pkt(frame, payload, out);
        EXPECT_TRUE(ec == psm::fault::code::success) << "build udp ipv6: success";

        auto [pec, result] = psm::protocol::trojan::format::parse_udp_pkt(out);
        EXPECT_TRUE(pec == psm::fault::code::success) << "parse udp ipv6: success";
        EXPECT_TRUE(result.destination_port == 8080) << "parse udp ipv6: port=8080";
        EXPECT_TRUE(result.payload_size == 1) << "parse udp ipv6: payload_size=1";
    }

    TEST(TrojanFraming, BuildParseUdpDomain)
    {
        psm::memory::vector<std::byte> out(psm::memory::current_resource());
        psm::protocol::trojan::format::udp_routed frame;
        psm::protocol::common::domain_address domain{};
        const char name[] = "example.com";
        domain.length = 11;
        std::memcpy(domain.value.data(), name, 11);
        frame.destination_address = domain;
        frame.destination_port = 443;

        const std::byte payload[] = {std::byte{0xDD}, std::byte{0xEE}};
        auto ec = psm::protocol::trojan::format::build_udp_pkt(frame, payload, out);
        EXPECT_TRUE(ec == psm::fault::code::success) << "build udp domain: success";

        auto [pec, result] = psm::protocol::trojan::format::parse_udp_pkt(out);
        EXPECT_TRUE(pec == psm::fault::code::success) << "parse udp domain: success";
        EXPECT_TRUE(result.destination_port == 443) << "parse udp domain: port=443";
        EXPECT_TRUE(result.payload_size == 2) << "parse udp domain: payload_size=2";
    }

    TEST(TrojanFraming, ParseUdpTooShort)
    {
        std::byte buf[5]{};
        auto [ec, result] = psm::protocol::trojan::format::parse_udp_pkt(buf);
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "parse udp short: bad_message";
    }

    TEST(TrojanFraming, ParseUdpBadCrlf)
    {
        // ATYP(1) + IPv4(4) + PORT(2) + Length(2) + bad CRLF(2) = 11 bytes
        std::byte buf[13]{};
        buf[0] = std::byte{0x01}; // IPv4
        // bytes 1-4 = IPv4 addr (zeros)
        // bytes 5-6 = port (zeros)
        // bytes 7-8 = length (0)
        buf[9] = std::byte{'X'}; // wrong CRLF
        buf[10] = std::byte{'Y'};
        auto [ec, result] = psm::protocol::trojan::format::parse_udp_pkt(buf);
        EXPECT_TRUE(ec == psm::fault::code::protocol_error) << "parse udp bad crlf: protocol_error";
    }

    TEST(TrojanFraming, BuildUdpEmptyPayload)
    {
        psm::memory::vector<std::byte> out(psm::memory::current_resource());
        psm::protocol::trojan::format::udp_routed frame;
        frame.destination_address = psm::protocol::common::ipv4_address{{{127, 0, 0, 1}}};
        frame.destination_port = 80;

        std::span<const std::byte> empty_payload;
        auto ec = psm::protocol::trojan::format::build_udp_pkt(frame, empty_payload, out);
        EXPECT_TRUE(ec == psm::fault::code::success) << "build udp empty payload: success";

        auto [pec, result] = psm::protocol::trojan::format::parse_udp_pkt(out);
        EXPECT_TRUE(pec == psm::fault::code::success) << "parse udp empty payload: success";
        EXPECT_TRUE(result.payload_size == 0) << "parse udp empty payload: payload_size=0";
    }

} // namespace
