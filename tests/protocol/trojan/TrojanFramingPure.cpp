/**
 * @file TrojanFramingPure.cpp
 * @brief Trojan framing 纯函数测试
 * @details 测试 parse_credential/parse_crlf/parse_cmd_atyp/build_udp_pkt/parse_udp_pkt 全分支
 */

#include <prism/core/core.hpp>
#include <prism/proto/protocol/trojan/framing.hpp>
#include <prism/proto/protocol/trojan/constants.hpp>
#include <prism/trace/spdlog.hpp>


#include <gtest/gtest.h>

namespace
{
    using psm::protocol::trojan::format::parse_credential;
    using psm::protocol::trojan::format::parse_crlf;
    using psm::protocol::trojan::format::parse_cmd_atyp;
    using psm::protocol::trojan::format::build_udp_pkt;
    using psm::protocol::trojan::format::parse_udp_pkt;
    using psm::protocol::trojan::format::udp_routed;
    using psm::protocol::trojan::command;
    using psm::protocol::trojan::address_type;

    TEST(TrojanFramingPure, ParseCredentialTooShort)
    {
        std::array<std::uint8_t, 10> buf{};
        auto [ec, cred] = parse_credential(buf);
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "credential: too short";
    }

    TEST(TrojanFramingPure, ParseCredentialInvalidChar)
    {
        std::array<std::uint8_t, 56> buf{};
        buf[0] = 'Z'; // not hex
        auto [ec, cred] = parse_credential(buf);
        EXPECT_TRUE(ec == psm::fault::code::protocol_error) << "credential: invalid char";
    }

    TEST(TrojanFramingPure, ParseCredentialValidHex)
    {
        std::array<std::uint8_t, 56> buf{};
        for (int i = 0; i < 56; ++i)
        {
            buf[i] = static_cast<std::uint8_t>('a' + (i % 6));
        }
        auto [ec, cred] = parse_credential(buf);
        EXPECT_TRUE(ec == psm::fault::code::success) << "credential: valid hex -> success";
        EXPECT_TRUE(cred[0] == 'a') << "credential: first char = 'a'";
    }

    TEST(TrojanFramingPure, ParseCredentialValidDigits)
    {
        std::array<std::uint8_t, 56> buf{};
        for (int i = 0; i < 56; ++i)
        {
            buf[i] = static_cast<std::uint8_t>('0' + (i % 10));
        }
        auto [ec, cred] = parse_credential(buf);
        EXPECT_TRUE(ec == psm::fault::code::success) << "credential: all digits -> success";
    }

    TEST(TrojanFramingPure, ParseCredentialValidUpperHex)
    {
        std::array<std::uint8_t, 56> buf{};
        for (int i = 0; i < 56; ++i)
        {
            buf[i] = static_cast<std::uint8_t>('A' + (i % 6));
        }
        auto [ec, cred] = parse_credential(buf);
        EXPECT_TRUE(ec == psm::fault::code::success) << "credential: upper hex -> success";
    }

    TEST(TrojanFramingPure, ParseCrlfTooShort)
    {
        std::array<std::uint8_t, 1> buf{};
        EXPECT_TRUE(parse_crlf(buf) == psm::fault::code::bad_message) << "crlf: too short";
    }

    TEST(TrojanFramingPure, ParseCrlfValid)
    {
        std::array<std::uint8_t, 2> buf{'\r', '\n'};
        EXPECT_TRUE(parse_crlf(buf) == psm::fault::code::success) << "crlf: valid CRLF";
    }

    TEST(TrojanFramingPure, ParseCrlfInvalid)
    {
        std::array<std::uint8_t, 2> buf{'\n', '\r'};
        EXPECT_TRUE(parse_crlf(buf) == psm::fault::code::protocol_error) << "crlf: wrong order";
    }

    TEST(TrojanFramingPure, ParseCmdAtypTooShort)
    {
        std::array<std::uint8_t, 1> buf{};
        auto [ec, result] = parse_cmd_atyp(buf);
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "cmd_atyp: too short";
    }

    TEST(TrojanFramingPure, ParseCmdAtypValid)
    {
        std::array<std::uint8_t, 2> buf{};
        buf[0] = static_cast<std::uint8_t>(command::connect);
        buf[1] = static_cast<std::uint8_t>(address_type::ipv4);
        auto [ec, result] = parse_cmd_atyp(buf);
        EXPECT_TRUE(ec == psm::fault::code::success) << "cmd_atyp: success";
        EXPECT_TRUE(result.cmd == command::connect) << "cmd_atyp: cmd=connect";
        EXPECT_TRUE(result.atyp == address_type::ipv4) << "cmd_atyp: atyp=ipv4";
    }

    TEST(TrojanFramingPure, BuildUdpPktIPv4Roundtrip)
    {
        psm::memory::vector<std::byte> out(psm::memory::current_resource());
        udp_routed frame;
        frame.destination_address = psm::protocol::common::ipv4_address{{{127, 0, 0, 1}}};
        frame.destination_port = 80;
        std::array<std::byte, 3> payload = {std::byte{1}, std::byte{2}, std::byte{3}};

        auto ec = build_udp_pkt(frame, payload, out);
        EXPECT_TRUE(ec == psm::fault::code::success) << "trojan build_udp IPv4: success";
        EXPECT_TRUE(out.size() >= 11) << "trojan build_udp IPv4: min size";

        auto [pec, result] = parse_udp_pkt(out);
        EXPECT_TRUE(pec == psm::fault::code::success) << "trojan roundtrip: parse success";
        EXPECT_TRUE(result.destination_port == 80) << "trojan roundtrip: port=80";
        EXPECT_TRUE(result.payload_size == 3) << "trojan roundtrip: payload_size=3";
    }

    TEST(TrojanFramingPure, BuildUdpPktDomainRoundtrip)
    {
        psm::memory::vector<std::byte> out(psm::memory::current_resource());
        psm::protocol::common::domain_address domain{};
        domain.length = 7;
        const char *name = "test.co";
        std::copy_n(name, 7, domain.value.begin());

        udp_routed frame;
        frame.destination_address = domain;
        frame.destination_port = 443;

        auto ec = build_udp_pkt(frame, {}, out);
        EXPECT_TRUE(ec == psm::fault::code::success) << "trojan build_udp domain: success";

        auto [pec, result] = parse_udp_pkt(out);
        EXPECT_TRUE(pec == psm::fault::code::success) << "trojan domain roundtrip: parse success";
        EXPECT_TRUE(result.destination_port == 443) << "trojan domain roundtrip: port=443";
        EXPECT_TRUE(result.payload_size == 0) << "trojan domain roundtrip: payload_size=0";
    }

    TEST(TrojanFramingPure, BuildUdpPktIPv6Roundtrip)
    {
        psm::memory::vector<std::byte> out(psm::memory::current_resource());
        psm::protocol::common::ipv6_address addr{};
        addr.bytes[15] = 1;

        udp_routed frame;
        frame.destination_address = addr;
        frame.destination_port = 8443;

        auto ec = build_udp_pkt(frame, {}, out);
        EXPECT_TRUE(ec == psm::fault::code::success) << "trojan build_udp IPv6: success";

        auto [pec, result] = parse_udp_pkt(out);
        EXPECT_TRUE(pec == psm::fault::code::success) << "trojan IPv6 roundtrip: parse success";
        EXPECT_TRUE(result.destination_port == 8443) << "trojan IPv6 roundtrip: port=8443";
    }

    TEST(TrojanFramingPure, ParseUdpPktTooShort)
    {
        std::array<std::byte, 5> buf{};
        auto [ec, result] = parse_udp_pkt(buf);
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "trojan parse_udp: too short";
    }

    TEST(TrojanFramingPure, ParseUdpPktUnknownAtyp)
    {
        std::array<std::byte, 12> buf{};
        buf[0] = std::byte{0xFF};
        auto [ec, result] = parse_udp_pkt(buf);
        EXPECT_TRUE(ec == psm::fault::code::unsupported_address) << "trojan parse_udp: unknown atyp";
    }
} // namespace
