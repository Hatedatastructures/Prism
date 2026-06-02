/**
 * @file VlessFramingPure.cpp
 * @brief VLESS framing 纯函数测试
 * @details 测试 parse_request/parse_udp_pkt/build_udp_pkt/make_response 全分支
 */

#include <prism/memory.hpp>
#include <prism/protocol/vless/framing.hpp>
#include <prism/protocol/vless/constants.hpp>
#include <prism/trace/spdlog.hpp>

#include <gtest/gtest.h>

namespace
{
    using psm::protocol::vless::format::parse_request;
    using psm::protocol::vless::format::parse_udp_pkt;
    using psm::protocol::vless::format::build_udp_pkt;
    using psm::protocol::vless::format::make_response;
    using psm::protocol::vless::format::udp_routed;
    using psm::protocol::vless::format::udp_parse_result;
    using psm::protocol::vless::command;
    using psm::protocol::vless::address_type;

    TEST(VlessFramingPure, ParseRequestTooShort)
    {
        std::array<std::uint8_t, 10> buf{};
        auto result = parse_request(buf);
        EXPECT_TRUE(!result.has_value()) << "parse_request: too short -> nullopt";
    }

    TEST(VlessFramingPure, ParseRequestBadVersion)
    {
        std::array<std::uint8_t, 30> buf{};
        buf[0] = 0xFF; // bad version
        auto result = parse_request(buf);
        EXPECT_TRUE(!result.has_value()) << "parse_request: bad version -> nullopt";
    }

    TEST(VlessFramingPure, ParseRequestNonZeroAddnl)
    {
        std::array<std::uint8_t, 30> buf{};
        buf[0] = psm::protocol::vless::version;
        buf[17] = 5; // non-zero additional info length
        auto result = parse_request(buf);
        EXPECT_TRUE(!result.has_value()) << "parse_request: non-zero addnl -> nullopt";
    }

    TEST(VlessFramingPure, ParseRequestBadCommand)
    {
        std::array<std::uint8_t, 30> buf{};
        buf[0] = psm::protocol::vless::version;
        // addnl_len at buf[17] = 0 (default)
        buf[18] = 0x99; // bad command
        auto result = parse_request(buf);
        EXPECT_TRUE(!result.has_value()) << "parse_request: bad cmd -> nullopt";
    }

    TEST(VlessFramingPure, ParseRequestTcpIPv4)
    {
        // Version(1) + UUID(16) + AddnlLen(1)=0 + Cmd(1)=tcp + Port(2)=80 + Atyp(1)=ipv4 + Addr(4)
        std::array<std::uint8_t, 26> buf{};
        buf[0] = psm::protocol::vless::version;
        // UUID: all zeros
        buf[17] = 0; // addnl_len
        buf[18] = static_cast<std::uint8_t>(command::tcp);
        buf[19] = 0x00; buf[20] = 0x50; // port 80
        buf[21] = static_cast<std::uint8_t>(address_type::ipv4);
        buf[22] = 127; buf[23] = 0; buf[24] = 0; buf[25] = 1;

        auto result = parse_request(buf);
        EXPECT_TRUE(result.has_value()) << "parse_request: TCP IPv4 -> has_value";
        EXPECT_TRUE(result->cmd == command::tcp) << "parse_request: cmd=tcp";
        EXPECT_TRUE(result->port == 80) << "parse_request: port=80";
        EXPECT_TRUE(result->transport == psm::protocol::form::stream) << "parse_request: transport=stream";

        auto *ipv4 = std::get_if<psm::protocol::common::ipv4_address>(&result->destination_address);
        EXPECT_TRUE(ipv4 != nullptr) << "parse_request: addr is IPv4";
        EXPECT_TRUE(ipv4->bytes[0] == 127) << "parse_request: IPv4[0]=127";
        EXPECT_TRUE(ipv4->bytes[3] == 1) << "parse_request: IPv4[3]=1";
    }

    TEST(VlessFramingPure, ParseRequestUdpIPv4)
    {
        std::array<std::uint8_t, 26> buf{};
        buf[0] = psm::protocol::vless::version;
        buf[18] = static_cast<std::uint8_t>(command::udp);
        buf[19] = 0x01; buf[20] = 0xBB; // port 443
        buf[21] = static_cast<std::uint8_t>(address_type::ipv4);
        buf[22] = 10; buf[23] = 0; buf[24] = 0; buf[25] = 1;

        auto result = parse_request(buf);
        EXPECT_TRUE(result.has_value()) << "parse_request: UDP IPv4 -> has_value";
        EXPECT_TRUE(result->cmd == command::udp) << "parse_request: cmd=udp";
        EXPECT_TRUE(result->transport == psm::protocol::form::datagram) << "parse_request: transport=datagram";
    }

    TEST(VlessFramingPure, ParseRequestMuxCommand)
    {
        std::array<std::uint8_t, 26> buf{};
        buf[0] = psm::protocol::vless::version;
        buf[18] = static_cast<std::uint8_t>(command::mux);
        buf[19] = 0; buf[20] = 80;
        buf[21] = static_cast<std::uint8_t>(address_type::ipv4);
        buf[22] = 0; buf[23] = 0; buf[24] = 0; buf[25] = 0;

        auto result = parse_request(buf);
        EXPECT_TRUE(result.has_value()) << "parse_request: mux -> has_value";
        EXPECT_TRUE(result->cmd == command::mux) << "parse_request: cmd=mux";
        EXPECT_TRUE(result->transport == psm::protocol::form::stream) << "parse_request: mux -> stream";
    }

    TEST(VlessFramingPure, ParseRequestDomain)
    {
        // Version + UUID + AddnlLen + Cmd + Port + Atyp=domain + Len + "example.com"
        std::vector<std::uint8_t> buf(26 + 11, 0);
        buf[0] = psm::protocol::vless::version;
        buf[17] = 0;
        buf[18] = static_cast<std::uint8_t>(command::tcp);
        buf[19] = 0x01; buf[20] = 0xBB; // port 443
        buf[21] = static_cast<std::uint8_t>(address_type::domain);
        buf[22] = 11; // domain length
        const char *domain = "example.com";
        std::copy(domain, domain + 11, buf.begin() + 23);

        auto result = parse_request(buf);
        EXPECT_TRUE(result.has_value()) << "parse_request: domain -> has_value";

        auto *d = std::get_if<psm::protocol::common::domain_address>(&result->destination_address);
        EXPECT_TRUE(d != nullptr) << "parse_request: addr is domain";
        EXPECT_TRUE(d->length == 11) << "parse_request: domain len=11";
    }

    TEST(VlessFramingPure, ParseRequestIPv6)
    {
        // Version + UUID + AddnlLen + Cmd + Port + Atyp=ipv6 + 16 bytes
        std::array<std::uint8_t, 38> buf{};
        buf[0] = psm::protocol::vless::version;
        buf[17] = 0;
        buf[18] = static_cast<std::uint8_t>(command::tcp);
        buf[19] = 0x11; buf[20] = 0x51; // port 4433
        buf[21] = static_cast<std::uint8_t>(address_type::ipv6);
        buf[37] = 1; // last byte = 1 (::1)

        auto result = parse_request(buf);
        EXPECT_TRUE(result.has_value()) << "parse_request: IPv6 -> has_value";

        auto *ipv6 = std::get_if<psm::protocol::common::ipv6_address>(&result->destination_address);
        EXPECT_TRUE(ipv6 != nullptr) << "parse_request: addr is IPv6";
        EXPECT_TRUE(ipv6->bytes[15] == 1) << "parse_request: IPv6[15]=1";
    }

    TEST(VlessFramingPure, MakeResponse)
    {
        auto resp = make_response();
        EXPECT_TRUE(resp.size() == 2) << "make_response: size=2";
        EXPECT_TRUE(resp[0] == std::byte{psm::protocol::vless::version}) << "make_response: byte[0]=version";
        EXPECT_TRUE(resp[1] == std::byte{0x00}) << "make_response: byte[1]=0x00";
    }

    TEST(VlessFramingPure, BuildUdpPktIPv4Roundtrip)
    {
        psm::memory::vector<std::byte> out(psm::memory::current_resource());
        udp_routed frame;
        frame.destination_address = psm::protocol::common::ipv4_address{{{127, 0, 0, 1}}};
        frame.destination_port = 80;
        std::array<std::byte, 4> payload = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}};

        auto ec = build_udp_pkt(frame, payload, out);
        EXPECT_TRUE(ec == psm::fault::code::success) << "build_udp IPv4: success";

        auto [pec, result] = parse_udp_pkt(out);
        EXPECT_TRUE(pec == psm::fault::code::success) << "roundtrip: parse success";
        EXPECT_TRUE(result.destination_port == 80) << "roundtrip: port=80";
        EXPECT_TRUE(result.payload_offset == 7) << "roundtrip: offset=7";
        EXPECT_TRUE(result.payload_size == 4) << "roundtrip: payload_size=4";
    }

    TEST(VlessFramingPure, BuildUdpPktDomainRoundtrip)
    {
        psm::memory::vector<std::byte> out(psm::memory::current_resource());
        psm::protocol::common::domain_address domain{};
        domain.length = 11;
        const char *name = "example.com";
        std::copy_n(name, 11, domain.value.begin());

        udp_routed frame;
        frame.destination_address = domain;
        frame.destination_port = 443;

        auto ec = build_udp_pkt(frame, {}, out);
        EXPECT_TRUE(ec == psm::fault::code::success) << "build_udp domain: success";

        auto [pec, result] = parse_udp_pkt(out);
        EXPECT_TRUE(pec == psm::fault::code::success) << "domain roundtrip: parse success";
        EXPECT_TRUE(result.destination_port == 443) << "domain roundtrip: port=443";
    }

    TEST(VlessFramingPure, ParseUdpPktTooShort)
    {
        std::array<std::byte, 3> buf{};
        auto [ec, result] = parse_udp_pkt(buf);
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "parse_udp: too short";
    }

    TEST(VlessFramingPure, ParseUdpPktUnknownAtyp)
    {
        std::array<std::byte, 10> buf{};
        buf[0] = std::byte{0xFF};
        auto [ec, result] = parse_udp_pkt(buf);
        EXPECT_TRUE(ec == psm::fault::code::unsupported_address) << "parse_udp: unknown atyp";
    }

    TEST(VlessFramingPure, BuildUdpPktIPv6Roundtrip)
    {
        psm::memory::vector<std::byte> out(psm::memory::current_resource());
        psm::protocol::common::ipv6_address addr{};
        addr.bytes[15] = 1;

        udp_routed frame;
        frame.destination_address = addr;
        frame.destination_port = 4433;

        auto ec = build_udp_pkt(frame, {}, out);
        EXPECT_TRUE(ec == psm::fault::code::success) << "build_udp IPv6: success";

        auto [pec, result] = parse_udp_pkt(out);
        EXPECT_TRUE(pec == psm::fault::code::success) << "IPv6 roundtrip: parse success";
        EXPECT_TRUE(result.destination_port == 4433) << "IPv6 roundtrip: port=4433";
    }
} // namespace
