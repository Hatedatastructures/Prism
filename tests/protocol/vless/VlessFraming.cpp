/**
 * @file VlessFraming.cpp
 * @brief VLESS 协议格式编解码单元测试
 * @details 测试 parse_request、make_response、build_udp_pkt、parse_udp_pkt。
 */

#include <prism/core/core.hpp>
#include <prism/proto/protocol/vless/framing.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/core/core.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>


#include <gtest/gtest.h>

namespace
{
    // Helper: build a VLESS request buffer
    auto build_request(std::uint8_t cmd, std::uint8_t atyp,
                       const std::vector<std::uint8_t> &uuid,
                       const std::vector<std::uint8_t> &addr,
                       std::uint16_t port)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> buf;
        buf.push_back(0x00); // version
        buf.insert(buf.end(), uuid.begin(), uuid.end());
        buf.push_back(0x00); // addnl_len = 0 (plain)
        buf.push_back(cmd);
        buf.push_back(static_cast<std::uint8_t>(port >> 8));
        buf.push_back(static_cast<std::uint8_t>(port & 0xFF));
        buf.push_back(atyp);
        buf.insert(buf.end(), addr.begin(), addr.end());
        return buf;
    }

    TEST(VlessFraming, ParseRequestIpv4)
    {
        std::vector<std::uint8_t> uuid(16, 0x42);
        std::vector<std::uint8_t> addr = {192, 168, 1, 1};
        auto buf = build_request(0x01, 0x01, uuid, addr, 443); // TCP + IPv4

        auto result = psm::protocol::vless::format::parse_request(buf);
        EXPECT_TRUE(result.has_value()) << "parse request ipv4: has_value";
        EXPECT_TRUE(result->port == 443) << "parse request ipv4: port=443";
        EXPECT_TRUE(result->cmd == psm::protocol::vless::command::tcp) << "parse request ipv4: cmd=tcp";
        EXPECT_TRUE(result->uuid[0] == 0x42) << "parse request ipv4: uuid[0]=0x42";
    }

    TEST(VlessFraming, ParseRequestDomain)
    {
        std::vector<std::uint8_t> uuid(16, 0);
        std::vector<std::uint8_t> addr;
        addr.push_back(11); // domain length
        const char domain[] = "example.com";
        addr.insert(addr.end(), domain, domain + 11);
        auto buf = build_request(0x02, 0x02, uuid, addr, 80); // UDP + domain

        auto result = psm::protocol::vless::format::parse_request(buf);
        EXPECT_TRUE(result.has_value()) << "parse request domain: has_value";
        EXPECT_TRUE(result->port == 80) << "parse request domain: port=80";
        EXPECT_TRUE(result->cmd == psm::protocol::vless::command::udp) << "parse request domain: cmd=udp";
    }

    TEST(VlessFraming, ParseRequestIpv6)
    {
        std::vector<std::uint8_t> uuid(16, 0);
        std::vector<std::uint8_t> addr(16, 0);
        addr[15] = 1; // ::1
        auto buf = build_request(0x01, 0x03, uuid, addr, 8080); // TCP + IPv6

        auto result = psm::protocol::vless::format::parse_request(buf);
        EXPECT_TRUE(result.has_value()) << "parse request ipv6: has_value";
        EXPECT_TRUE(result->port == 8080) << "parse request ipv6: port=8080";
    }

    TEST(VlessFraming, ParseRequestMux)
    {
        std::vector<std::uint8_t> uuid(16, 0);
        std::vector<std::uint8_t> addr = {127, 0, 0, 1};
        auto buf = build_request(0x7F, 0x01, uuid, addr, 443); // mux (0x7F) + IPv4

        auto result = psm::protocol::vless::format::parse_request(buf);
        EXPECT_TRUE(result.has_value()) << "parse request mux: has_value";
        EXPECT_TRUE(result->transport == psm::protocol::form::stream) << "parse request mux: transport=stream";
    }

    TEST(VlessFraming, ParseRequestTooShort)
    {
        std::vector<std::uint8_t> buf(10, 0);
        auto result = psm::protocol::vless::format::parse_request(buf);
        EXPECT_TRUE(!result.has_value()) << "parse request short: nullopt";
    }

    TEST(VlessFraming, ParseRequestBadVersion)
    {
        std::vector<std::uint8_t> buf(30, 0);
        buf[0] = 0x01; // wrong version
        auto result = psm::protocol::vless::format::parse_request(buf);
        EXPECT_TRUE(!result.has_value()) << "parse request bad version: nullopt";
    }

    TEST(VlessFraming, ParseRequestNonZeroAddnl)
    {
        std::vector<std::uint8_t> uuid(16, 0);
        std::vector<std::uint8_t> addr = {127, 0, 0, 1};
        auto buf = build_request(0x01, 0x01, uuid, addr, 443);
        buf[17] = 0x05; // addnl_len = 5 (non-zero -> reject)
        auto result = psm::protocol::vless::format::parse_request(buf);
        EXPECT_TRUE(!result.has_value()) << "parse request non-zero addnl: nullopt";
    }

    TEST(VlessFraming, ParseRequestBadCmd)
    {
        std::vector<std::uint8_t> uuid(16, 0);
        std::vector<std::uint8_t> addr = {127, 0, 0, 1};
        auto buf = build_request(0xFF, 0x01, uuid, addr, 443); // invalid cmd
        auto result = psm::protocol::vless::format::parse_request(buf);
        EXPECT_TRUE(!result.has_value()) << "parse request bad cmd: nullopt";
    }

    TEST(VlessFraming, MakeResponse)
    {
        auto resp = psm::protocol::vless::format::make_response();
        EXPECT_TRUE(resp[0] == std::byte{0x00}) << "make_response byte 0 = 0x00";
        EXPECT_TRUE(resp[1] == std::byte{0x00}) << "make_response byte 1 = 0x00";
        EXPECT_TRUE(resp.size() == 2) << "make_response size = 2";
    }

    TEST(VlessFraming, BuildParseUdpIpv4)
    {
        psm::memory::vector<std::byte> out(psm::memory::current_resource());
        psm::protocol::vless::format::udp_routed frame;
        frame.destination_address = psm::protocol::common::ipv4_address{{{10, 0, 0, 1}}};
        frame.destination_port = 443;

        const std::byte payload[] = {std::byte{0x01}, std::byte{0x02}};
        auto ec = psm::protocol::vless::format::build_udp_pkt(frame, payload, out);
        EXPECT_TRUE(ec == psm::fault::code::success) << "build vless udp ipv4: success";

        auto [pec, result] = psm::protocol::vless::format::parse_udp_pkt(out);
        EXPECT_TRUE(pec == psm::fault::code::success) << "parse vless udp ipv4: success";
        EXPECT_TRUE(result.destination_port == 443) << "parse vless udp ipv4: port=443";
        EXPECT_TRUE(result.payload_size == 2) << "parse vless udp ipv4: payload_size=2";
    }

    TEST(VlessFraming, BuildParseUdpIpv6)
    {
        psm::memory::vector<std::byte> out(psm::memory::current_resource());
        psm::protocol::vless::format::udp_routed frame;
        psm::protocol::common::ipv6_address addr{};
        addr.bytes[15] = 1; // ::1
        frame.destination_address = addr;
        frame.destination_port = 8443;

        const std::byte payload[] = {std::byte{0xCC}};
        auto ec = psm::protocol::vless::format::build_udp_pkt(frame, payload, out);
        EXPECT_TRUE(ec == psm::fault::code::success) << "build vless udp ipv6: success";

        auto [pec, result] = psm::protocol::vless::format::parse_udp_pkt(out);
        EXPECT_TRUE(pec == psm::fault::code::success) << "parse vless udp ipv6: success";
        EXPECT_TRUE(result.destination_port == 8443) << "parse vless udp ipv6: port=8443";
    }

    TEST(VlessFraming, BuildParseUdpDomain)
    {
        psm::memory::vector<std::byte> out(psm::memory::current_resource());
        psm::protocol::vless::format::udp_routed frame;
        psm::protocol::common::domain_address domain{};
        const char name[] = "test.local";
        domain.length = 10;
        std::memcpy(domain.value.data(), name, 10);
        frame.destination_address = domain;
        frame.destination_port = 53;

        const std::byte payload[] = {std::byte{0xAA}};
        auto ec = psm::protocol::vless::format::build_udp_pkt(frame, payload, out);
        EXPECT_TRUE(ec == psm::fault::code::success) << "build vless udp domain: success";

        auto [pec, result] = psm::protocol::vless::format::parse_udp_pkt(out);
        EXPECT_TRUE(pec == psm::fault::code::success) << "parse vless udp domain: success";
        EXPECT_TRUE(result.destination_port == 53) << "parse vless udp domain: port=53";
    }

    TEST(VlessFraming, ParseUdpTooShort)
    {
        std::byte buf[5]{};
        auto [ec, result] = psm::protocol::vless::format::parse_udp_pkt(buf);
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "parse vless udp short: bad_message";
    }

} // namespace
