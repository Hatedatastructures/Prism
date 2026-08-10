/**
 * @file Socks5Common.cpp
 * @brief Socks5 协议 common 模块测试（客户端与服务端编解码互操作）
 */

#include <common/socks5/socks5.hpp>

#include <gtest/gtest.h>

using namespace psm_test;

namespace
{
    auto make_ipv4(const std::string_view host, const std::uint16_t port) -> socks5::address
    {
        socks5::address a;
        a.type = atyp::ipv4;
        a.host = std::string(host);
        a.port = port;
        return a;
    }
} // namespace

TEST(Socks5Common, ClientHandshakeServerParse)
{
    socks5::client c;
    socks5::server s;

    const auto dst = make_ipv4("127.0.0.1", 8080);
    const auto wire = c.handshake(dst);

    ASSERT_GE(wire.size(), 10);
    EXPECT_EQ(wire[0], 0x05);
    EXPECT_EQ(wire[1], 0x01);
    EXPECT_EQ(wire[2], 0x00);

    const view greeting(wire.data(), 3);
    ASSERT_TRUE(s.parse_greeting(greeting));
    const auto gresp = s.greeting_response();
    ASSERT_EQ(gresp.size(), 2);
    EXPECT_EQ(gresp[0], 0x05);
    EXPECT_EQ(gresp[1], 0x00);

    socks5::address parsed;
    ASSERT_TRUE(s.parse_request(view(wire.data() + 3, wire.size() - 3), parsed));
    EXPECT_EQ(s.command(), 0x01);
    EXPECT_EQ(parsed.host, "127.0.0.1");
    EXPECT_EQ(parsed.port, 8080);
}

TEST(Socks5Common, ServerResponseClientParse)
{
    socks5::client c;

    const auto ok = socks5::server::request_response(true);
    ASSERT_TRUE(c.parse_response(ok));

    const auto bad = socks5::server::request_response(false);
    EXPECT_FALSE(c.parse_response(bad));
}

TEST(Socks5Common, DomainAddressRoundTrip)
{
    socks5::client c;
    socks5::server s;

    socks5::address dst;
    dst.type = atyp::domain;
    dst.host = "example.com";
    dst.port = 443;

    const auto wire = c.handshake(dst);
    socks5::address parsed;
    ASSERT_TRUE(s.parse_request(view(wire.data() + 3, wire.size() - 3), parsed));
    EXPECT_EQ(parsed.host, "example.com");
    EXPECT_EQ(parsed.port, 443);
}

TEST(Socks5Common, RejectGarbage)
{
    socks5::server s;
    socks5::address parsed;
    const std::uint8_t garbage[] = {0x01, 0x02, 0x03};
    EXPECT_FALSE(s.parse_request(view(garbage), parsed));
}
