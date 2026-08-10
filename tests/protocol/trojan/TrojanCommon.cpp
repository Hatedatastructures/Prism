/**
 * @file TrojanCommon.cpp
 * @brief Trojan 协议 common 模块测试（客户端与服务端编解码互操作）
 */

#include <common/trojan/trojan.hpp>

#include <gtest/gtest.h>

using namespace psm_test;

TEST(TrojanCommon, HandshakeRoundTrip)
{
    const std::string password = "prism";
    trojan::client c(password);
    trojan::server s(password);

    trojan::address dst;
    dst.type = atyp::domain;
    dst.host = "example.com";
    dst.port = 443;

    const auto wire = c.handshake(dst);
    ASSERT_GE(wire.size(), 60);
    const auto hash = trojan::sha224_hex(password);
    EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(wire.data()), 56), hash);

    const auto req = s.parse(wire);
    ASSERT_TRUE(req.valid);
    EXPECT_EQ(req.dst.host, "example.com");
    EXPECT_EQ(req.dst.port, 443);
}

TEST(TrojanCommon, WrongPasswordRejected)
{
    trojan::client c("prism");
    trojan::server s("other-password");

    trojan::address dst;
    dst.type = atyp::ipv4;
    dst.host = "127.0.0.1";
    dst.port = 8080;

    const auto wire = c.handshake(dst);
    const auto req = s.parse(wire);
    EXPECT_FALSE(req.valid);
}

TEST(TrojanCommon, ResponseHeader)
{
    const auto resp = trojan::server::response();
    ASSERT_TRUE(trojan::client::parse_response(resp));
}

TEST(TrojanCommon, UdpHeader)
{
    const std::string password = "prism";
    trojan::client c(password);

    trojan::address dst;
    dst.type = atyp::ipv4;
    dst.host = "127.0.0.1";
    dst.port = 5353;

    const auto wire = c.handshake(dst, true);
    EXPECT_EQ(wire[0], '\r');
    EXPECT_EQ(wire[1], '\n');
}
