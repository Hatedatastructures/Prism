/**
 * @file VlessCommon.cpp
 * @brief VLESS 协议 common 模块测试（客户端与服务端编解码互操作）
 */

#include <common/vless/vless.hpp>

#include <gtest/gtest.h>

using namespace psm_test;

namespace
{
    constexpr std::string_view uuid_hex = "123e4567-e89b-12d3-a456-426614174000";
} // namespace

TEST(VlessCommon, HandshakeRoundTrip)
{
    const auto uuid = parse_uuid(uuid_hex);
    vless::client c(uuid);
    vless::server s(uuid);

    vless::address dst;
    dst.type = atyp::domain;
    dst.host = "example.com";
    dst.port = 443;

    const auto wire = c.handshake(dst, vless::cmd_tcp);
    const auto req = s.parse(wire);
    ASSERT_TRUE(req.valid);
    EXPECT_EQ(req.cmd, vless::cmd_tcp);
    EXPECT_EQ(req.dst.host, "example.com");
    EXPECT_EQ(req.dst.port, 443);
}

TEST(VlessCommon, WrongUuidRejected)
{
    const auto uuid = parse_uuid(uuid_hex);
    vless::client c(uuid);
    vless::server s(parse_uuid("00000000-0000-0000-0000-000000000000"));

    vless::address dst;
    dst.type = atyp::ipv4;
    dst.host = "127.0.0.1";
    dst.port = 8080;

    const auto wire = c.handshake(dst);
    const auto req = s.parse(wire);
    EXPECT_FALSE(req.valid);
}

TEST(VlessCommon, UdpAndMuxCommand)
{
    const auto uuid = parse_uuid(uuid_hex);
    vless::client c(uuid);
    vless::server s(uuid);

    vless::address dst;
    dst.type = atyp::ipv4;
    dst.host = "127.0.0.1";
    dst.port = 5353;

    const auto udp_wire = c.handshake(dst, vless::cmd_udp);
    const auto udp_req = s.parse(udp_wire);
    ASSERT_TRUE(udp_req.valid);
    EXPECT_EQ(udp_req.cmd, vless::cmd_udp);

    const auto mux_wire = c.handshake(dst, vless::cmd_mux);
    const auto mux_req = s.parse(mux_wire);
    ASSERT_TRUE(mux_req.valid);
    EXPECT_EQ(mux_req.cmd, vless::cmd_mux);
}

TEST(VlessCommon, ResponseHeader)
{
    const auto resp = vless::server::response();
    ASSERT_TRUE(vless::client::parse_response(resp));
}

TEST(VlessCommon, UuidString)
{
    const auto uuid = parse_uuid(uuid_hex);
    EXPECT_EQ(uuid_string(uuid), uuid_hex);
}
