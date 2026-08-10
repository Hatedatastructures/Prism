/**
 * @file Hysteria2Common.cpp
 * @brief Hysteria2 协议 common 模块测试（认证 + TCP/UDP 帧编解码）
 */

#include <common/hysteria2/hysteria2.hpp>

#include <gtest/gtest.h>

using namespace psm_test;

TEST(Hysteria2Common, AuthRequestRoundTrip)
{
    const auto frame = hysteria2::build_auth_request("hysteria2_password");
    ASSERT_GE(frame.size(), 8);
    EXPECT_EQ(frame[0], 0x01); // HEADERS 帧类型

    hysteria2::auth_request req;
    ASSERT_TRUE(hysteria2::parse_auth_request(frame, req));
    EXPECT_EQ(req.method, "POST");
    EXPECT_EQ(req.path, "/auth");
    EXPECT_EQ(req.auth, "hysteria2_password");
    EXPECT_TRUE(req.valid);
    ASSERT_TRUE(req.valid);
    EXPECT_EQ(req.method, "POST");
    EXPECT_EQ(req.path, "/auth");
    EXPECT_EQ(req.auth, "hysteria2_password");
}

TEST(Hysteria2Common, AuthAnyPasswordParsed)
{
    // 密码校验在服务端配置比对；此处验证任意密码可被解析
    const auto frame = hysteria2::build_auth_request("wrong-password");
    hysteria2::auth_request req;
    ASSERT_TRUE(hysteria2::parse_auth_request(frame, req));
    EXPECT_EQ(req.auth, "wrong-password");
}

TEST(Hysteria2Common, AuthRejectGarbage)
{
    // 非法帧（帧类型非 HEADERS）解析失败
    hysteria2::auth_request req;
    const std::uint8_t garbage[] = {0x00, 0x01, 0x02, 0x03};
    EXPECT_FALSE(hysteria2::parse_auth_request(view(garbage), req));
}

TEST(Hysteria2Common, TcpFrameRoundTrip)
{
    hysteria2::address dst;
    dst.type = atyp::domain;
    dst.host = "example.com";
    dst.port = 443;

    const std::string payload = "hello hysteria2 tcp";
    const auto frame = hysteria2::build_tcp_request(dst, view(
        reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));

    hysteria2::address parsed;
    std::size_t offset = 0;
    ASSERT_TRUE(hysteria2::parse_tcp_request(frame, parsed, offset));
    EXPECT_EQ(parsed.host, "example.com");
    EXPECT_EQ(parsed.port, 443);
    EXPECT_EQ(frame.size() - offset, payload.size());
    EXPECT_EQ(std::string(reinterpret_cast<const char *>(frame.data() + offset),
                          frame.size() - offset),
              payload);
}

TEST(Hysteria2Common, UdpMessageRoundTrip)
{
    hysteria2::address dst;
    dst.type = atyp::ipv4;
    dst.host = "127.0.0.1";
    dst.port = 5353;

    const std::string payload = "udp datagram";
    const auto frame = hysteria2::build_udp_message(0x01020304, 7, dst, view(
        reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));

    std::uint32_t session_id = 0;
    hysteria2::address parsed;
    std::size_t offset = 0;
    ASSERT_TRUE(hysteria2::parse_udp_message(frame, session_id, parsed, offset));
    EXPECT_EQ(session_id, 0x01020304);
    EXPECT_EQ(parsed.host, "127.0.0.1");
    EXPECT_EQ(parsed.port, 5353);
    EXPECT_EQ(std::string(reinterpret_cast<const char *>(frame.data() + offset),
                          frame.size() - offset),
              payload);
}

TEST(Hysteria2Common, TcpResponse)
{
    const auto resp = hysteria2::build_tcp_response(true, "");
    ASSERT_GE(resp.size(), 3);
    EXPECT_EQ(resp[0], 0x00); // status = 成功
    EXPECT_EQ(resp[1], 0x00); // message len = 0
    EXPECT_EQ(resp[2], 0x00); // padding len = 0
}
