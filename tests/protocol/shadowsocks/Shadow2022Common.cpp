/**
 * @file Shadow2022Common.cpp
 * @brief Shadowsocks 2022 协议 common 模块测试（客户端握手 ↔ 服务端解析互操作）
 */

#include <common/shadowsocks2022/client.hpp>
#include <common/shadowsocks2022/server.hpp>

#include <gtest/gtest.h>

using namespace psm_test;

namespace
{
    constexpr std::uint64_t fixed_time = 1700000000ULL;

    auto make_psk() -> std::array<std::uint8_t, 16>
    {
        // "5n5ESu953i/pjIp02oZvHA==" 的 16 字节（configuration.json 的 psk）
        return {0xE6, 0x7E, 0x44, 0x4A, 0xEF, 0x79, 0xDE, 0x2F,
        0xE9, 0x8C, 0x8A, 0x74, 0xDA, 0x86, 0x6F, 0x1C};
    }
} // namespace

TEST(Shadow2022Common, HandshakeRoundTrip)
{
    const auto psk = make_psk();
    shadow2022::client c(psk);
    shadow2022::server s(psk);

    shadow2022::address dst;
    dst.type = atyp::domain;
    dst.host = "example.com";
    dst.port = 443;

    const auto wire = c.handshake(dst, {}, fixed_time);
    ASSERT_GE(wire.size(), 16 + 27 + 16);

    const auto req = s.parse(wire, fixed_time);
    ASSERT_TRUE(req.valid);
    EXPECT_EQ(req.dst.host, "example.com");
    EXPECT_EQ(req.dst.port, 443);
    EXPECT_TRUE(req.initial_payload.empty());
}

TEST(Shadow2022Common, WrongPskRejected)
{
    const auto psk = make_psk();
    std::array<std::uint8_t, 16> bad_psk = psk;
    bad_psk[0] ^= 0xFF;

    shadow2022::client c(psk);
    shadow2022::server s(bad_psk);

    shadow2022::address dst;
    dst.type = atyp::ipv4;
    dst.host = "127.0.0.1";
    dst.port = 8080;

    const auto wire = c.handshake(dst, {}, fixed_time);
    const auto req = s.parse(wire, fixed_time);
    EXPECT_FALSE(req.valid);
}

TEST(Shadow2022Common, TimeWindowRejected)
{
    const auto psk = make_psk();
    shadow2022::client c(psk);
    shadow2022::server s(psk);

    shadow2022::address dst;
    dst.type = atyp::ipv4;
    dst.host = "127.0.0.1";
    dst.port = 8080;

    const auto wire = c.handshake(dst, {}, fixed_time);
    const auto req = s.parse(wire, fixed_time + 1000);
    EXPECT_FALSE(req.valid);
}

TEST(Shadow2022Common, InitialPayload)
{
    const auto psk = make_psk();
    shadow2022::client c(psk);
    shadow2022::server s(psk);

    shadow2022::address dst;
    dst.type = atyp::ipv4;
    dst.host = "127.0.0.1";
    dst.port = 8080;

    const std::string payload = "early data";
    const auto wire = c.handshake(dst, view(
        reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()), fixed_time);
    const auto req = s.parse(wire, fixed_time);
    ASSERT_TRUE(req.valid);
    EXPECT_EQ(std::string(reinterpret_cast<const char *>(req.initial_payload.data()),
                          req.initial_payload.size()),
              payload);
}

TEST(Shadow2022Common, ServerResponseVerify)
{
    const auto psk = make_psk();
    shadow2022::client c(psk);
    shadow2022::server s(psk);

    shadow2022::address dst;
    dst.type = atyp::ipv4;
    dst.host = "127.0.0.1";
    dst.port = 8080;

    const auto wire = c.handshake(dst, {}, fixed_time);
    const auto req = s.parse(wire, fixed_time);
    ASSERT_TRUE(req.valid);

    std::array<std::uint8_t, 16> server_salt{};
    const auto resp = s.respond(c.salt(), fixed_time, server_salt);
    ASSERT_TRUE(shadow2022::server::verify_response(resp, psk));
}

TEST(Shadow2022Common, KnownVectorDecrypt)
{
    // 用 sing-shadowsocks（Go 验证）的真实握手字节验证解密
    const std::array<std::uint8_t, 16> psk{
        0xE6, 0x7E, 0x44, 0x4A, 0xEF, 0x79, 0xDE, 0x2F,
        0xE9, 0x8C, 0x8A, 0x74, 0xDA, 0x86, 0x6F, 0x1C};
    const std::array<std::uint8_t, 16> salt{
        0xf2, 0xc7, 0x3a, 0x39, 0x7b, 0x4d, 0x7a, 0xbd,
        0x52, 0x9f, 0x15, 0xdc, 0xd2, 0x76, 0x5e, 0x15};
    const std::array<std::uint8_t, 27> fixed_enc{
        0x76, 0xaa, 0x7a, 0xf4, 0x16, 0xce, 0x63, 0x67, 0x7e, 0x30, 0xd3,
        0x8a, 0xfd, 0x7f, 0xfc, 0xc9, 0x71, 0x6c, 0x91, 0x1b, 0x86, 0x64,
        0xf4, 0xc6, 0xe0, 0x3c, 0xc7};

    const auto key = shadow2022::session_key(psk, salt);
    shadow2022::chunk_codec codec(key);
    buffer plain;
    ASSERT_TRUE(codec.open_raw(fixed_enc, plain));
    ASSERT_EQ(plain.size(), 11);
    EXPECT_EQ(plain[0], 0x00); // type client
    EXPECT_EQ(plain[9], 0x00); // var_len 高字节
    EXPECT_EQ(plain[10], 0x20); // var_len 低字节（32）
}

TEST(Shadow2022Common, ChunkRoundTrip)
{
    const auto psk = make_psk();
    shadow2022::client c(psk);
    shadow2022::server s(psk);

    shadow2022::address dst;
    dst.type = atyp::ipv4;
    dst.host = "127.0.0.1";
    dst.port = 8080;

    const auto wire = c.handshake(dst, {}, fixed_time);
    ASSERT_TRUE(s.parse(wire, fixed_time).valid);
}
