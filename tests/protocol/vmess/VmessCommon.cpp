/**
 * @file VmessCommon.cpp
 * @brief VMess AEAD 协议 common 模块测试（客户端握手 → 服务端解析互操作）
 */

#include <common/vmess/client.hpp>
#include <common/vmess/server.hpp>

#include <gtest/gtest.h>

using namespace psm_test;

namespace
{
    constexpr std::string_view uuid_hex = "123e4567-e89b-12d3-a456-426614174000";
    constexpr std::uint64_t fixed_time = 1700000000ULL;
} // namespace

TEST(VmessCommon, HandshakeRoundTrip)
{
    const auto uuid = parse_uuid(uuid_hex);
    vmess::client c(uuid);
    vmess::server s(uuid);

    vmess::address dst;
    dst.type = atyp::domain;
    dst.host = "example.com";
    dst.port = 443;

    const auto wire = c.handshake(dst, vmess::cmd_tcp, fixed_time);
    ASSERT_GE(wire.size(), 58 + 16);

    const auto req = s.parse(wire, fixed_time);
    ASSERT_TRUE(req.valid);
    EXPECT_EQ(req.cmd, vmess::cmd_tcp);
    EXPECT_EQ(req.dst.host, "example.com");
    EXPECT_EQ(req.dst.port, 443);
}

TEST(VmessCommon, WrongUuidRejected)
{
    const auto uuid = parse_uuid(uuid_hex);
    vmess::client c(uuid);
    vmess::server s(parse_uuid("00000000-0000-0000-0000-000000000000"));

    vmess::address dst;
    dst.type = atyp::ipv4;
    dst.host = "127.0.0.1";
    dst.port = 8080;

    const auto wire = c.handshake(dst, vmess::cmd_tcp, fixed_time);
    const auto req = s.parse(wire, fixed_time);
    EXPECT_FALSE(req.valid);
}

TEST(VmessCommon, TimeWindowRejected)
{
    const auto uuid = parse_uuid(uuid_hex);
    vmess::client c(uuid);
    vmess::server s(uuid);

    vmess::address dst;
    dst.type = atyp::ipv4;
    dst.host = "127.0.0.1";
    dst.port = 8080;

    const auto wire = c.handshake(dst, vmess::cmd_tcp, fixed_time);
    const auto req = s.parse(wire, fixed_time + 1000);
    EXPECT_FALSE(req.valid);
}

TEST(VmessCommon, UdpCommand)
{
    const auto uuid = parse_uuid(uuid_hex);
    vmess::client c(uuid);
    vmess::server s(uuid);

    vmess::address dst;
    dst.type = atyp::ipv4;
    dst.host = "127.0.0.1";
    dst.port = 5353;

    const auto wire = c.handshake(dst, vmess::cmd_udp, fixed_time);
    const auto req = s.parse(wire, fixed_time);
    ASSERT_TRUE(req.valid);
    EXPECT_EQ(req.cmd, vmess::cmd_udp);
    EXPECT_EQ(req.dst.port, 5353);
}

TEST(VmessCommon, ChunkEncryptDecrypt)
{
    const auto uuid = parse_uuid(uuid_hex);
    vmess::client c(uuid);
    vmess::server s(uuid);

    vmess::address dst;
    dst.type = atyp::ipv4;
    dst.host = "127.0.0.1";
    dst.port = 8080;

    const auto wire = c.handshake(dst, vmess::cmd_tcp, fixed_time);
    ASSERT_TRUE(s.parse(wire, fixed_time).valid);

    const std::string payload = "hello vmess chunk";
    const auto chunk = c.encrypt_chunk(
        view(reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()), 0);
    buffer decrypted;
    ASSERT_TRUE(s.decrypt_chunk(chunk, 0, decrypted));
    EXPECT_EQ(std::string(reinterpret_cast<const char *>(decrypted.data()), decrypted.size()),
              payload);

    // 计数不匹配解密失败
    buffer bad;
    EXPECT_FALSE(s.decrypt_chunk(chunk, 1, bad));
}
