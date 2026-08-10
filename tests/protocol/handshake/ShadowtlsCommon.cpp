/**
 * @file ShadowtlsCommon.cpp
 * @brief ShadowTLS v3 认证 common 模块测试（HMAC-SHA1 认证编解码）
 */

#include <common/shadowtls/shadowtls.hpp>

#include <gtest/gtest.h>

using namespace psm_test;

namespace
{
    // 模拟 TLS 握手字节流（客户端与服务端协商的假握手）
    auto make_handshake() -> buffer
    {
        buffer hs;
        // 简化 ClientHello + ServerHello 字节
        const std::uint8_t hello[] = {
            0x16, 0x03, 0x01, 0x00, 0x2E, 0x01, 0x00, 0x00, 0x2A, 0x03, 0x03,
            0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A,
            0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A,
            0x00, 0x00, 0x02, 0x13, 0x01, 0x13, 0x02, 0x01, 0x00,
        };
        hs.assign(hello, hello + sizeof(hello));
        return hs;
    }
} // namespace

TEST(ShadowtlsCommon, AuthHashVerify)
{
    const std::string password = "shadowtls_password";
    const auto hs = make_handshake();

    const auto hash = shadowtls::compute_hash(password, hs);
    ASSERT_TRUE(shadowtls::verify(password, hs, hash));
}

TEST(ShadowtlsCommon, WrongPasswordRejected)
{
    const auto hs = make_handshake();
    const auto hash = shadowtls::compute_hash("shadowtls_password", hs);
    EXPECT_FALSE(shadowtls::verify("wrong-password", hs, hash));
}

TEST(ShadowtlsCommon, FirstPacketRoundTrip)
{
    const std::string password = "shadowtls_password";
    const auto hs = make_handshake();
    const std::string payload = "hello shadowtls";

    const auto pkt = shadowtls::build_first_packet(password, hs, view(
        reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));
    ASSERT_GE(pkt.size(), 5 + 20);

    EXPECT_EQ(pkt[0], 0x17);
    EXPECT_EQ(pkt[1], 0x03);
    EXPECT_EQ(pkt[2], 0x03);

    const auto parsed = shadowtls::parse_first_packet(pkt);
    ASSERT_TRUE(parsed.valid);
    ASSERT_TRUE(shadowtls::verify(password, hs, parsed.hash));
    EXPECT_EQ(pkt.size() - parsed.payload_offset, payload.size());
    EXPECT_EQ(std::string(reinterpret_cast<const char *>(pkt.data() + parsed.payload_offset),
                          pkt.size() - parsed.payload_offset),
              payload);
}

TEST(ShadowtlsCommon, TamperedHashRejected)
{
    const std::string password = "shadowtls_password";
    const auto hs = make_handshake();
    std::string payload = "hello";
    auto pkt = shadowtls::build_first_packet(password, hs, view(
        reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));
    pkt[5] ^= 0xFF; // 篡改 hash 首字节

    const auto parsed = shadowtls::parse_first_packet(pkt);
    ASSERT_TRUE(parsed.valid);
    EXPECT_FALSE(shadowtls::verify(password, hs, parsed.hash));
}
