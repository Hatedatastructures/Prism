/**
 * @file AnytlsCommon.cpp
 * @brief AnyTLS 认证原语 common 模块测试（HKDF 派生 + 认证帧）
 */

#include <common/anytls/anytls.hpp>

#include <gtest/gtest.h>

using namespace psm_test;

TEST(AnytlsCommon, HkdfDerive)
{
    std::array<std::uint8_t, 16> secret{};
    for (std::size_t i = 0; i < secret.size(); ++i)
        secret[i] = static_cast<std::uint8_t>(i);

    const auto key = anytls::derive_session_key(secret, {}, "anytls session key", 32);
    ASSERT_EQ(key.size(), 32);

    // 确定性：相同输入产出相同输出
    const auto key2 = anytls::derive_session_key(secret, {}, "anytls session key", 32);
    EXPECT_EQ(key, key2);
}

TEST(AnytlsCommon, HkdfDifferentInfo)
{
    std::array<std::uint8_t, 16> secret{};
    const auto key1 = anytls::derive_session_key(secret, {}, "info-a", 32);
    const auto key2 = anytls::derive_session_key(secret, {}, "info-b", 32);
    EXPECT_NE(key1, key2);
}

TEST(AnytlsCommon, AuthFrameRoundTrip)
{
    const std::string payload = "anytls-auth";
    const auto frame = anytls::build_auth_frame(view(
        reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));
    ASSERT_GE(frame.size(), 2);

    const auto parsed = anytls::parse_auth_frame(frame);
    ASSERT_TRUE(parsed.valid);
    EXPECT_EQ(frame.size() - parsed.payload_offset, payload.size());
}

TEST(AnytlsCommon, AuthFrameTruncated)
{
    const std::uint8_t bad[] = {0x00, 0x10, 0x01};
    EXPECT_FALSE(anytls::parse_auth_frame(view(bad)).valid);
}
