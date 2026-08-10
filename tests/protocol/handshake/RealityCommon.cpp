/**
 * @file RealityCommon.cpp
 * @brief Reality 密钥原语 common 模块测试（base64url + X25519 + ShortID）
 */

#include <common/reality/reality.hpp>

#include <gtest/gtest.h>

using namespace psm_test;

TEST(RealityCommon, Base64UrlRoundTrip)
{
    const std::string data = "reality-key-material";
    const auto enc = reality::base64url_encode(view(
        reinterpret_cast<const std::uint8_t *>(data.data()), data.size()));
    const auto dec = reality::base64url_decode(enc);
    EXPECT_EQ(std::string(reinterpret_cast<const char *>(dec.data()), dec.size()), data);
}

TEST(RealityCommon, ParsePrivateKey)
{
    std::array<std::uint8_t, 32> priv{};
    for (std::size_t i = 0; i < priv.size(); ++i)
        priv[i] = static_cast<std::uint8_t>(i);
    const auto enc = reality::base64url_encode(priv);
    const auto parsed = reality::parse_private_key(enc);
    ASSERT_EQ(parsed.size(), 32);
    EXPECT_EQ(std::memcmp(parsed.data(), priv.data(), 32), 0);
}

TEST(RealityCommon, InvalidKeyRejected)
{
    const auto parsed = reality::parse_private_key("too-short");
    EXPECT_TRUE(parsed.empty());
}

TEST(RealityCommon, DerivePublicKey)
{
    const auto [priv, pub] = reality::generate_keypair();
    std::array<std::uint8_t, 32> derived{};
    ASSERT_TRUE(reality::derive_public_key(priv, derived));
    EXPECT_EQ(derived, pub);
}

TEST(RealityCommon, ShortIdParse)
{
    const auto id = reality::parse_short_id("0123456789abcdef");
    std::array<std::uint8_t, 8> expect{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    EXPECT_EQ(id, expect);
}
