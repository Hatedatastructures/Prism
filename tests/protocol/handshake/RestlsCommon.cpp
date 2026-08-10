/**
 * @file RestlsCommon.cpp
 * @brief Restls 认证原语 common 模块测试（握手摘要派生 + 认证载荷）
 */

#include <common/restls/restls.hpp>

#include <gtest/gtest.h>

using namespace psm_test;

namespace
{
    auto make_handshake() -> buffer
    {
        // 模拟 TLS 握手字节
        buffer hs;
        for (std::uint8_t i = 0; i < 64; ++i)
            hs.push_back(i);
        return hs;
    }
} // namespace

TEST(RestlsCommon, AuthKeyVerify)
{
    const std::string password = "restls_password";
    const auto hs = make_handshake();

    const auto key = restls::derive_auth_key(password, hs);
    ASSERT_TRUE(restls::verify_auth(password, hs, key));
}

TEST(RestlsCommon, WrongPasswordRejected)
{
    const auto hs = make_handshake();
    const auto key = restls::derive_auth_key("restls_password", hs);
    EXPECT_FALSE(restls::verify_auth("wrong", hs, key));
}

TEST(RestlsCommon, AuthPayloadRoundTrip)
{
    const std::string password = "restls_password";
    const auto hs = make_handshake();
    const auto key = restls::derive_auth_key(password, hs);

    const auto payload = restls::build_auth_payload(0x01, key);
    const auto parsed = restls::parse_auth_payload(payload);
    ASSERT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.version, 0x01);
    EXPECT_EQ(std::memcmp(parsed.auth_key.data(), key.data(), 32), 0);
}

TEST(RestlsCommon, AuthPayloadBadLength)
{
    const std::uint8_t bad[] = {0x01, 0x02, 0x03};
    EXPECT_FALSE(restls::parse_auth_payload(view(bad)).valid);
}
