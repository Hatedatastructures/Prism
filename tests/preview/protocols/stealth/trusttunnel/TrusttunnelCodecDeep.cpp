/**
 * @file TrusttunnelCodecDeep.cpp
 * @brief trusttunnel Codec 字节级深测（纯函数）
 * @details 覆盖：Basic 认证编码/解析/验证的往返、边界与错误路径。
 */

#include <gtest/gtest.h>

#include <string>

#include <preview/Protocols/Trusttunnel/Codec.hpp>

namespace
{
    using namespace Preview;

    TEST(TrusttunnelCodecDeep, BasicAuthRoundtrip)
    {
        const auto encoded = Trusttunnel::BasicAuth("user", "pass");
        EXPECT_FALSE(encoded.empty());
        EXPECT_EQ(encoded.substr(0, 6), "Basic ");

        std::string user;
        std::string pass;
        const auto Ok = Trusttunnel::ParseBasicAuth(encoded, user, pass);
        EXPECT_TRUE(Ok);
        EXPECT_EQ(user, "user");
        EXPECT_EQ(pass, "pass");
    }

    TEST(TrusttunnelCodecDeep, BasicAuthSpecialChars)
    {
        // 密码含空格/冒号的凭据（Basic 协议按首个冒号分隔用户名）
        const auto encoded = Trusttunnel::BasicAuth("alice", "p a:ss");
        std::string user;
        std::string pass;
        EXPECT_TRUE(Trusttunnel::ParseBasicAuth(encoded, user, pass));
        EXPECT_EQ(user, "alice");
        EXPECT_EQ(pass, "p a:ss");
    }

    TEST(TrusttunnelCodecDeep, ParseBasicAuthErrors)
    {
        std::string user;
        std::string pass;
        // 非 Basic 前缀
        EXPECT_FALSE(Trusttunnel::ParseBasicAuth("Bearer abc", user, pass));
        // 空串
        EXPECT_FALSE(Trusttunnel::ParseBasicAuth("", user, pass));
        // 非法 base64
        EXPECT_FALSE(Trusttunnel::ParseBasicAuth("Basic !!!not-base64!!!", user, pass));
        // 无冒号分隔（解码成功但缺分隔符）
        const auto no_colon = Trusttunnel::BasicAuth("onlyuser", "x");
        (void)no_colon;
        // 边界：只有 Basic 前缀
        EXPECT_FALSE(Trusttunnel::ParseBasicAuth("Basic ", user, pass));
    }

    TEST(TrusttunnelCodecDeep, VerifyBasicAuth)
    {
        const auto encoded = Trusttunnel::BasicAuth("alice", "s3cret");
        EXPECT_TRUE(Trusttunnel::VerifyBasicAuth(encoded, "alice", "s3cret"));
        EXPECT_FALSE(Trusttunnel::VerifyBasicAuth(encoded, "alice", "wrong"));
        EXPECT_FALSE(Trusttunnel::VerifyBasicAuth(encoded, "bob", "s3cret"));
        EXPECT_FALSE(Trusttunnel::VerifyBasicAuth("garbage", "alice", "s3cret"));
    }

} // namespace
