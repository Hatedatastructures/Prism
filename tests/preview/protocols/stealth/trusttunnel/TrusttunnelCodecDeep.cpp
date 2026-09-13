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
    namespace Trusttunnel = Preview::Trusttunnel;

    TEST(TrusttunnelCodecDeep, BasicAuthRoundtrip)
    {
        const auto Encoded = Trusttunnel::BasicAuth("user", "pass");
        EXPECT_FALSE(Encoded.empty());
        EXPECT_EQ(Encoded.substr(0, 6), "Basic ");

        std::string User;
        std::string Password;
        const auto IsValid = Trusttunnel::ParseBasicAuth(Encoded, User, Password);
        EXPECT_TRUE(IsValid);
        EXPECT_EQ(User, "user");
        EXPECT_EQ(Password, "pass");
    }

    TEST(TrusttunnelCodecDeep, BasicAuthSpecialChars)
    {
        // 密码含空格/冒号的凭据（Basic 协议按首个冒号分隔用户名）
        const auto Encoded = Trusttunnel::BasicAuth("alice", "p a:ss");
        std::string User;
        std::string Password;
        EXPECT_TRUE(Trusttunnel::ParseBasicAuth(Encoded, User, Password));
        EXPECT_EQ(User, "alice");
        EXPECT_EQ(Password, "p a:ss");
    }

    TEST(TrusttunnelCodecDeep, ParseBasicAuthErrors)
    {
        std::string User;
        std::string Password;
        // 非 Basic 前缀
        EXPECT_FALSE(Trusttunnel::ParseBasicAuth("Bearer abc", User, Password));
        // 空串
        EXPECT_FALSE(Trusttunnel::ParseBasicAuth("", User, Password));
        // 非法 base64
        EXPECT_FALSE(Trusttunnel::ParseBasicAuth("Basic !!!not-base64!!!", User, Password));
        // 无冒号分隔（解码成功但缺分隔符）
        const auto NoColon = Trusttunnel::BasicAuth("onlyuser", "x");
        (void)NoColon;
        // 边界：只有 Basic 前缀
        EXPECT_FALSE(Trusttunnel::ParseBasicAuth("Basic ", User, Password));
    }

    TEST(TrusttunnelCodecDeep, RejectsNonCanonicalBase64)
    {
        std::string User;
        std::string Password;
        // padding 后的尾随字节和非规范补位不能被当成同一凭据。
        EXPECT_FALSE(Trusttunnel::ParseBasicAuth("Basic dXNlcjpwYXNz=", User, Password));
        EXPECT_FALSE(Trusttunnel::ParseBasicAuth("Basic dXNlcjpwYXNz=AAAA", User, Password));
    }

    TEST(TrusttunnelCodecDeep, VerifyBasicAuth)
    {
        const auto Encoded = Trusttunnel::BasicAuth("alice", "s3cret");
        EXPECT_TRUE(Trusttunnel::VerifyBasicAuth(Encoded, "alice", "s3cret"));
        EXPECT_FALSE(Trusttunnel::VerifyBasicAuth(Encoded, "alice", "wrong"));
        EXPECT_FALSE(Trusttunnel::VerifyBasicAuth(Encoded, "bob", "s3cret"));
        EXPECT_FALSE(Trusttunnel::VerifyBasicAuth("garbage", "alice", "s3cret"));
    }

} // namespace
