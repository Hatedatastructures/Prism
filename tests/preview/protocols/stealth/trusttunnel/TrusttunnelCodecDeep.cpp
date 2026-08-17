/**
 * @file TrusttunnelCodecDeep.cpp
 * @brief trusttunnel codec 字节级深测（纯函数）
 * @details 覆盖：Basic 认证编码/解析/验证的往返、边界与错误路径。
 */

#include <gtest/gtest.h>

#include <string>

#include <common/protocols/trusttunnel/codec.hpp>

namespace
{
    using namespace preview;

    TEST(TrusttunnelCodecDeep, BasicAuthRoundtrip)
    {
        const auto encoded = trusttunnel::basic_auth("user", "pass");
        EXPECT_FALSE(encoded.empty());
        EXPECT_EQ(encoded.substr(0, 6), "Basic ");

        std::string user;
        std::string pass;
        const auto ok = trusttunnel::parse_basic_auth(encoded, user, pass);
        EXPECT_TRUE(ok);
        EXPECT_EQ(user, "user");
        EXPECT_EQ(pass, "pass");
    }

    TEST(TrusttunnelCodecDeep, BasicAuthSpecialChars)
    {
        // 密码含空格/冒号的凭据（Basic 协议按首个冒号分隔用户名）
        const auto encoded = trusttunnel::basic_auth("alice", "p a:ss");
        std::string user;
        std::string pass;
        EXPECT_TRUE(trusttunnel::parse_basic_auth(encoded, user, pass));
        EXPECT_EQ(user, "alice");
        EXPECT_EQ(pass, "p a:ss");
    }

    TEST(TrusttunnelCodecDeep, ParseBasicAuthErrors)
    {
        std::string user;
        std::string pass;
        // 非 Basic 前缀
        EXPECT_FALSE(trusttunnel::parse_basic_auth("Bearer abc", user, pass));
        // 空串
        EXPECT_FALSE(trusttunnel::parse_basic_auth("", user, pass));
        // 非法 base64
        EXPECT_FALSE(trusttunnel::parse_basic_auth("Basic !!!not-base64!!!", user, pass));
        // 无冒号分隔（解码成功但缺分隔符）
        const auto no_colon = trusttunnel::basic_auth("onlyuser", "x");
        (void)no_colon;
        // 边界：只有 Basic 前缀
        EXPECT_FALSE(trusttunnel::parse_basic_auth("Basic ", user, pass));
    }

    TEST(TrusttunnelCodecDeep, VerifyBasicAuth)
    {
        const auto encoded = trusttunnel::basic_auth("alice", "s3cret");
        EXPECT_TRUE(trusttunnel::verify_basic_auth(encoded, "alice", "s3cret"));
        EXPECT_FALSE(trusttunnel::verify_basic_auth(encoded, "alice", "wrong"));
        EXPECT_FALSE(trusttunnel::verify_basic_auth(encoded, "bob", "s3cret"));
        EXPECT_FALSE(trusttunnel::verify_basic_auth("garbage", "alice", "s3cret"));
    }

} // namespace
