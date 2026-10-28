/**
 * @file BasicAuthTest.cpp
 * @brief Trusttunnel Basic Auth 编解码与验证测试。
 */

#include <string>
#include <Prism/Protocols/Trusttunnel/Codec.hpp>
#include <gtest/gtest.h>

namespace
{

    namespace Trusttunnel = Prism::Trusttunnel;

TEST(TrustTunnelBeast, BasicAuth)
    {
        const auto Auth = Trusttunnel::BasicAuth("user", "pass");
        EXPECT_EQ(Auth, "Basic dXNlcjpwYXNz");

        std::string user, pass;
        EXPECT_TRUE(Trusttunnel::ParseBasicAuth(Auth, user, pass));
        EXPECT_EQ(user, "user");
        EXPECT_EQ(pass, "pass");
        EXPECT_TRUE(Trusttunnel::VerifyBasicAuth(Auth, "user", "pass"));
        EXPECT_FALSE(Trusttunnel::VerifyBasicAuth(Auth, "user", "wrong"));
        EXPECT_FALSE(Trusttunnel::ParseBasicAuth("Bearer token", user, pass));
    }

} // namespace
