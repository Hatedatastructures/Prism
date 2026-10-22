/**
 * @file Http11BasicAuthTest.cpp
 * @brief HTTP/1.1 Proxy-Authorization Basic 认证转换测试。
 */
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Protocols/Http1/Detail/BasicAuthentication.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>

#include <string_view>

#include <gtest/gtest.h>

TEST(Http11Connect, CheckBasicAuth)
{
    constexpr std::string_view ValidAuthorization = "Basic dXNlcjpwYXNz";
    constexpr std::string_view InvalidAuthorization = "Basic dXNlcjpiYWQ=";
    const auto AccountOwner = Prism::Testing::ProviderAccount(
        Prism::Testing::ProviderAccountInput{Prism::AccountId{1U},
            Prism::Account::Credential::Password("pass"), "user", "user", {}});
    const auto &Authenticator = *AccountOwner->Authenticator;

    const auto Valid = Prism::Http11::detail::AuthenticateBasic(
        ValidAuthorization, Authenticator);
    ASSERT_TRUE(Valid);
    EXPECT_EQ(Valid->Identity(), "user");

    const auto InvalidPassword = Prism::Http11::detail::AuthenticateBasic(
        InvalidAuthorization, Authenticator);
    ASSERT_FALSE(InvalidPassword);
    EXPECT_EQ(InvalidPassword.error().Code, Prism::Fault::Code::AuthFailed);
    EXPECT_FALSE(Prism::Http11::detail::AuthenticateBasic("Bearer token", Authenticator));
    EXPECT_FALSE(Prism::Http11::detail::AuthenticateBasic("", Authenticator));
}
