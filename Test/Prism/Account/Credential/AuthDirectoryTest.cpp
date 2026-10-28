/**
 * @file DirectoryTest.cpp
 * @brief typed AccountStore pure inspect、认证租约和 middleware 接入测试。
 */

#include <gtest/gtest.h>


#include <memory>

#include <Prism/Account/Authenticator.hpp>
#include <Prism/Account/Store.hpp>
#include "../Runtime/AccountTestSupport.hpp"
#include <Prism/Contract/Services/Authentication.hpp>
#include <Prism/Foundation/Fault/Code.hpp>

namespace
{

    namespace Net = boost::asio;
    TEST(DirectoryAuthenticator, InspectIsPureAndAuthenticateOwnsLease)
    {
        auto Directory = std::make_shared<AccountStore>();
        const auto Record = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{7101}, .CredentialValue = Credential::Password("cred-a"), .Quota = {.MaxConnections = 1}});
        ASSERT_TRUE(Publish(*Directory, Record));
        Prism::DirectoryAuthenticator Auth(CompileView(*Directory));

        EXPECT_TRUE(InspectMatch(Auth, CredentialView::Password("cred-a")));
        EXPECT_FALSE(InspectMatch(Auth, CredentialView::Password("wrong")));
        EXPECT_EQ(Directory->FindById(Record.Materials->AccountId())->Runtime()->ActiveConnections(), 0U);

        auto Result = Auth.Authenticate(Prism::AuthenticationRequest{
            .Identity = "user", .Credential = CredentialView::Password("cred-a"),
            .Rate = RateRequest{0, 1, 1}});
        ASSERT_TRUE(Result.has_value());
        EXPECT_EQ(Result->AccountId(), Prism::AccountId{7101});
        ASSERT_TRUE(*Result);
        EXPECT_EQ(Directory->FindById(Record.Materials->AccountId())->Runtime()->ActiveConnections(), 1U);
        Result->Release();
        EXPECT_EQ(Directory->FindById(Record.Materials->AccountId())->Runtime()->ActiveConnections(), 0U);
    }

    TEST(DirectoryAuthenticator, MissingAndInvalidCredentialsDoNotAcquire)
    {
        auto Directory = std::make_shared<AccountStore>();
        ASSERT_TRUE(Publish(*Directory, MakeDefinition(AccountInput{.AccountId = Prism::AccountId{7102}, .CredentialValue = Credential::Token("token"), .Quota = {.MaxConnections = 1}})));
        Prism::DirectoryAuthenticator Auth(CompileView(*Directory));

        const auto Missing = Auth.Authenticate(Prism::AuthenticationRequest{
            .Credential = CredentialView::Token("missing")});
        EXPECT_FALSE(Missing.has_value());
        ASSERT_FALSE(Missing);
        EXPECT_EQ(Missing.error().Native, Prism::Account::MakeFailure(Prism::Account::FailureReason::NotFound).Native);

        const auto Invalid = Auth.Authenticate(Prism::AuthenticationRequest{
            .Credential = CredentialView{}});
        EXPECT_FALSE(Invalid.has_value());
        ASSERT_FALSE(Invalid);
        EXPECT_EQ(Invalid.error().Native, Prism::Account::MakeFailure(Prism::Account::FailureReason::InvalidCredential).Native);
    }

    TEST(DirectoryAuthenticator, QuotaAndRevocationAreTypedAuthenticateFailures)
    {
        auto Directory = std::make_shared<AccountStore>();
        const auto Record = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{7103}, .CredentialValue = Credential::Psk("psk"), .Quota = {.MaxConnections = 1}});
        ASSERT_TRUE(Publish(*Directory, Record));
        Prism::DirectoryAuthenticator Auth(CompileView(*Directory));

        auto Held = Auth.Authenticate(Prism::AuthenticationRequest{
            .Credential = CredentialView::Psk("psk")});
        ASSERT_TRUE(Held.has_value());
        const auto Busy = Auth.Authenticate(Prism::AuthenticationRequest{
            .Credential = CredentialView::Psk("psk")});
        EXPECT_FALSE(Busy.has_value());
        ASSERT_FALSE(Busy);
        EXPECT_EQ(Busy.error().Native, Prism::Account::MakeFailure(Prism::Account::FailureReason::ConnectionQuota).Native);
        Held->Release();

        EXPECT_TRUE(Directory->Revoke(Prism::AccountId{7103}));
        const auto Revoked = Auth.Authenticate(Prism::AuthenticationRequest{
            .Credential = CredentialView::Psk("psk")});
        EXPECT_FALSE(Revoked.has_value());
        ASSERT_FALSE(Revoked);
        EXPECT_EQ(Revoked.error().Native, Prism::Account::MakeFailure(Prism::Account::FailureReason::Revoked).Native);
    }

} // namespace
