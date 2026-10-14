/**
 * @file AuthDirectoryTest.cpp
 * @brief typed AccountStore pure inspect、认证租约和 middleware 接入测试。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <memory>
#include <optional>
#include <string>

#include <Preview/Account/Authenticator.hpp>
#include <Preview/Account/Store.hpp>
#include "AccountTestSupport.hpp"
#include <Preview/Contract/Services/Authentication.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Experiments/Preview/Authentication.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>

namespace
{

    namespace Net = boost::asio;
    TEST(DirectoryAuthenticator, InspectIsPureAndAuthenticateOwnsLease)
    {
        auto Directory = std::make_shared<AccountStore>();
        const auto Record = MakeDefinition(AccountInput{.AccountId = Preview::AccountId{7101}, .CredentialValue = Credential::Password("cred-a"), .Quota = {.MaxConnections = 1}});
        ASSERT_TRUE(Publish(*Directory, Record));
        Preview::DirectoryAuthenticator Auth(CompileView(*Directory));

        EXPECT_TRUE(InspectMatch(Auth, CredentialView::Password("cred-a")));
        EXPECT_FALSE(InspectMatch(Auth, CredentialView::Password("wrong")));
        EXPECT_EQ(Directory->FindById(Record.Materials->AccountId())->Runtime()->ActiveConnections(), 0U);

        auto Result = Auth.Authenticate(Preview::AuthenticationRequest{
            .Identity = "user", .Credential = CredentialView::Password("cred-a"),
            .Rate = RateRequest{0, 1, 1}});
        ASSERT_TRUE(Result.has_value());
        EXPECT_EQ(Result->AccountId(), Preview::AccountId{7101});
        ASSERT_TRUE(*Result);
        EXPECT_EQ(Directory->FindById(Record.Materials->AccountId())->Runtime()->ActiveConnections(), 1U);
        Result->Release();
        EXPECT_EQ(Directory->FindById(Record.Materials->AccountId())->Runtime()->ActiveConnections(), 0U);
    }

    TEST(DirectoryAuthenticator, MissingAndInvalidCredentialsDoNotAcquire)
    {
        auto Directory = std::make_shared<AccountStore>();
        ASSERT_TRUE(Publish(*Directory, MakeDefinition(AccountInput{.AccountId = Preview::AccountId{7102}, .CredentialValue = Credential::Token("token"), .Quota = {.MaxConnections = 1}})));
        Preview::DirectoryAuthenticator Auth(CompileView(*Directory));

        const auto Missing = Auth.Authenticate(Preview::AuthenticationRequest{
            .Credential = CredentialView::Token("missing")});
        EXPECT_FALSE(Missing.has_value());
        ASSERT_FALSE(Missing);
        EXPECT_EQ(Missing.error().Native, Preview::Account::MakeFailure(Preview::Account::FailureReason::NotFound).Native);

        const auto Invalid = Auth.Authenticate(Preview::AuthenticationRequest{
            .Credential = CredentialView{}});
        EXPECT_FALSE(Invalid.has_value());
        ASSERT_FALSE(Invalid);
        EXPECT_EQ(Invalid.error().Native, Preview::Account::MakeFailure(Preview::Account::FailureReason::InvalidCredential).Native);
    }

    TEST(DirectoryAuthenticator, QuotaAndRevocationAreTypedAuthenticateFailures)
    {
        auto Directory = std::make_shared<AccountStore>();
        const auto Record = MakeDefinition(AccountInput{.AccountId = Preview::AccountId{7103}, .CredentialValue = Credential::Psk("psk"), .Quota = {.MaxConnections = 1}});
        ASSERT_TRUE(Publish(*Directory, Record));
        Preview::DirectoryAuthenticator Auth(CompileView(*Directory));

        auto Held = Auth.Authenticate(Preview::AuthenticationRequest{
            .Credential = CredentialView::Psk("psk")});
        ASSERT_TRUE(Held.has_value());
        const auto Busy = Auth.Authenticate(Preview::AuthenticationRequest{
            .Credential = CredentialView::Psk("psk")});
        EXPECT_FALSE(Busy.has_value());
        ASSERT_FALSE(Busy);
        EXPECT_EQ(Busy.error().Native, Preview::Account::MakeFailure(Preview::Account::FailureReason::ConnectionQuota).Native);
        Held->Release();

        EXPECT_TRUE(Directory->Revoke(Preview::AccountId{7103}));
        const auto Revoked = Auth.Authenticate(Preview::AuthenticationRequest{
            .Credential = CredentialView::Psk("psk")});
        EXPECT_FALSE(Revoked.has_value());
        ASSERT_FALSE(Revoked);
        EXPECT_EQ(Revoked.error().Native, Preview::Account::MakeFailure(Preview::Account::FailureReason::Revoked).Native);
    }

    TEST(DirectoryAuthenticator, MiddlewareIntegrationUsesTypedLease)
    {
        Net::io_context IoContext;
        auto Directory = std::make_shared<AccountStore>();
        const auto Record = MakeDefinition(AccountInput{.AccountId = Preview::AccountId{7104}, .CredentialValue = Credential::Password("cred-a"), .Quota = {.MaxConnections = 5}});
        ASSERT_TRUE(Publish(*Directory, Record));
        auto Auth = std::make_shared<Preview::DirectoryAuthenticator>(CompileView(*Directory));
        std::string Secret = "cred-a";
        Preview::Experiments::AuthenticationCheck Middleware(
            Auth,
            [&Secret](const Preview::Middleware::Context &)
                -> std::optional<Preview::Experiments::AuthenticationCheck::CredentialInput>
            {
                return Preview::Experiments::AuthenticationCheck::CredentialInput{
                    .Identity = "user",
                    .Credential = std::make_shared<const Credential>(Credential::Password(Secret))};
            });

        Preview::Middleware::Context Context;
        Preview::SharedTransmission Inbound;
        Preview::Fault::Code Accepted = Preview::Fault::Code::Success;
        Preview::Fault::Code Rejected = Preview::Fault::Code::Success;
        std::exception_ptr Exception;
        Net::co_spawn(IoContext,
            [&]() -> Net::awaitable<void>
            {
                Accepted = co_await Middleware.Handle(Inbound, Context);
                EXPECT_TRUE(Context.Identity().empty()); // 成功identity来自材料，不复制未约束的wire label。
                EXPECT_TRUE(Context.AccountLease());
                EXPECT_EQ(Directory->FindById(Record.Materials->AccountId())->Runtime()->ActiveConnections(), 1U);
                Context.AccountLease().Release();
                Secret = "wrong";
                Rejected = co_await Middleware.Handle(Inbound, Context);
            },
            [&](std::exception_ptr Error)
            {
                Exception = Error;
                IoContext.stop();
            });
        IoContext.run();
        ASSERT_FALSE(Exception);
        EXPECT_EQ(Accepted, Preview::Fault::Code::Success);
        EXPECT_EQ(Rejected, Preview::Fault::Code::AuthFailed);
        EXPECT_TRUE(Context.Identity().empty());
        EXPECT_FALSE(Context.AccountLease());
        EXPECT_EQ(Directory->FindById(Record.Materials->AccountId())->Runtime()->ActiveConnections(), 0U);
    }

} // namespace
