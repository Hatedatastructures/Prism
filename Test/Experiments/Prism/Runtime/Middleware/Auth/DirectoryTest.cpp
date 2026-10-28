/**
 * @file DirectoryTest.cpp
 * @brief DirectoryAuthenticator 与认证中间件的 typed lease 集成测试。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <exception>
#include <memory>
#include <optional>
#include <string>

#include <Experiments/Prism/Runtime/Middleware/Auth/Authentication.hpp>
#include <Test/Prism/Account/Runtime/AccountTestSupport.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Account/Store.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>

namespace
{
    namespace Net = boost::asio;

    TEST(DirectoryAuthenticator, MiddlewareIntegrationUsesTypedLease)
    {
        Net::io_context IoContext;
        auto Directory = std::make_shared<AccountStore>();
        const auto Record = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{7104}, .CredentialValue = Credential::Password("cred-a"), .Quota = {.MaxConnections = 5}});
        ASSERT_TRUE(Publish(*Directory, Record));
        auto Auth = std::make_shared<Prism::DirectoryAuthenticator>(CompileView(*Directory));
        std::string Secret = "cred-a";
        Prism::Experiments::AuthenticationCheck Middleware(
            Auth,
            [&Secret](const Prism::Middleware::Context &)
                -> std::optional<Prism::Experiments::AuthenticationCheck::CredentialInput>
            {
                return Prism::Experiments::AuthenticationCheck::CredentialInput{
                    .Identity = "user",
                    .Credential = std::make_shared<const Credential>(Credential::Password(Secret))};
            });

        Prism::Middleware::Context Context;
        Prism::SharedTransmission Inbound;
        Prism::Fault::Failure Accepted;
        Prism::Fault::Failure Rejected;
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
        EXPECT_TRUE(Accepted.Succeeded());
        EXPECT_EQ(Rejected.Code, Prism::Fault::Code::AuthFailed);
        EXPECT_TRUE(Rejected.Failed());
        EXPECT_TRUE(Context.Identity().empty());
        EXPECT_FALSE(Context.AccountLease());
        EXPECT_EQ(Directory->FindById(Record.Materials->AccountId())->Runtime()->ActiveConnections(), 0U);
    }

} // namespace
