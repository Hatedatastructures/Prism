/**
 * @file AuthMiddlewareTest.cpp
 * @brief 认证中间件测试（T4-1）
 * @details 覆盖：
 *          - 认证通过：identity 写入 MiddlewareContext
 *          - 认证失败 / 缺失凭据 / 总是拒绝 → auth_failed
 *          - 凭据提取函数注入（协议无关）
 *          - Pipeline 集成：认证失败终止管线，通过后进入 Dial/relay
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <Preview/Account/Account.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Experiments/Preview/Authentication.hpp>
#include <Preview/Runtime/Middleware/Builtin/Dial.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Runtime/Middleware/Pipeline.hpp>
#include <TestSupport/Preview/ProviderBindings.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Fault = Preview::Fault;
    namespace Middleware = Preview::Middleware;
    namespace Network = Preview::Network;
    using Preview::RejectAuthenticator;
    using Preview::SharedTransmission;
    using AuthMiddleware = Preview::Experiments::AuthenticationCheck;
    using Credential = Preview::Account::Credential;

    auto Input(std::string Identity, std::string Secret) -> AuthMiddleware::CredentialFn
    {
        return [Identity = std::move(Identity), Secret = std::move(Secret)](const Middleware::Context &)
            -> std::optional<AuthMiddleware::CredentialInput>
        {
            return AuthMiddleware::CredentialInput{
                .Identity = Identity,
                .Credential = std::make_shared<const Credential>(Credential::Password(Secret))};
        };
    }

    template <typename Type>
    concept HasRawSecret = requires(Type Value) { Value.RawSecret; };

    static_assert(!HasRawSecret<Middleware::Context>);

    auto RunCoroutine(Net::io_context &IoContext, auto Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Coroutine),
                      [&](std::exception_ptr ErrorValue)
                      {
                          Exception = ErrorValue;
                          IoContext.stop();
                      });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    auto ExtractBobCredential(const Middleware::Context &MiddlewareContext)
        -> std::optional<AuthMiddleware::CredentialInput>
    {
        if (static_cast<std::uint16_t>(MiddlewareContext.DataPlane.Protocol) == 1)
        {
            return AuthMiddleware::CredentialInput{
                .Identity = "bob",
                .Credential = std::make_shared<const Credential>(Credential::Password("pw"))};
        }
        return std::nullopt;
    }

    TEST(AuthMiddleware, PassWritesIdentity)
    {
        Net::io_context IoContext;
        auto Auth = Preview::Testing::ProviderAccount(Preview::Testing::ProviderAccountInput{Preview::AccountId{1U}, Credential::Password("s3cret"), "alice", "alice", {}})->Authenticator;
        AuthMiddleware AuthMiddlewareInstance(Auth, Input("alice", "s3cret"));

        Middleware::Context MiddlewareContext;
        SharedTransmission Inbound;

        Fault::Code ResultCode = Fault::Code::Success;
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void> { ResultCode = co_await AuthMiddlewareInstance.Handle(Inbound, MiddlewareContext); });
        EXPECT_EQ(ResultCode, Fault::Code::Success);
        EXPECT_EQ(MiddlewareContext.Identity(), "alice");
        EXPECT_EQ(MiddlewareContext.DisplayIdentity(), "alice");
    }

    TEST(AuthMiddleware, UserForLogFallsBackToAccountId)
    {
        Middleware::Context Context;
        Context.AccountId() = Preview::AccountId{7003};
        EXPECT_EQ(Context.UserForLog(), "7003");
        Context.DisplayIdentity() = "safe-user";
        EXPECT_EQ(Context.UserForLog(), "safe-user");
    }

    TEST(AuthMiddleware, ValueCredentialWritesTypedAccountWithoutRawSecret)
    {
        Net::io_context IoContext;
        using Preview::Account::Credential;

        auto Directory = Preview::Testing::ProviderAccount(Preview::Testing::ProviderAccountInput{
            .Id = Preview::AccountId{7002},
            .CredentialValue = Credential::Password("middleware-password"),
            .Identity = "alice",
            .DisplayIdentity = "alice",
            .Quota = {.MaxConnections = 1}});
        const auto Record = Directory->Store->FindById(Preview::AccountId{7002});
        ASSERT_TRUE(Record);
        auto Auth = Directory->Authenticator;

        Preview::Experiments::AuthenticationCheck AuthMiddlewareInstance(
            Auth,
            [](const Middleware::Context &)
                -> std::optional<AuthMiddleware::CredentialInput>
            {
                return AuthMiddleware::CredentialInput{
                    .Identity = "alice",
                    .Credential = std::make_shared<const Credential>(Credential::Password("middleware-password"))};
            });

        Middleware::Context MiddlewareContext;
        SharedTransmission Inbound;
        Fault::Code ResultCode = Fault::Code::Success;
        RunCoroutine(IoContext,
                     [&]() -> Net::awaitable<void>
                     { ResultCode = co_await AuthMiddlewareInstance.Handle(Inbound, MiddlewareContext); });

        EXPECT_EQ(ResultCode, Fault::Code::Success);
        EXPECT_EQ(MiddlewareContext.AccountId(), Preview::AccountId{7002});
        EXPECT_EQ(MiddlewareContext.Identity(), "alice");
        EXPECT_EQ(MiddlewareContext.Identity().find("middleware-password"), std::string::npos);
        EXPECT_EQ(MiddlewareContext.DisplayIdentity(), "alice");
        EXPECT_EQ(MiddlewareContext.UserForLog(), "alice");
        EXPECT_TRUE(MiddlewareContext.AccountLease());
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);
        MiddlewareContext.AccountLease().Release();
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
    }

    TEST(AuthMiddleware, WrongSecretFails)
    {
        Net::io_context IoContext;
        auto Auth = Preview::Testing::ProviderAccount(Preview::Testing::ProviderAccountInput{Preview::AccountId{1U}, Credential::Password("s3cret"), "alice", "alice", {}})->Authenticator;
        AuthMiddleware AuthMiddlewareInstance(Auth, Input("alice", "wrong"));

        Middleware::Context MiddlewareContext;
        SharedTransmission Inbound;

        Fault::Code ResultCode = Fault::Code::Success;
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void> { ResultCode = co_await AuthMiddlewareInstance.Handle(Inbound, MiddlewareContext); });
        EXPECT_EQ(ResultCode, Fault::Code::AuthFailed);
        EXPECT_TRUE(MiddlewareContext.Identity().empty());
    }

    TEST(AuthMiddleware, MissingCredentialFails)
    {
        Net::io_context IoContext;
        auto Auth = Preview::Testing::ProviderAccount(Preview::Testing::ProviderAccountInput{Preview::AccountId{1U}, Credential::Password("s3cret"), "alice", "alice", {}})->Authenticator;
        AuthMiddleware AuthMiddlewareInstance(Auth);

        Middleware::Context MiddlewareContext; // 无凭据
        SharedTransmission Inbound;

        Fault::Code ResultCode = Fault::Code::Success;
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void> { ResultCode = co_await AuthMiddlewareInstance.Handle(Inbound, MiddlewareContext); });
        EXPECT_EQ(ResultCode, Fault::Code::AuthFailed);
    }

    TEST(AuthMiddleware, RejectAuthenticatorFails)
    {
        Net::io_context IoContext;
        auto Auth = std::make_shared<RejectAuthenticator>();
        AuthMiddleware AuthMiddlewareInstance(Auth, Input("any", "any"));

        Middleware::Context MiddlewareContext;
        SharedTransmission Inbound;

        Fault::Code ResultCode = Fault::Code::Success;
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void> { ResultCode = co_await AuthMiddlewareInstance.Handle(Inbound, MiddlewareContext); });
        EXPECT_EQ(ResultCode, Fault::Code::AuthFailed);
    }

    TEST(AuthMiddleware, MissingAuthInstanceNotSupported)
    {
        Net::io_context IoContext;
        AuthMiddleware AuthMiddlewareInstance(nullptr);
        Middleware::Context MiddlewareContext;
        SharedTransmission Inbound;

        Fault::Code ResultCode = Fault::Code::Success;
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void> { ResultCode = co_await AuthMiddlewareInstance.Handle(Inbound, MiddlewareContext); });
        EXPECT_EQ(ResultCode, Fault::Code::NotSupported);
    }

    TEST(AuthMiddleware, CustomCredentialExtraction)
    {
        Net::io_context IoContext;
        auto Auth = Preview::Testing::ProviderAccount(Preview::Testing::ProviderAccountInput{Preview::AccountId{1U}, Credential::Password("pw"), "bob", "bob", {}})->Authenticator;
        // 协议无关提取：模拟 HTTP Basic（凭据来自 Authorization 头）
        AuthMiddleware AuthMiddlewareInstance(
            Auth,
            ExtractBobCredential);

        Middleware::Context MiddlewareContext;
        MiddlewareContext.DataPlane.Protocol = Preview::Contract::ProtocolType::Http;
        SharedTransmission Inbound;

        Fault::Code ResultCode = Fault::Code::Success;
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void> { ResultCode = co_await AuthMiddlewareInstance.Handle(Inbound, MiddlewareContext); });
        EXPECT_EQ(ResultCode, Fault::Code::Success);
        EXPECT_EQ(MiddlewareContext.Identity(), "bob");
    }

    TEST(AuthMiddleware, PipelineStopsOnAuthFailure)
    {
        Net::io_context IoContext;
        auto Auth = Preview::Testing::ProviderAccount(Preview::Testing::ProviderAccountInput{Preview::AccountId{1U}, Credential::Password("s3cret"), "alice", "alice", {}})->Authenticator;

        int DialCalls = 0;
        auto Dial = std::make_shared<Middleware::Builtin::DialMiddleware>(
            [&](const Network::Target &) -> Net::awaitable<
                std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>
            {
                ++DialCalls;
                co_return Preview::SharedTransmission{};
            });

        Middleware::Pipeline MiddlewarePipeline;
        MiddlewarePipeline.Add(std::make_shared<AuthMiddleware>(Auth, Input("alice", "wrong")))
            .Add(Dial);

        Middleware::Context MiddlewareContext;
        SharedTransmission Inbound;

        Fault::Code ResultCode = Fault::Code::Success;
        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void> { ResultCode = co_await [&]() -> Net::awaitable<Preview::Fault::Code> { MiddlewareContext.Inbound() = Inbound; co_return co_await MiddlewarePipeline.Run(MiddlewareContext); }(); });
        EXPECT_EQ(ResultCode, Fault::Code::AuthFailed);
        EXPECT_EQ(DialCalls, 0); // 后续中间件未执行
    }

    TEST(AuthMiddleware, PipelineProceedsOnAuthPass)
    {
        Net::io_context IoContext;
        auto Auth = Preview::Testing::ProviderAccount(Preview::Testing::ProviderAccountInput{Preview::AccountId{1U}, Credential::Password("s3cret"), "alice", "alice", {}})->Authenticator;

        Middleware::Context MiddlewareContext;
        SharedTransmission Inbound;

        Middleware::Pipeline MiddlewarePipeline;
        MiddlewarePipeline.Add(std::make_shared<AuthMiddleware>(Auth, Input("alice", "s3cret")));

        Fault::Code ResultCode = Fault::Code::Success;
        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void> { ResultCode = co_await [&]() -> Net::awaitable<Preview::Fault::Code> { MiddlewareContext.Inbound() = Inbound; co_return co_await MiddlewarePipeline.Run(MiddlewareContext); }(); });
        EXPECT_EQ(ResultCode, Fault::Code::Success);
        EXPECT_EQ(MiddlewareContext.Identity(), "alice");
    }

} // namespace
