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
#include <string>

#include <preview/Foundation/Authenticator.hpp>
#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Foundation/Fault/Handling.hpp>
#include <preview/Runtime/Middleware/Builtin/Auth.hpp>
#include <preview/Runtime/Middleware/Builtin/Dial.hpp>
#include <preview/Runtime/Middleware/Context.hpp>
#include <preview/Runtime/Middleware/Pipeline.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Fault = Preview::Fault;
    namespace Middleware = Preview::Middleware;
    namespace Network = Preview::Network;
    using Preview::RejectAuthenticator;
    using Preview::SharedTransmission;
    using Preview::StaticAuthenticator;

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

    TEST(AuthMiddleware, PassWritesIdentity)
    {
        Net::io_context IoContext;
        auto Auth = std::make_shared<StaticAuthenticator>("alice", "s3cret");
        Middleware::Builtin::AuthMiddleware AuthMiddlewareInstance(Auth);

        Middleware::Context MiddlewareContext;
        MiddlewareContext.RawIdentity = "alice";
        MiddlewareContext.RawSecret = "s3cret";
        SharedTransmission Inbound;

        Fault::Code ResultCode = Fault::Code::Success;
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void> { ResultCode = co_await AuthMiddlewareInstance.Handle(Inbound, MiddlewareContext); });
        EXPECT_EQ(ResultCode, Fault::Code::Success);
        EXPECT_EQ(MiddlewareContext.identity, "alice");
    }

    TEST(AuthMiddleware, WrongSecretFails)
    {
        Net::io_context IoContext;
        auto Auth = std::make_shared<StaticAuthenticator>("alice", "s3cret");
        Middleware::Builtin::AuthMiddleware AuthMiddlewareInstance(Auth);

        Middleware::Context MiddlewareContext;
        MiddlewareContext.RawIdentity = "alice";
        MiddlewareContext.RawSecret = "wrong";
        SharedTransmission Inbound;

        Fault::Code ResultCode = Fault::Code::Success;
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void> { ResultCode = co_await AuthMiddlewareInstance.Handle(Inbound, MiddlewareContext); });
        EXPECT_EQ(ResultCode, Fault::Code::AuthFailed);
        EXPECT_TRUE(MiddlewareContext.identity.empty());
    }

    TEST(AuthMiddleware, MissingCredentialFails)
    {
        Net::io_context IoContext;
        auto Auth = std::make_shared<StaticAuthenticator>("alice", "s3cret");
        Middleware::Builtin::AuthMiddleware AuthMiddlewareInstance(Auth);

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
        Middleware::Builtin::AuthMiddleware AuthMiddlewareInstance(Auth);

        Middleware::Context MiddlewareContext;
        MiddlewareContext.RawIdentity = "any";
        MiddlewareContext.RawSecret = "any";
        SharedTransmission Inbound;

        Fault::Code ResultCode = Fault::Code::Success;
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void> { ResultCode = co_await AuthMiddlewareInstance.Handle(Inbound, MiddlewareContext); });
        EXPECT_EQ(ResultCode, Fault::Code::AuthFailed);
    }

    TEST(AuthMiddleware, MissingAuthInstanceNotSupported)
    {
        Net::io_context IoContext;
        Middleware::Builtin::AuthMiddleware AuthMiddlewareInstance(nullptr);
        Middleware::Context MiddlewareContext;
        SharedTransmission Inbound;

        Fault::Code ResultCode = Fault::Code::Success;
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void> { ResultCode = co_await AuthMiddlewareInstance.Handle(Inbound, MiddlewareContext); });
        EXPECT_EQ(ResultCode, Fault::Code::NotSupported);
    }

    TEST(AuthMiddleware, CustomCredentialExtraction)
    {
        Net::io_context IoContext;
        auto Auth = std::make_shared<StaticAuthenticator>("bob", "pw");
        // 协议无关提取：模拟 HTTP Basic（凭据来自 Authorization 头）
        Middleware::Builtin::AuthMiddleware AuthMiddlewareInstance(
            Auth,
            [](const Middleware::Context &MiddlewareContext)
                -> std::optional<std::pair<std::string, std::string>>
            {
                if (MiddlewareContext.RawIdentity == "Basic Ym9iOnB3")
                {
                    return std::make_pair("bob", "pw");
                }
                return std::nullopt;
            });

        Middleware::Context MiddlewareContext;
        MiddlewareContext.RawIdentity = "Basic Ym9iOnB3";
        SharedTransmission Inbound;

        Fault::Code ResultCode = Fault::Code::Success;
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void> { ResultCode = co_await AuthMiddlewareInstance.Handle(Inbound, MiddlewareContext); });
        EXPECT_EQ(ResultCode, Fault::Code::Success);
        EXPECT_EQ(MiddlewareContext.identity, "bob");
    }

    TEST(AuthMiddleware, PipelineStopsOnAuthFailure)
    {
        Net::io_context IoContext;
        auto Auth = std::make_shared<StaticAuthenticator>("alice", "s3cret");

        int DialCalls = 0;
        auto Dial = std::make_shared<Middleware::Builtin::DialMiddleware>(
            [&](const Network::Target &) -> Net::awaitable<
                std::pair<Fault::Code, SharedTransmission>>
            {
                ++DialCalls;
                co_return std::pair{Fault::Code::Success, nullptr};
            });

        Middleware::Pipeline MiddlewarePipeline;
        MiddlewarePipeline.Add(std::make_shared<Middleware::Builtin::AuthMiddleware>(Auth))
            .Add(Dial);

        Middleware::Context MiddlewareContext;
        MiddlewareContext.RawIdentity = "alice";
        MiddlewareContext.RawSecret = "wrong"; // 认证失败
        SharedTransmission Inbound;

        Fault::Code ResultCode = Fault::Code::Success;
        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void> { ResultCode = co_await MiddlewarePipeline.Run(Inbound, MiddlewareContext); });
        EXPECT_EQ(ResultCode, Fault::Code::AuthFailed);
        EXPECT_EQ(DialCalls, 0); // 后续中间件未执行
    }

    TEST(AuthMiddleware, PipelineProceedsOnAuthPass)
    {
        Net::io_context IoContext;
        auto Auth = std::make_shared<StaticAuthenticator>("alice", "s3cret");

        Middleware::Context MiddlewareContext;
        MiddlewareContext.RawIdentity = "alice";
        MiddlewareContext.RawSecret = "s3cret";
        SharedTransmission Inbound;

        Middleware::Pipeline MiddlewarePipeline;
        MiddlewarePipeline.Add(std::make_shared<Middleware::Builtin::AuthMiddleware>(Auth));

        Fault::Code ResultCode = Fault::Code::Success;
        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void> { ResultCode = co_await MiddlewarePipeline.Run(Inbound, MiddlewareContext); });
        EXPECT_EQ(ResultCode, Fault::Code::Success);
        EXPECT_EQ(MiddlewareContext.identity, "alice");
    }

} // namespace
