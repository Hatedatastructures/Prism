/**
 * @file AuthMiddlewareTest.cpp
 * @brief 认证中间件测试（T4-1）
 * @details 覆盖：
 *          - 认证通过：identity 写入 ctx
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

#include <common/Core/Authenticator.hpp>
#include <common/Core/Fault/Code.hpp>
#include <common/Core/Fault/Handling.hpp>
#include <common/Core/Middleware/Builtin/Auth.hpp>
#include <common/Core/Middleware/Builtin/Dial.hpp>
#include <common/Core/Middleware/Context.hpp>
#include <common/Core/Middleware/Pipeline.hpp>

namespace
{

    namespace net = boost::asio;

    auto run_coro(net::io_context &ioc, auto coro)
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro), [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    TEST(AuthMiddleware, PassWritesIdentity)
    {
        net::io_context ioc;
        auto Auth = std::make_shared<Preview::StaticAuthenticator>("alice", "s3cret");
        Preview::Middleware::Builtin::AuthMiddleware mw(Auth);

        Preview::Middleware::Context ctx;
        ctx.RawIdentity = "alice";
        ctx.RawSecret = "s3cret";
        Preview::SharedTransmission inbound;

        Preview::Fault::Code rc = Preview::Fault::Code::success;
        run_coro(ioc, [&]() -> net::awaitable<void> { rc = co_await mw.Handle(inbound, ctx); });
        EXPECT_EQ(rc, Preview::Fault::Code::success);
        EXPECT_EQ(ctx.identity, "alice");
    }

    TEST(AuthMiddleware, WrongSecretFails)
    {
        net::io_context ioc;
        auto Auth = std::make_shared<Preview::StaticAuthenticator>("alice", "s3cret");
        Preview::Middleware::Builtin::AuthMiddleware mw(Auth);

        Preview::Middleware::Context ctx;
        ctx.RawIdentity = "alice";
        ctx.RawSecret = "wrong";
        Preview::SharedTransmission inbound;

        Preview::Fault::Code rc = Preview::Fault::Code::success;
        run_coro(ioc, [&]() -> net::awaitable<void> { rc = co_await mw.Handle(inbound, ctx); });
        EXPECT_EQ(rc, Preview::Fault::Code::auth_failed);
        EXPECT_TRUE(ctx.identity.empty());
    }

    TEST(AuthMiddleware, MissingCredentialFails)
    {
        net::io_context ioc;
        auto Auth = std::make_shared<Preview::StaticAuthenticator>("alice", "s3cret");
        Preview::Middleware::Builtin::AuthMiddleware mw(Auth);

        Preview::Middleware::Context ctx; // 无凭据
        Preview::SharedTransmission inbound;

        Preview::Fault::Code rc = Preview::Fault::Code::success;
        run_coro(ioc, [&]() -> net::awaitable<void> { rc = co_await mw.Handle(inbound, ctx); });
        EXPECT_EQ(rc, Preview::Fault::Code::auth_failed);
    }

    TEST(AuthMiddleware, RejectAuthenticatorFails)
    {
        net::io_context ioc;
        auto Auth = std::make_shared<Preview::RejectAuthenticator>();
        Preview::Middleware::Builtin::AuthMiddleware mw(Auth);

        Preview::Middleware::Context ctx;
        ctx.RawIdentity = "any";
        ctx.RawSecret = "any";
        Preview::SharedTransmission inbound;

        Preview::Fault::Code rc = Preview::Fault::Code::success;
        run_coro(ioc, [&]() -> net::awaitable<void> { rc = co_await mw.Handle(inbound, ctx); });
        EXPECT_EQ(rc, Preview::Fault::Code::auth_failed);
    }

    TEST(AuthMiddleware, MissingAuthInstanceNotSupported)
    {
        net::io_context ioc;
        Preview::Middleware::Builtin::AuthMiddleware mw(nullptr);
        Preview::Middleware::Context ctx;
        Preview::SharedTransmission inbound;

        Preview::Fault::Code rc = Preview::Fault::Code::success;
        run_coro(ioc, [&]() -> net::awaitable<void> { rc = co_await mw.Handle(inbound, ctx); });
        EXPECT_EQ(rc, Preview::Fault::Code::not_supported);
    }

    TEST(AuthMiddleware, CustomCredentialExtraction)
    {
        net::io_context ioc;
        auto Auth = std::make_shared<Preview::StaticAuthenticator>("bob", "pw");
        // 协议无关提取：模拟 HTTP Basic（凭据来自 Authorization 头）
        Preview::Middleware::Builtin::AuthMiddleware mw(
            Auth,
            [](const Preview::Middleware::Context &ctx)
                -> std::optional<std::pair<std::string, std::string>>
            {
                if (ctx.RawIdentity == "Basic Ym9iOnB3")
                {
                    return std::make_pair("bob", "pw");
                }
                return std::nullopt;
            });

        Preview::Middleware::Context ctx;
        ctx.RawIdentity = "Basic Ym9iOnB3";
        Preview::SharedTransmission inbound;

        Preview::Fault::Code rc = Preview::Fault::Code::success;
        run_coro(ioc, [&]() -> net::awaitable<void> { rc = co_await mw.Handle(inbound, ctx); });
        EXPECT_EQ(rc, Preview::Fault::Code::success);
        EXPECT_EQ(ctx.identity, "bob");
    }

    TEST(AuthMiddleware, PipelineStopsOnAuthFailure)
    {
        net::io_context ioc;
        auto Auth = std::make_shared<Preview::StaticAuthenticator>("alice", "s3cret");

        int dial_calls = 0;
        auto Dial = std::make_shared<Preview::Middleware::Builtin::DialMiddleware>(
            [&](const Preview::Network::Target &) -> net::awaitable<
                std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
            {
                ++dial_calls;
                co_return std::pair{Preview::Fault::Code::success, nullptr};
            });

        Preview::Middleware::Pipeline pipe;
        pipe.Add(std::make_shared<Preview::Middleware::Builtin::AuthMiddleware>(Auth))
            .Add(Dial);

        Preview::Middleware::Context ctx;
        ctx.RawIdentity = "alice";
        ctx.RawSecret = "wrong"; // 认证失败
        Preview::SharedTransmission inbound;

        Preview::Fault::Code rc = Preview::Fault::Code::success;
        run_coro(ioc,
                 [&]() -> net::awaitable<void> { rc = co_await pipe.Run(inbound, ctx); });
        EXPECT_EQ(rc, Preview::Fault::Code::auth_failed);
        EXPECT_EQ(dial_calls, 0); // 后续中间件未执行
    }

    TEST(AuthMiddleware, PipelineProceedsOnAuthPass)
    {
        net::io_context ioc;
        auto Auth = std::make_shared<Preview::StaticAuthenticator>("alice", "s3cret");

        Preview::Middleware::Context ctx;
        ctx.RawIdentity = "alice";
        ctx.RawSecret = "s3cret";
        Preview::SharedTransmission inbound;

        Preview::Middleware::Pipeline pipe;
        pipe.Add(std::make_shared<Preview::Middleware::Builtin::AuthMiddleware>(Auth));

        Preview::Fault::Code rc = Preview::Fault::Code::success;
        run_coro(ioc,
                 [&]() -> net::awaitable<void> { rc = co_await pipe.Run(inbound, ctx); });
        EXPECT_EQ(rc, Preview::Fault::Code::success);
        EXPECT_EQ(ctx.identity, "alice");
    }

} // namespace
