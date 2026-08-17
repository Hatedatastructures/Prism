/**
 * @file AuthMiddlewareTest.cpp
 * @brief 认证中间件测试（T4-1）
 * @details 覆盖：
 *          - 认证通过：identity 写入 ctx
 *          - 认证失败 / 缺失凭据 / 总是拒绝 → auth_failed
 *          - 凭据提取函数注入（协议无关）
 *          - pipeline 集成：认证失败终止管线，通过后进入 dial/relay
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <memory>
#include <string>

#include <common/core/authenticator.hpp>
#include <common/core/fault/code.hpp>
#include <common/core/fault/handling.hpp>
#include <common/core/middleware/builtin/auth.hpp>
#include <common/core/middleware/builtin/dial.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/middleware/pipeline.hpp>

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
        auto auth = std::make_shared<preview::static_authenticator>("alice", "s3cret");
        preview::middleware::builtin::auth_middleware mw(auth);

        preview::middleware::context ctx;
        ctx.raw_identity = "alice";
        ctx.raw_secret = "s3cret";
        preview::shared_transmission inbound;

        preview::fault::code rc = preview::fault::code::success;
        run_coro(ioc, [&]() -> net::awaitable<void> { rc = co_await mw.handle(inbound, ctx); });
        EXPECT_EQ(rc, preview::fault::code::success);
        EXPECT_EQ(ctx.identity, "alice");
    }

    TEST(AuthMiddleware, WrongSecretFails)
    {
        net::io_context ioc;
        auto auth = std::make_shared<preview::static_authenticator>("alice", "s3cret");
        preview::middleware::builtin::auth_middleware mw(auth);

        preview::middleware::context ctx;
        ctx.raw_identity = "alice";
        ctx.raw_secret = "wrong";
        preview::shared_transmission inbound;

        preview::fault::code rc = preview::fault::code::success;
        run_coro(ioc, [&]() -> net::awaitable<void> { rc = co_await mw.handle(inbound, ctx); });
        EXPECT_EQ(rc, preview::fault::code::auth_failed);
        EXPECT_TRUE(ctx.identity.empty());
    }

    TEST(AuthMiddleware, MissingCredentialFails)
    {
        net::io_context ioc;
        auto auth = std::make_shared<preview::static_authenticator>("alice", "s3cret");
        preview::middleware::builtin::auth_middleware mw(auth);

        preview::middleware::context ctx; // 无凭据
        preview::shared_transmission inbound;

        preview::fault::code rc = preview::fault::code::success;
        run_coro(ioc, [&]() -> net::awaitable<void> { rc = co_await mw.handle(inbound, ctx); });
        EXPECT_EQ(rc, preview::fault::code::auth_failed);
    }

    TEST(AuthMiddleware, RejectAuthenticatorFails)
    {
        net::io_context ioc;
        auto auth = std::make_shared<preview::reject_authenticator>();
        preview::middleware::builtin::auth_middleware mw(auth);

        preview::middleware::context ctx;
        ctx.raw_identity = "any";
        ctx.raw_secret = "any";
        preview::shared_transmission inbound;

        preview::fault::code rc = preview::fault::code::success;
        run_coro(ioc, [&]() -> net::awaitable<void> { rc = co_await mw.handle(inbound, ctx); });
        EXPECT_EQ(rc, preview::fault::code::auth_failed);
    }

    TEST(AuthMiddleware, MissingAuthInstanceNotSupported)
    {
        net::io_context ioc;
        preview::middleware::builtin::auth_middleware mw(nullptr);
        preview::middleware::context ctx;
        preview::shared_transmission inbound;

        preview::fault::code rc = preview::fault::code::success;
        run_coro(ioc, [&]() -> net::awaitable<void> { rc = co_await mw.handle(inbound, ctx); });
        EXPECT_EQ(rc, preview::fault::code::not_supported);
    }

    TEST(AuthMiddleware, CustomCredentialExtraction)
    {
        net::io_context ioc;
        auto auth = std::make_shared<preview::static_authenticator>("bob", "pw");
        // 协议无关提取：模拟 HTTP Basic（凭据来自 Authorization 头）
        preview::middleware::builtin::auth_middleware mw(
            auth,
            [](const preview::middleware::context &ctx)
                -> std::optional<std::pair<std::string, std::string>>
            {
                if (ctx.raw_identity == "Basic Ym9iOnB3")
                {
                    return std::make_pair("bob", "pw");
                }
                return std::nullopt;
            });

        preview::middleware::context ctx;
        ctx.raw_identity = "Basic Ym9iOnB3";
        preview::shared_transmission inbound;

        preview::fault::code rc = preview::fault::code::success;
        run_coro(ioc, [&]() -> net::awaitable<void> { rc = co_await mw.handle(inbound, ctx); });
        EXPECT_EQ(rc, preview::fault::code::success);
        EXPECT_EQ(ctx.identity, "bob");
    }

    TEST(AuthMiddleware, PipelineStopsOnAuthFailure)
    {
        net::io_context ioc;
        auto auth = std::make_shared<preview::static_authenticator>("alice", "s3cret");

        int dial_calls = 0;
        auto dial = std::make_shared<preview::middleware::builtin::dial_middleware>(
            [&](const preview::network::target &) -> net::awaitable<
                std::pair<preview::fault::code, preview::shared_transmission>>
            {
                ++dial_calls;
                co_return std::pair{preview::fault::code::success, nullptr};
            });

        preview::middleware::pipeline pipe;
        pipe.add(std::make_shared<preview::middleware::builtin::auth_middleware>(auth))
            .add(dial);

        preview::middleware::context ctx;
        ctx.raw_identity = "alice";
        ctx.raw_secret = "wrong"; // 认证失败
        preview::shared_transmission inbound;

        preview::fault::code rc = preview::fault::code::success;
        run_coro(ioc,
                 [&]() -> net::awaitable<void> { rc = co_await pipe.run(inbound, ctx); });
        EXPECT_EQ(rc, preview::fault::code::auth_failed);
        EXPECT_EQ(dial_calls, 0); // 后续中间件未执行
    }

    TEST(AuthMiddleware, PipelineProceedsOnAuthPass)
    {
        net::io_context ioc;
        auto auth = std::make_shared<preview::static_authenticator>("alice", "s3cret");

        preview::middleware::context ctx;
        ctx.raw_identity = "alice";
        ctx.raw_secret = "s3cret";
        preview::shared_transmission inbound;

        preview::middleware::pipeline pipe;
        pipe.add(std::make_shared<preview::middleware::builtin::auth_middleware>(auth));

        preview::fault::code rc = preview::fault::code::success;
        run_coro(ioc,
                 [&]() -> net::awaitable<void> { rc = co_await pipe.run(inbound, ctx); });
        EXPECT_EQ(rc, preview::fault::code::success);
        EXPECT_EQ(ctx.identity, "alice");
    }

} // namespace
