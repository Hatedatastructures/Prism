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
        auto auth = std::make_shared<psmtest::static_authenticator>("alice", "s3cret");
        psmtest::middleware::builtin::auth_middleware mw(auth);

        psmtest::middleware::context ctx;
        ctx.raw_identity = "alice";
        ctx.raw_secret = "s3cret";
        psmtest::shared_transmission inbound;

        psmtest::fault::code rc = psmtest::fault::code::success;
        run_coro(ioc, [&]() -> net::awaitable<void> { rc = co_await mw.handle(inbound, ctx); });
        EXPECT_EQ(rc, psmtest::fault::code::success);
        EXPECT_EQ(ctx.identity, "alice");
    }

    TEST(AuthMiddleware, WrongSecretFails)
    {
        net::io_context ioc;
        auto auth = std::make_shared<psmtest::static_authenticator>("alice", "s3cret");
        psmtest::middleware::builtin::auth_middleware mw(auth);

        psmtest::middleware::context ctx;
        ctx.raw_identity = "alice";
        ctx.raw_secret = "wrong";
        psmtest::shared_transmission inbound;

        psmtest::fault::code rc = psmtest::fault::code::success;
        run_coro(ioc, [&]() -> net::awaitable<void> { rc = co_await mw.handle(inbound, ctx); });
        EXPECT_EQ(rc, psmtest::fault::code::auth_failed);
        EXPECT_TRUE(ctx.identity.empty());
    }

    TEST(AuthMiddleware, MissingCredentialFails)
    {
        net::io_context ioc;
        auto auth = std::make_shared<psmtest::static_authenticator>("alice", "s3cret");
        psmtest::middleware::builtin::auth_middleware mw(auth);

        psmtest::middleware::context ctx; // 无凭据
        psmtest::shared_transmission inbound;

        psmtest::fault::code rc = psmtest::fault::code::success;
        run_coro(ioc, [&]() -> net::awaitable<void> { rc = co_await mw.handle(inbound, ctx); });
        EXPECT_EQ(rc, psmtest::fault::code::auth_failed);
    }

    TEST(AuthMiddleware, RejectAuthenticatorFails)
    {
        net::io_context ioc;
        auto auth = std::make_shared<psmtest::reject_authenticator>();
        psmtest::middleware::builtin::auth_middleware mw(auth);

        psmtest::middleware::context ctx;
        ctx.raw_identity = "any";
        ctx.raw_secret = "any";
        psmtest::shared_transmission inbound;

        psmtest::fault::code rc = psmtest::fault::code::success;
        run_coro(ioc, [&]() -> net::awaitable<void> { rc = co_await mw.handle(inbound, ctx); });
        EXPECT_EQ(rc, psmtest::fault::code::auth_failed);
    }

    TEST(AuthMiddleware, MissingAuthInstanceNotSupported)
    {
        net::io_context ioc;
        psmtest::middleware::builtin::auth_middleware mw(nullptr);
        psmtest::middleware::context ctx;
        psmtest::shared_transmission inbound;

        psmtest::fault::code rc = psmtest::fault::code::success;
        run_coro(ioc, [&]() -> net::awaitable<void> { rc = co_await mw.handle(inbound, ctx); });
        EXPECT_EQ(rc, psmtest::fault::code::not_supported);
    }

    TEST(AuthMiddleware, CustomCredentialExtraction)
    {
        net::io_context ioc;
        auto auth = std::make_shared<psmtest::static_authenticator>("bob", "pw");
        // 协议无关提取：模拟 HTTP Basic（凭据来自 Authorization 头）
        psmtest::middleware::builtin::auth_middleware mw(
            auth,
            [](const psmtest::middleware::context &ctx)
                -> std::optional<std::pair<std::string, std::string>>
            {
                if (ctx.raw_identity == "Basic Ym9iOnB3")
                {
                    return std::make_pair("bob", "pw");
                }
                return std::nullopt;
            });

        psmtest::middleware::context ctx;
        ctx.raw_identity = "Basic Ym9iOnB3";
        psmtest::shared_transmission inbound;

        psmtest::fault::code rc = psmtest::fault::code::success;
        run_coro(ioc, [&]() -> net::awaitable<void> { rc = co_await mw.handle(inbound, ctx); });
        EXPECT_EQ(rc, psmtest::fault::code::success);
        EXPECT_EQ(ctx.identity, "bob");
    }

    TEST(AuthMiddleware, PipelineStopsOnAuthFailure)
    {
        net::io_context ioc;
        auto auth = std::make_shared<psmtest::static_authenticator>("alice", "s3cret");

        int dial_calls = 0;
        auto dial = std::make_shared<psmtest::middleware::builtin::dial_middleware>(
            [&](const psmtest::connect::target &) -> net::awaitable<
                std::pair<psmtest::fault::code, psmtest::shared_transmission>>
            {
                ++dial_calls;
                co_return std::pair{psmtest::fault::code::success, nullptr};
            });

        psmtest::middleware::pipeline pipe;
        pipe.add(std::make_shared<psmtest::middleware::builtin::auth_middleware>(auth))
            .add(dial);

        psmtest::middleware::context ctx;
        ctx.raw_identity = "alice";
        ctx.raw_secret = "wrong"; // 认证失败
        psmtest::shared_transmission inbound;

        psmtest::fault::code rc = psmtest::fault::code::success;
        run_coro(ioc,
                 [&]() -> net::awaitable<void> { rc = co_await pipe.run(inbound, ctx); });
        EXPECT_EQ(rc, psmtest::fault::code::auth_failed);
        EXPECT_EQ(dial_calls, 0); // 后续中间件未执行
    }

    TEST(AuthMiddleware, PipelineProceedsOnAuthPass)
    {
        net::io_context ioc;
        auto auth = std::make_shared<psmtest::static_authenticator>("alice", "s3cret");

        psmtest::middleware::context ctx;
        ctx.raw_identity = "alice";
        ctx.raw_secret = "s3cret";
        psmtest::shared_transmission inbound;

        psmtest::middleware::pipeline pipe;
        pipe.add(std::make_shared<psmtest::middleware::builtin::auth_middleware>(auth));

        psmtest::fault::code rc = psmtest::fault::code::success;
        run_coro(ioc,
                 [&]() -> net::awaitable<void> { rc = co_await pipe.run(inbound, ctx); });
        EXPECT_EQ(rc, psmtest::fault::code::success);
        EXPECT_EQ(ctx.identity, "alice");
    }

} // namespace
