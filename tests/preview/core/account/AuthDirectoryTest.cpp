/**
 * @file AuthDirectoryTest.cpp
 * @brief 目录认证器测试（T5-1 O1）
 * @details 覆盖：
 *          - 凭据命中 → 通过 + identity + 租约
 *          - 不存在 / 禁用 / 过期 → 拒绝（原因正确）
 *          - 连接超限 → 拒绝（配额生效）
 *          - 接入 auth 中间件（T4-1）
 *          - 可注入时钟
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <cstdint>
#include <memory>
#include <string>

#include <common/core/account/authenticator.hpp>
#include <common/core/account/directory.hpp>
#include <common/core/fault/code.hpp>
#include <common/core/middleware/builtin/auth.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/middleware/pipeline.hpp>

namespace
{

    namespace net = boost::asio;

    /// 可注入时钟
    std::uint64_t fake_now = 0;
    auto fake_clock() -> std::uint64_t
    {
        return fake_now;
    }

    TEST(DirectoryAuthenticator, HitPassesWithLease)
    {
        preview::account::directory dir;
        dir.upsert("secret-1", 5);

        const preview::account::directory_authenticator auth(&dir);
        auto r = auth.check_directory("user", "secret-1");
        EXPECT_TRUE(r.ok);
        EXPECT_EQ(r.identity, "secret-1");
        EXPECT_TRUE(r.lease);

        auto e = dir.find("secret-1");
        EXPECT_EQ(e->active(), 1); // 租约占位
    }

    TEST(DirectoryAuthenticator, NotFoundRejected)
    {
        preview::account::directory dir;
        dir.upsert("known", 5);

        const preview::account::directory_authenticator auth(&dir);
        auto r = auth.check_directory("user", "unknown");
        EXPECT_FALSE(r.ok);
        EXPECT_EQ(r.reason, preview::account::auth_reason::not_found);
    }

    TEST(DirectoryAuthenticator, DisabledRejected)
    {
        preview::account::directory dir;
        dir.upsert("blocked", 5, true); // 禁用

        const preview::account::directory_authenticator auth(&dir);
        auto r = auth.check_directory("user", "blocked");
        EXPECT_FALSE(r.ok);
        EXPECT_EQ(r.reason, preview::account::auth_reason::disabled);
    }

    TEST(DirectoryAuthenticator, ExpiredRejected)
    {
        preview::account::directory dir;
        dir.upsert("old", 5, false, 1000);

        fake_now = 500;
        const preview::account::directory_authenticator auth(&dir, fake_clock);
        EXPECT_TRUE(auth.check_directory("user", "old").ok);

        fake_now = 1000; // 过期
        auto r = auth.check_directory("user", "old");
        EXPECT_FALSE(r.ok);
        EXPECT_EQ(r.reason, preview::account::auth_reason::expired);
    }

    TEST(DirectoryAuthenticator, QuotaLimitRejected)
    {
        preview::account::directory dir;
        dir.upsert("limited", 1);

        const preview::account::directory_authenticator auth(&dir);
        auto r1 = auth.check_directory("user", "limited");
        ASSERT_TRUE(r1.ok);
        auto r2 = auth.check_directory("user", "limited");
        EXPECT_FALSE(r2.ok); // 超限
    }

    TEST(DirectoryAuthenticator, MiddlewareIntegration)
    {
        net::io_context ioc;
        preview::account::directory dir;
        dir.upsert("cred-a", 5);

        auto auth = std::make_shared<preview::account::directory_authenticator>(&dir);
        preview::middleware::builtin::auth_middleware mw(auth);

        preview::middleware::context ctx;
        ctx.raw_identity = "user";
        ctx.raw_secret = "cred-a";
        preview::shared_transmission inbound;

        preview::fault::code rc_ok = preview::fault::code::success;
        preview::fault::code rc_bad = preview::fault::code::success;
        std::exception_ptr ep;
        net::co_spawn(ioc,
                      [&]() -> net::awaitable<void>
                      {
                          rc_ok = co_await mw.handle(inbound, ctx);
                          // 错误凭据 → auth_failed
                          ctx.raw_secret = "wrong";
                          rc_bad = co_await mw.handle(inbound, ctx);
                      },
                      [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        ASSERT_FALSE(ep);
        EXPECT_EQ(rc_ok, preview::fault::code::success);
        EXPECT_EQ(ctx.identity, "cred-a");
        EXPECT_EQ(rc_bad, preview::fault::code::auth_failed);
    }

} // namespace
