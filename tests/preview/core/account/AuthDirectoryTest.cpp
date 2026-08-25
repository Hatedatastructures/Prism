/**
 * @file AuthDirectoryTest.cpp
 * @brief 目录认证器测试（T5-1 O1）
 * @details 覆盖：
 *          - 凭据命中 → 通过 + identity + 租约
 *          - 不存在 / 禁用 / 过期 → 拒绝（原因正确）
 *          - 连接超限 → 拒绝（配额生效）
 *          - 接入 Auth 中间件（T4-1）
 *          - 可注入时钟
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <cstdint>
#include <memory>
#include <string>

#include <common/Core/Account/Authenticator.hpp>
#include <common/Core/Account/Directory.hpp>
#include <common/Core/Fault/Code.hpp>
#include <common/Core/Middleware/Builtin/Auth.hpp>
#include <common/Core/Middleware/Context.hpp>
#include <common/Core/Middleware/Pipeline.hpp>

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
        Preview::Account::Directory dir;
        dir.Upsert("Secret-1", 5);

        const Preview::Account::DirectoryAuthenticator Auth(&dir);
        auto r = Auth.CheckDirectory("user", "Secret-1");
        EXPECT_TRUE(r.Ok);
        EXPECT_EQ(r.identity, "Secret-1");
        EXPECT_TRUE(r.Lease);

        auto e = dir.Find("Secret-1");
        EXPECT_EQ(e->Active(), 1); // 租约占位
    }

    TEST(DirectoryAuthenticator, NotFoundRejected)
    {
        Preview::Account::Directory dir;
        dir.Upsert("known", 5);

        const Preview::Account::DirectoryAuthenticator Auth(&dir);
        auto r = Auth.CheckDirectory("user", "unknown");
        EXPECT_FALSE(r.Ok);
        EXPECT_EQ(r.reason, Preview::Account::AuthReason::not_found);
    }

    TEST(DirectoryAuthenticator, DisabledRejected)
    {
        Preview::Account::Directory dir;
        dir.Upsert("blocked", 5, true); // 禁用

        const Preview::Account::DirectoryAuthenticator Auth(&dir);
        auto r = Auth.CheckDirectory("user", "blocked");
        EXPECT_FALSE(r.Ok);
        EXPECT_EQ(r.reason, Preview::Account::AuthReason::Disabled);
    }

    TEST(DirectoryAuthenticator, ExpiredRejected)
    {
        Preview::Account::Directory dir;
        dir.Upsert("old", 5, false, 1000);

        fake_now = 500;
        const Preview::Account::DirectoryAuthenticator Auth(&dir, fake_clock);
        EXPECT_TRUE(Auth.CheckDirectory("user", "old").Ok);

        fake_now = 1000; // 过期
        auto r = Auth.CheckDirectory("user", "old");
        EXPECT_FALSE(r.Ok);
        EXPECT_EQ(r.reason, Preview::Account::AuthReason::Expired);
    }

    TEST(DirectoryAuthenticator, QuotaLimitRejected)
    {
        Preview::Account::Directory dir;
        dir.Upsert("limited", 1);

        const Preview::Account::DirectoryAuthenticator Auth(&dir);
        auto r1 = Auth.CheckDirectory("user", "limited");
        ASSERT_TRUE(r1.Ok);
        auto r2 = Auth.CheckDirectory("user", "limited");
        EXPECT_FALSE(r2.Ok); // 超限
    }

    TEST(DirectoryAuthenticator, MiddlewareIntegration)
    {
        net::io_context ioc;
        Preview::Account::Directory dir;
        dir.Upsert("cred-a", 5);

        auto Auth = std::make_shared<Preview::Account::DirectoryAuthenticator>(&dir);
        Preview::Middleware::Builtin::AuthMiddleware mw(Auth);

        Preview::Middleware::Context ctx;
        ctx.RawIdentity = "user";
        ctx.RawSecret = "cred-a";
        Preview::SharedTransmission inbound;

        Preview::Fault::Code rc_ok = Preview::Fault::Code::success;
        Preview::Fault::Code rc_bad = Preview::Fault::Code::success;
        std::exception_ptr ep;
        net::co_spawn(ioc,
                      [&]() -> net::awaitable<void>
                      {
                          rc_ok = co_await mw.Handle(inbound, ctx);
                          // 错误凭据 → auth_failed
                          ctx.RawSecret = "wrong";
                          rc_bad = co_await mw.Handle(inbound, ctx);
                      },
                      [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        ASSERT_FALSE(ep);
        EXPECT_EQ(rc_ok, Preview::Fault::Code::success);
        EXPECT_EQ(ctx.identity, "cred-a");
        EXPECT_EQ(rc_bad, Preview::Fault::Code::auth_failed);
    }

} // namespace
