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
#include <optional>
#include <string>

#include <Preview/Account/Directory.hpp>
#include <Preview/Foundation/Authenticator.hpp>
#include <Preview/Foundation/Utility/Account/Authenticator.hpp>
#include <Preview/Foundation/Utility/Account/Directory.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Runtime/Middleware/Builtin/Auth.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Runtime/Middleware/Pipeline.hpp>

namespace
{

    namespace Net = boost::asio;

    /// 可注入时钟
    std::uint64_t FakeNow = 0;
    auto FakeClock() -> std::uint64_t
    {
        return FakeNow;
    }

    TEST(DirectoryAuthenticator, HitPassesWithLease)
    {
        Preview::Account::Directory dir;
        dir.Upsert("Secret-1", 5);

        const Preview::Account::DirectoryAuthenticator Auth(&dir);
        auto r = Auth.CheckDirectory("user", "Secret-1");
        EXPECT_TRUE(r.Ok);
        EXPECT_EQ(r.Identity, "Secret-1");
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
        EXPECT_EQ(r.Reason, Preview::Account::AuthReason::NotFound);
    }

    TEST(DirectoryAuthenticator, DisabledRejected)
    {
        Preview::Account::Directory dir;
        dir.Upsert("blocked", {.MaxConnections = 5, .Disabled = true}); // 禁用

        const Preview::Account::DirectoryAuthenticator Auth(&dir);
        auto r = Auth.CheckDirectory("user", "blocked");
        EXPECT_FALSE(r.Ok);
        EXPECT_EQ(r.Reason, Preview::Account::AuthReason::Disabled);
    }

    TEST(DirectoryAuthenticator, ExpiredRejected)
    {
        Preview::Account::Directory dir;
        dir.Upsert("old", {.MaxConnections = 5, .ExpireAt = 1000});

        FakeNow = 500;
        const Preview::Account::DirectoryAuthenticator Auth(&dir, FakeClock);
        EXPECT_TRUE(Auth.CheckDirectory("user", "old").Ok);

        FakeNow = 1000; // 过期
        auto r = Auth.CheckDirectory("user", "old");
        EXPECT_FALSE(r.Ok);
        EXPECT_EQ(r.Reason, Preview::Account::AuthReason::Expired);
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
        Net::io_context IoContext;
        const auto Record = std::make_shared<const Preview::Account::AccountRecord>(
            Preview::Account::AccountRecord::CreateRequest{
                .AccountId = Preview::AccountId{7101},
                .CredentialValue = Preview::Account::Credential::Password("cred-a"),
                .Quota = {.MaxConnections = 5}});
        Preview::Account::AccountDirectory dir;
        ASSERT_TRUE(dir.Upsert(Record));

        auto Auth = std::make_shared<Preview::DirectoryAuthenticator>(&dir);
        std::string Secret = "cred-a";
        Preview::Middleware::Builtin::AuthMiddleware mw(
            Auth,
            [&Secret](const Preview::Middleware::Context &)
                -> std::optional<Preview::Middleware::Builtin::AuthMiddleware::CredentialInput>
            {
                return Preview::Middleware::Builtin::AuthMiddleware::CredentialInput{
                    .Identity = "user",
                    .Credential = std::make_shared<const Preview::Account::Credential>(
                        Preview::Account::Credential::Password(Secret))};
            });

        Preview::Middleware::Context ctx;
        ctx.RawIdentity = "user";
        Preview::SharedTransmission Inbound;

        Preview::Fault::Code rc_ok = Preview::Fault::Code::Success;
        Preview::Fault::Code rc_bad = Preview::Fault::Code::Success;
        std::exception_ptr ep;
        Net::co_spawn(IoContext,
                      [&]() -> Net::awaitable<void>
                       {
                           rc_ok = co_await mw.Handle(Inbound, ctx);
                           EXPECT_EQ(ctx.identity, "user");
                           EXPECT_TRUE(ctx.AccountLease);
                           EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1u);
                           // 错误凭据 → auth_failed
                           Secret = "wrong";
                           rc_bad = co_await mw.Handle(Inbound, ctx);
                      },
                      [&](std::exception_ptr Exception)
                      {
                          ep = Exception;
                          IoContext.stop();
                      });
        IoContext.run();
        ASSERT_FALSE(ep);
        EXPECT_EQ(rc_ok, Preview::Fault::Code::Success);
        EXPECT_EQ(rc_bad, Preview::Fault::Code::AuthFailed);
        EXPECT_TRUE(ctx.identity.empty());
        EXPECT_FALSE(ctx.AccountLease);
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0u);
    }

} // namespace
