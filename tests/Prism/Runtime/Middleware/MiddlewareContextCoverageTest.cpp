/**
 * @file MiddlewareContextCoverageTest.cpp
 * @brief Runtime Middleware Context 基础契约测试。
 */
#include <Prism/Runtime/Middleware/Context.hpp>

#include <gtest/gtest.h>
TEST(CoreModules, MiddlewareContextBasics)
{
    Prism::Middleware::Context ctx;
    EXPECT_EQ(static_cast<std::uint16_t>(ctx.DataPlane.Protocol), 0u);
    EXPECT_EQ(ctx.BufferSize, 16384u);
    ctx.Identity() = "alice";
    EXPECT_EQ(ctx.Identity(), "alice");
}

TEST(CoreModules, MiddlewareContextUserForLogFallsBackToAccountId)
{
    Prism::Middleware::Context MiddlewareContext;
    MiddlewareContext.AccountId() = Prism::AccountId{7003};
    EXPECT_EQ(MiddlewareContext.UserForLog(), "7003");

    MiddlewareContext.DisplayIdentity() = "safe-user";
    EXPECT_EQ(MiddlewareContext.UserForLog(), "safe-user");
}
