/**
 * @file MiddlewareContextCoverageTest.cpp
 * @brief Runtime Middleware Context 基础契约测试。
 */
#include <gtest/gtest.h>
#include <Preview/Runtime/Middleware/Context.hpp>
TEST(CoreModules, MiddlewareContextBasics)
    {
        Preview::Middleware::Context ctx;
        EXPECT_EQ(static_cast<std::uint16_t>(ctx.DataPlane.Protocol), 0u);
        EXPECT_EQ(ctx.BufferSize, 16384u);
        ctx.Identity() = "alice";
        EXPECT_EQ(ctx.Identity(), "alice");
    }

