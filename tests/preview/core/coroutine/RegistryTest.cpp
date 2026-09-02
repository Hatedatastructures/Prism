/**
 * @file RegistryTest.cpp
 * @brief 协程注册表测试（coroutine/registry）
 * @details 覆盖：
 *          - SpawnTracked 正常完成 → token 释放 + 计数
 *          - 多协程统计计数（spawned/released/Active）
 *          - CancelAndWait 清算路径（cancelled 计数 + 清空）
 *          - registry 析构解除 token 绑定（不悬垂）
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <chrono>
#include <string>

#include <preview/Foundation/Utility/Coroutine/Registry.hpp>

namespace
{

    namespace net = boost::asio;

    TEST(TaskRegistry, SpawnTrackedCompletes)
    {
        net::io_context ioc;
        Preview::Coroutine::TaskRegistry registry(ioc);

        std::atomic<int> ran{0};
        registry.SpawnTracked("complete", [&]() -> net::awaitable<void>
                               { ++ran; co_return; });
        ioc.run();

        EXPECT_EQ(ran, 1);
        const auto s = registry.Stats();
        EXPECT_EQ(s.TotalSpawned, 1);
        EXPECT_EQ(s.TotalReleased, 1);
        EXPECT_EQ(s.Active, 0);
    }

    TEST(TaskRegistry, StatsCounters)
    {
        net::io_context ioc;
        Preview::Coroutine::TaskRegistry registry(ioc);

        for (int i = 0; i < 5; ++i)
        {
            registry.SpawnTracked("task-" + std::to_string(i),
                                   [i]() -> net::awaitable<void>
                                   {
                                       (void)i;
                                       co_return;
                                   });
        }
        EXPECT_EQ(registry.Stats().TotalSpawned, 5);
        EXPECT_EQ(registry.Stats().Active, 5); // Run 前活跃

        ioc.run();
        const auto s = registry.Stats();
        EXPECT_EQ(s.TotalSpawned, 5);
        EXPECT_EQ(s.TotalReleased, 5);
        EXPECT_EQ(s.Active, 0);
    }

    TEST(TaskRegistry, CancelAndWaitCleans)
    {
        net::io_context ioc;
        Preview::Coroutine::TaskRegistry registry(ioc);

        // 未 Run 的协程：token 残留 → CancelAndWait 清算
        registry.SpawnTracked("pending", []() -> net::awaitable<void>
                               { co_return; });
        registry.SpawnTracked("pending2", []() -> net::awaitable<void>
                               { co_return; });

        EXPECT_TRUE(registry.CancelAndWait());
        const auto s = registry.Stats();
        EXPECT_EQ(s.TotalSpawned, 2);
        EXPECT_EQ(s.TotalCancelled, 2);
        EXPECT_EQ(s.Active, 0);
    }

    TEST(TaskRegistry, DestroyDetachesTokens)
    {
        net::io_context ioc;
        {
            Preview::Coroutine::TaskRegistry registry(ioc);
            registry.SpawnTracked("orphan", []() -> net::awaitable<void>
                                   { co_return; });
        } // 析构：解除 token 绑定，无悬垂（不崩溃即通过）
        ioc.run();
        SUCCEED();
    }

    TEST(TaskRegistry, MixedCompleteAndPending)
    {
        net::io_context ioc;
        Preview::Coroutine::TaskRegistry registry(ioc);

        std::atomic<int> ran{0};
        registry.SpawnTracked("Done", [&]() -> net::awaitable<void>
                               { ++ran; co_return; });
        // pending：挂起在超长 timer 上（Run 后 token 仍活跃；析构安全）
        registry.SpawnTracked("pending", [&]() -> net::awaitable<void>
                               {
            net::steady_timer t(ioc);
            t.expires_after(std::chrono::hours(24));
            co_await t.async_wait(net::use_awaitable);
        });

        // 驱动 100ms：Done 完成，pending 仍挂起（run_for 保证返回）
        ioc.run_for(std::chrono::milliseconds(100));
        EXPECT_EQ(ran, 1);
        EXPECT_EQ(registry.Stats().TotalReleased, 1);
        EXPECT_EQ(registry.Stats().Active, 1);

        // 清算残留
        EXPECT_TRUE(registry.CancelAndWait());
        EXPECT_EQ(registry.Stats().TotalCancelled, 1);
        EXPECT_EQ(registry.Stats().Active, 0);
    }

} // namespace
