/**
 * @file RegistryTest.cpp
 * @brief 协程注册表测试（coroutine/registry）
 * @details 覆盖：
 *          - spawn_tracked 正常完成 → token 释放 + 计数
 *          - 多协程统计计数（spawned/released/active）
 *          - cancel_and_wait 清算路径（cancelled 计数 + 清空）
 *          - registry 析构解除 token 绑定（不悬垂）
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <chrono>
#include <string>

#include <common/core/coroutine/registry.hpp>

namespace
{

    namespace net = boost::asio;

    TEST(TaskRegistry, SpawnTrackedCompletes)
    {
        net::io_context ioc;
        preview::coroutine::task_registry registry(ioc);

        std::atomic<int> ran{0};
        registry.spawn_tracked("complete", [&]() -> net::awaitable<void>
                               { ++ran; co_return; });
        ioc.run();

        EXPECT_EQ(ran, 1);
        const auto s = registry.stats();
        EXPECT_EQ(s.total_spawned, 1);
        EXPECT_EQ(s.total_released, 1);
        EXPECT_EQ(s.active, 0);
    }

    TEST(TaskRegistry, StatsCounters)
    {
        net::io_context ioc;
        preview::coroutine::task_registry registry(ioc);

        for (int i = 0; i < 5; ++i)
        {
            registry.spawn_tracked("task-" + std::to_string(i),
                                   [i]() -> net::awaitable<void>
                                   {
                                       (void)i;
                                       co_return;
                                   });
        }
        EXPECT_EQ(registry.stats().total_spawned, 5);
        EXPECT_EQ(registry.stats().active, 5); // run 前活跃

        ioc.run();
        const auto s = registry.stats();
        EXPECT_EQ(s.total_spawned, 5);
        EXPECT_EQ(s.total_released, 5);
        EXPECT_EQ(s.active, 0);
    }

    TEST(TaskRegistry, CancelAndWaitCleans)
    {
        net::io_context ioc;
        preview::coroutine::task_registry registry(ioc);

        // 未 run 的协程：token 残留 → cancel_and_wait 清算
        registry.spawn_tracked("pending", []() -> net::awaitable<void>
                               { co_return; });
        registry.spawn_tracked("pending2", []() -> net::awaitable<void>
                               { co_return; });

        EXPECT_TRUE(registry.cancel_and_wait());
        const auto s = registry.stats();
        EXPECT_EQ(s.total_spawned, 2);
        EXPECT_EQ(s.total_cancelled, 2);
        EXPECT_EQ(s.active, 0);
    }

    TEST(TaskRegistry, DestroyDetachesTokens)
    {
        net::io_context ioc;
        {
            preview::coroutine::task_registry registry(ioc);
            registry.spawn_tracked("orphan", []() -> net::awaitable<void>
                                   { co_return; });
        } // 析构：解除 token 绑定，无悬垂（不崩溃即通过）
        ioc.run();
        SUCCEED();
    }

    TEST(TaskRegistry, MixedCompleteAndPending)
    {
        net::io_context ioc;
        preview::coroutine::task_registry registry(ioc);

        std::atomic<int> ran{0};
        registry.spawn_tracked("done", [&]() -> net::awaitable<void>
                               { ++ran; co_return; });
        // pending：挂起在超长 timer 上（run 后 token 仍活跃；析构安全）
        registry.spawn_tracked("pending", [&]() -> net::awaitable<void>
                               {
            net::steady_timer t(ioc);
            t.expires_after(std::chrono::hours(24));
            co_await t.async_wait(net::use_awaitable);
        });

        // 驱动 100ms：done 完成，pending 仍挂起（run_for 保证返回）
        ioc.run_for(std::chrono::milliseconds(100));
        EXPECT_EQ(ran, 1);
        EXPECT_EQ(registry.stats().total_released, 1);
        EXPECT_EQ(registry.stats().active, 1);

        // 清算残留
        EXPECT_TRUE(registry.cancel_and_wait());
        EXPECT_EQ(registry.stats().total_cancelled, 1);
        EXPECT_EQ(registry.stats().active, 0);
    }

} // namespace
