/**
 * @file task_registry.cpp
 * @brief task_registry 单元测试
 * @details 验证 spawn_tracked 的 token 注册/释放/统计/cancel 行为。
 * task_registry 设计为单线程使用（每 worker 一个），测试在单 io_context
 * 上同步驱动协程完成。
 */

#include <prism/foundation/coroutine/registry.hpp>

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <chrono>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;

    /**
     * @brief 立即完成的协程，模拟短任务
     */
    auto quick_task() -> net::awaitable<void>
    {
        co_return;
    }

    /**
     * @brief 等待定时器的协程，模拟长任务
     */
    auto blocked_task(net::steady_timer &timer) -> net::awaitable<void>
    {
        boost::system::error_code ec;
        co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
    }
} // namespace

/**
 * @brief spawn 单个协程，run ioc 让其完成，验证 release 计数
 */
TEST(TaskRegistry, SpawnAndRelease)
{
    net::io_context ioc;
    psm::coroutine::task_registry registry{ioc};

    registry.spawn_tracked("quick", quick_task());
    EXPECT_EQ(registry.stats().total_spawned, std::size_t{1});
    EXPECT_EQ(registry.stats().active, std::size_t{1});

    ioc.run();

    const auto s = registry.stats();
    EXPECT_EQ(s.total_spawned, std::size_t{1});
    EXPECT_EQ(s.total_released, std::size_t{1});
    EXPECT_EQ(s.total_cancelled, std::size_t{0});
    EXPECT_EQ(s.active, std::size_t{0});
}

/**
 * @brief spawn 多个协程，验证统计字段正确累加
 */
TEST(TaskRegistry, SpawnMultipleAccumulatesStats)
{
    net::io_context ioc;
    psm::coroutine::task_registry registry{ioc};

    for (std::size_t i = 0; i < 5; ++i)
    {
        registry.spawn_tracked("bulk", quick_task());
    }

    EXPECT_EQ(registry.stats().total_spawned, std::size_t{5});
    EXPECT_EQ(registry.stats().active, std::size_t{5});

    ioc.run();

    const auto s = registry.stats();
    EXPECT_EQ(s.total_spawned, std::size_t{5});
    EXPECT_EQ(s.total_released, std::size_t{5});
    EXPECT_EQ(s.active, std::size_t{0});
}

/**
 * @brief cancel_and_wait 立即清理 tokens_，统计累加 cancelled
 */
TEST(TaskRegistry, CancelClearsTokensAndCounts)
{
    net::io_context ioc;
    psm::coroutine::task_registry registry{ioc};

    net::steady_timer timer{ioc};
    timer.expires_after(std::chrono::hours(1));

    // 启动 3 个阻塞协程，ioc 不 run，token 不会自然 release
    for (std::size_t i = 0; i < 3; ++i)
    {
        registry.spawn_tracked("blocked", blocked_task(timer));
    }

    EXPECT_EQ(registry.stats().active, std::size_t{3});

    const auto cleared = registry.cancel_and_wait(std::chrono::seconds(1));
    EXPECT_TRUE(cleared);

    const auto s = registry.stats();
    EXPECT_EQ(s.active, std::size_t{0});
    EXPECT_EQ(s.total_cancelled, std::size_t{3});
    EXPECT_EQ(s.total_released, std::size_t{0}); // 未自然完成
}

/**
 * @brief cancel 后再 release_internal 应是 no-op（cancelling_ 标志保护）
 */
TEST(TaskRegistry, ReleaseAfterCancelIsNoop)
{
    net::io_context ioc;
    psm::coroutine::task_registry registry{ioc};

    net::steady_timer timer{ioc};
    timer.expires_after(std::chrono::hours(1));
    registry.spawn_tracked("blocked", blocked_task(timer));

    ASSERT_EQ(registry.stats().active, std::size_t{1});

    const auto cleared = registry.cancel_and_wait();
    EXPECT_TRUE(cleared);
    EXPECT_EQ(registry.stats().active, std::size_t{0});

    // cancelling_ 标志保护：再次调用 cancel 不会重复累加 cancelled 计数。
    // 同时不调 ioc.run()，模拟 worker 析构时 ioc 已 stop 的真实场景。
    const auto cleared_again = registry.cancel_and_wait();
    EXPECT_TRUE(cleared_again);
    EXPECT_EQ(registry.stats().total_cancelled, std::size_t{1}); // 仍是 1，未翻倍
    EXPECT_EQ(registry.stats().active, std::size_t{0});
}

/**
 * @brief stats() 是只读快照，不影响内部状态
 */
TEST(TaskRegistry, StatsSnapshotIsReadOnly)
{
    net::io_context ioc;
    psm::coroutine::task_registry registry{ioc};

    const auto s1 = registry.stats();
    EXPECT_EQ(s1.total_spawned, std::size_t{0});

    registry.spawn_tracked("once", quick_task());
    const auto s2 = registry.stats();
    EXPECT_EQ(s2.total_spawned, std::size_t{1});

    ioc.run();
    const auto s3 = registry.stats();
    EXPECT_EQ(s3.total_spawned, std::size_t{1});
    EXPECT_EQ(s3.total_released, std::size_t{1});
}
