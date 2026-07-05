/**
 * @file resources.cpp
 * @brief resources 单元测试（类型与配置层）
 * @details 验证 resources 的类型别名、options/stats 结构体字段。
 * 完整构造测试因依赖 OpenSSL/Asio 完整初始化（需 main.cpp 加载真实 cfg），
 * 留给集成测试覆盖。本测试只验证编译期与对象层语义。
 */

#include <prism/config/config.hpp>
#include <prism/worker/resources.hpp>
#include <prism/foundation/coroutine/registry.hpp>

#include <boost/asio.hpp>

#include <memory>
#include <type_traits>

#include <gtest/gtest.h>

namespace
{
    /**
     * @brief 验证 worker::handle / worker::borrow 类型别名存在且语义正确
     */
    static_assert(std::is_same_v<psm::worker::handle,
                                 std::shared_ptr<psm::worker::resources>>);
    static_assert(std::is_same_v<psm::worker::borrow,
                                 std::weak_ptr<psm::worker::resources>>);
} // namespace

/**
 * @brief options 字段可正确填充
 */
TEST(WorkerResources, OptionsFieldsAccessible)
{
    psm::config cfg;
    cfg.dns.cache_size = 5000;

    psm::worker::options opts{
        cfg,
        std::make_shared<psm::account::directory>(),
        nullptr,
        psm::memory::system::local_pool()};

    EXPECT_EQ(opts.cfg.dns.cache_size, std::size_t{5000});
    EXPECT_NE(opts.account_store, nullptr);
    EXPECT_EQ(opts.ssl_ctx, nullptr);
    EXPECT_NE(opts.mr, nullptr);
}

/**
 * @brief stats 默认值合理
 */
TEST(WorkerResources, StatsDefaultValues)
{
    psm::worker::stats stats;
    EXPECT_EQ(stats.tasks.active, std::size_t{0});
    EXPECT_EQ(stats.tasks.total_spawned, std::size_t{0});
    EXPECT_EQ(stats.tasks.total_released, std::size_t{0});
    EXPECT_EQ(stats.tasks.total_cancelled, std::size_t{0});
    EXPECT_EQ(stats.pool.idle_count, std::size_t{0});
    EXPECT_EQ(stats.pool.total_acquires, std::size_t{0});
    EXPECT_EQ(stats.traffic.total_connections, std::uint64_t{0});
    EXPECT_TRUE(stats.alive);
}

/**
 * @brief task_registry 可独立使用（resources 集成测试由 P1.5 集成路径覆盖）
 */
TEST(WorkerResources, TaskRegistryUsableStandalone)
{
    boost::asio::io_context ioc;
    psm::coroutine::task_registry registry{ioc};

    auto quick = []() -> boost::asio::awaitable<void>
    {
        co_return;
    };

    registry.spawn_tracked("test", quick());
    EXPECT_EQ(registry.stats().total_spawned, std::size_t{1});
    EXPECT_EQ(registry.stats().active, std::size_t{1});

    ioc.run();

    EXPECT_EQ(registry.stats().total_released, std::size_t{1});
    EXPECT_EQ(registry.stats().active, std::size_t{0});
}
