/**
 * @file resources.cpp
 * @brief resources 具体类单元测试（类型与编译期验证）
 */

#include <prism/resource/process.hpp>
#include <prism/resource/worker.hpp>
#include <prism/resource/session.hpp>
#include <prism/foundation/coroutine/registry.hpp>

#include <boost/asio.hpp>

#include <memory>
#include <type_traits>

#include <gtest/gtest.h>

namespace
{
    static_assert(std::is_same_v<std::weak_ptr<psm::resource::worker>,
                                 std::weak_ptr<psm::resource::worker>>);
    static_assert(std::is_class_v<psm::resource::process>);
    static_assert(std::is_class_v<psm::resource::worker>);
    static_assert(std::is_class_v<psm::resource::session>);
}


TEST(WorkerResources, TypeAliasesCorrect)
{
    auto borrow = std::weak_ptr<psm::resource::worker>{};
    EXPECT_TRUE(borrow.expired());
}


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
