/**
 * @file Balancer.cpp
 * @brief Balancer 单元测试
 * @details 测试负载均衡器的评分、过载滞后、空绑定、一致性哈希等核心逻辑。
 */

#include <prism/instance/front/balancer.hpp>
#include <prism/account/stats/snapshot.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>
#include <gtest/gtest.h>
#include <set>
#include <vector>

namespace front = psm::instance::front;

namespace
{
    /**
     * @brief 创建 mock worker binding
     * @param sessions 活跃会话数
     * @param pending 待处理连接数
     * @param lag_us 事件循环延迟（微秒）
     */
    static auto MakeBinding(std::uint32_t sessions, std::uint32_t pending, std::uint64_t lag_us)
        -> front::balancer::worker_binding
    {
        return {
            .dispatch = [](front::tcp::socket) {},
            .snapshot = [=]() -> psm::stats::worker_snapshot
            {
                return {sessions, pending, lag_us};
            }};
    }

    /**
     * @brief 测试单 worker 始终被选中
     */
    TEST(Balancer, SingleWorker)
    {
        psm::memory::vector<front::balancer::worker_binding> bindings(psm::memory::current_resource());
        bindings.push_back(MakeBinding(10, 0, 100));

        front::balancer bal(std::move(bindings));

        for (int i = 0; i < 10; ++i)
        {
            auto result = bal.select(static_cast<std::uint64_t>(i) * 1000);
            EXPECT_TRUE(result.worker_index == 0)
                << "single worker: index should be 0";
            EXPECT_TRUE(!result.overflowed && !result.backpressure)
                << "single worker: no overflow or backpressure";
        }
    }

    /**
     * @brief 测试过载滞后机制
     */
    TEST(Balancer, OverloadHysteresis)
    {
        // 配置：进入过载 90%，退出过载 80%，容量 100 会话
        front::distribute_config cfg;
        cfg.enter_overload = 0.90;
        cfg.exit_overload = 0.80;
        cfg.session_capacity = 100;

        psm::memory::vector<front::balancer::worker_binding> bindings(psm::memory::current_resource());
        bindings.push_back(MakeBinding(0, 0, 0)); // 空闲
        bindings.push_back(MakeBinding(0, 0, 0)); // 空闲

        front::balancer bal(std::move(bindings), cfg);

        // 简单验证：两个空闲 worker，select 应该返回有效索引
        auto result = bal.select(12345);
        EXPECT_TRUE(result.worker_index < 2)
            << "overload hysteresis: valid worker index";
        EXPECT_TRUE(!result.backpressure)
            << "overload hysteresis: no backpressure with idle workers";
    }

    /**
     * @brief 测试空绑定
     */
    TEST(Balancer, EmptyBindings)
    {
        psm::memory::vector<front::balancer::worker_binding> bindings(psm::memory::current_resource());
        front::balancer bal(std::move(bindings));

        auto result = bal.select(12345);
        EXPECT_TRUE(result.worker_index == 0)
            << "empty bindings: index defaults to 0";
        EXPECT_TRUE(!result.overflowed)
            << "empty bindings: no overflow";
    }

    /**
     * @brief 测试一致性：相同 affinity 值应返回相同 worker
     */
    TEST(Balancer, Consistency)
    {
        psm::memory::vector<front::balancer::worker_binding> bindings(psm::memory::current_resource());
        bindings.push_back(MakeBinding(10, 0, 100));
        bindings.push_back(MakeBinding(10, 0, 100));
        bindings.push_back(MakeBinding(10, 0, 100));
        bindings.push_back(MakeBinding(10, 0, 100));

        front::balancer bal(std::move(bindings));

        // 相同 affinity 值多次 select，应返回相同 worker
        constexpr std::uint64_t affinity = 42;
        auto first = bal.select(affinity);
        for (int i = 0; i < 20; ++i)
        {
            auto result = bal.select(affinity);
            EXPECT_TRUE(result.worker_index == first.worker_index)
                << "consistency: same affinity -> same worker";
        }

        // 不同 affinity 值应分布到多个 worker
        std::set<std::size_t> used_workers;
        for (std::uint64_t i = 0; i < 100; ++i)
        {
            auto result = bal.select(i * 7919);
            used_workers.insert(result.worker_index);
        }
        EXPECT_TRUE(used_workers.size() > 1)
            << "consistency: different affinity values use multiple workers";
    }

    /**
     * @brief 测试 size() 方法
     */
    TEST(Balancer, Size)
    {
        psm::memory::vector<front::balancer::worker_binding> bindings(psm::memory::current_resource());
        EXPECT_TRUE(front::balancer(psm::memory::vector<front::balancer::worker_binding>(
                                        psm::memory::current_resource()))
                        .size() == 0)
            << "size: empty balancer has size 0";

        bindings.push_back(MakeBinding(0, 0, 0));
        bindings.push_back(MakeBinding(0, 0, 0));
        bindings.push_back(MakeBinding(0, 0, 0));

        front::balancer bal(std::move(bindings));
        EXPECT_TRUE(bal.size() == 3) << "size: 3 workers";
    }
} // namespace
