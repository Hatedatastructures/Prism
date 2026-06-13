/**
 * @file BalancerPure.cpp
 * @brief 负载均衡器纯函数测试 — select 分支覆盖
 */

#include <prism/core/core.hpp>
#include <prism/trace/spdlog.hpp>
#include <gtest/gtest.h>

// 包含源文件以访问 mix_hash 和 score 私有方法
#include "../../../../src/prism/instance/front/balancer.cpp"

namespace
{
    using psm::instance::front::balancer;
    using psm::instance::front::distribute_config;
    using psm::stats::worker_snapshot;

    TEST(BalancerPure, SelectEmpty)
    {
        distribute_config config;
        balancer b({}, config);
        auto result = b.select(42);
        EXPECT_TRUE(result.worker_index == 0) << "select: empty -> index=0";
        EXPECT_TRUE(!result.overflowed) << "select: empty -> not overflowed";
        EXPECT_TRUE(!result.backpressure) << "select: empty -> no backpressure";
    }

    TEST(BalancerPure, SelectSingleWorker)
    {
        distribute_config config;
        config.session_capacity = 100;

        psm::memory::vector<balancer::worker_binding> bindings;
        bindings.push_back({
            [](psm::instance::front::tcp::socket) {},
            []() { return worker_snapshot{10, 0, 0}; }
        });

        balancer b(std::move(bindings), config);
        auto result = b.select(42);
        EXPECT_TRUE(result.worker_index == 0) << "select: single -> index=0";
        EXPECT_TRUE(!result.overflowed) << "select: single -> not overflowed";
    }

    TEST(BalancerPure, SelectDeterministic)
    {
        distribute_config config;
        config.session_capacity = 100;

        psm::memory::vector<balancer::worker_binding> bindings;
        bindings.push_back({
            [](psm::instance::front::tcp::socket) {},
            []() { return worker_snapshot{10, 0, 0}; }
        });
        bindings.push_back({
            [](psm::instance::front::tcp::socket) {},
            []() { return worker_snapshot{20, 0, 0}; }
        });

        balancer b(std::move(bindings), config);
        auto r1 = b.select(12345);
        auto r2 = b.select(12345);
        auto r3 = b.select(12345);
        EXPECT_TRUE(r1.worker_index == r2.worker_index) << "select: deterministic r1==r2";
        EXPECT_TRUE(r2.worker_index == r3.worker_index) << "select: deterministic r2==r3";
    }

    TEST(BalancerPure, SelectDifferentAffinity)
    {
        distribute_config config;
        config.session_capacity = 100;

        psm::memory::vector<balancer::worker_binding> bindings;
        bindings.push_back({
            [](psm::instance::front::tcp::socket) {},
            []() { return worker_snapshot{50, 0, 0}; }
        });
        bindings.push_back({
            [](psm::instance::front::tcp::socket) {},
            []() { return worker_snapshot{50, 0, 0}; }
        });

        balancer b(std::move(bindings), config);
        // Same load on both workers, but different affinity values should produce valid results
        auto r1 = b.select(0);
        auto r2 = b.select(999);
        EXPECT_TRUE(r1.worker_index < 2) << "select: affinity 0 valid index";
        EXPECT_TRUE(r2.worker_index < 2) << "select: affinity 999 valid index";
    }

    TEST(BalancerPure, SelectOverloadFallback)
    {
        distribute_config config;
        config.session_capacity = 100;
        config.enter_overload = 0.50;
        config.exit_overload = 0.30;

        psm::memory::vector<balancer::worker_binding> bindings;
        // Worker 0: heavy (80/100=0.8 > enter_overload=0.5 -> overloaded)
        bindings.push_back({
            [](psm::instance::front::tcp::socket) {},
            []() { return worker_snapshot{80, 0, 0}; }
        });
        // Worker 1: light (10/100=0.1 -> not overloaded)
        bindings.push_back({
            [](psm::instance::front::tcp::socket) {},
            []() { return worker_snapshot{10, 0, 0}; }
        });

        balancer b(std::move(bindings), config);
        // For every affinity, if primary is worker 0 (overloaded),
        // secondary should be chosen if its score is lower
        for (std::uint64_t aff = 0; aff < 50; ++aff)
        {
            auto result = b.select(aff);
            EXPECT_TRUE(result.worker_index < 2) << "select: fallback valid index";
        }
    }

    TEST(BalancerPure, SelectBackpressure)
    {
        distribute_config config;
        config.session_capacity = 100;
        config.backpressure_thresh = 0.5;
        config.enter_overload = 0.9;

        psm::memory::vector<balancer::worker_binding> bindings;
        // Both workers overloaded (> 0.5)
        bindings.push_back({
            [](psm::instance::front::tcp::socket) {},
            []() { return worker_snapshot{90, 0, 0}; }
        });
        bindings.push_back({
            [](psm::instance::front::tcp::socket) {},
            []() { return worker_snapshot{90, 0, 0}; }
        });

        balancer b(std::move(bindings), config);
        auto result = b.select(42);
        // Both at 0.9 load which is > backpressure_thresh=0.5
        EXPECT_TRUE(result.backpressure) << "select: backpressure=true when all high load";
    }

    TEST(BalancerPure, SelectNoBackpressure)
    {
        distribute_config config;
        config.session_capacity = 100;
        config.backpressure_thresh = 0.95;

        psm::memory::vector<balancer::worker_binding> bindings;
        bindings.push_back({
            [](psm::instance::front::tcp::socket) {},
            []() { return worker_snapshot{10, 0, 0}; }
        });
        bindings.push_back({
            [](psm::instance::front::tcp::socket) {},
            []() { return worker_snapshot{20, 0, 0}; }
        });

        balancer b(std::move(bindings), config);
        auto result = b.select(42);
        EXPECT_TRUE(!result.backpressure) << "select: no backpressure at low load";
    }

    TEST(BalancerPure, SelectSize)
    {
        distribute_config config;

        psm::memory::vector<balancer::worker_binding> bindings;
        bindings.push_back({
            [](psm::instance::front::tcp::socket) {},
            []() { return worker_snapshot{0, 0, 0}; }
        });
        bindings.push_back({
            [](psm::instance::front::tcp::socket) {},
            []() { return worker_snapshot{0, 0, 0}; }
        });
        bindings.push_back({
            [](psm::instance::front::tcp::socket) {},
            []() { return worker_snapshot{0, 0, 0}; }
        });

        balancer b(std::move(bindings), config);
        EXPECT_TRUE(b.size() == 3) << "size: 3 workers";

        auto result = b.select(7);
        EXPECT_TRUE(result.worker_index < 3) << "select: index < 3";
    }

    TEST(BalancerPure, SelectOverflowDetection)
    {
        distribute_config config;
        config.session_capacity = 100;
        config.enter_overload = 0.5;
        config.exit_overload = 0.3;

        psm::memory::vector<balancer::worker_binding> bindings;
        // Worker heavily loaded (90/100 = 0.9, above enter_overload=0.5)
        bindings.push_back({
            [](psm::instance::front::tcp::socket) {},
            []() { return worker_snapshot{90, 0, 0}; }
        });

        balancer b(std::move(bindings), config);
        auto result = b.select(42);
        // Single worker at 0.9 load, enter_overload=0.5 -> overflow
        EXPECT_TRUE(result.overflowed) << "select: overflow=true for overloaded single worker";
    }

    TEST(BalancerPure, SelectThreeWorkersLoadSpread)
    {
        distribute_config config;
        config.session_capacity = 100;

        psm::memory::vector<balancer::worker_binding> bindings;
        bindings.push_back({
            [](psm::instance::front::tcp::socket) {},
            []() { return worker_snapshot{80, 10, 1000}; }
        });
        bindings.push_back({
            [](psm::instance::front::tcp::socket) {},
            []() { return worker_snapshot{40, 5, 500}; }
        });
        bindings.push_back({
            [](psm::instance::front::tcp::socket) {},
            []() { return worker_snapshot{5, 0, 50}; }
        });

        balancer b(std::move(bindings), config);
        // Try multiple affinity values — all should return valid indices
        for (std::uint64_t aff = 0; aff < 20; ++aff)
        {
            auto result = b.select(aff);
            EXPECT_TRUE(result.worker_index < 3) << "select: 3-worker valid index";
        }
    }
} // namespace
