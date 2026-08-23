/**
 * @file BalancerDispatchE2E.cpp
 * @brief listener→balancer→worker 分发确定性（亲和性哈希粘滞）
 */

#include <gtest/gtest.h>

#include <prism/foundation/memory/container.hpp>
#include <prism/runtime/front/balancer.hpp>
#include <prism/runtime/front/listener.hpp>

#include <cstdint>

TEST(BalancerDispatchE2E, AffinitySticks)
{
    // 验证同一亲和性哈希值落同一 worker（select 确定性）
    using balancer_t = psm::runtime::front::balancer;
    using binding_t = balancer_t::worker_binding;
    psm::memory::vector<binding_t> bindings;
    bindings.emplace_back(binding_t{[](psm::runtime::front::tcp::socket) {}, [] { return psm::stats::worker_snapshot{}; }, nullptr});
    bindings.emplace_back(binding_t{[](psm::runtime::front::tcp::socket) {}, [] { return psm::stats::worker_snapshot{}; }, nullptr});
    balancer_t b(std::move(bindings));
    const auto r1 = b.select(0x12345678);
    const auto r2 = b.select(0x12345678);
    EXPECT_EQ(r1.worker_index, r2.worker_index);
    EXPECT_LT(r1.worker_index, b.size());
}

TEST(BalancerDispatchE2E, SelectCoversAllWorkers)
{
    // 不同哈希应能覆盖全部 worker 槽位（分布非退化）
    using balancer_t = psm::runtime::front::balancer;
    using binding_t = balancer_t::worker_binding;
    psm::memory::vector<binding_t> bindings;
    bindings.emplace_back(binding_t{[](psm::runtime::front::tcp::socket) {}, [] { return psm::stats::worker_snapshot{}; }, nullptr});
    bindings.emplace_back(binding_t{[](psm::runtime::front::tcp::socket) {}, [] { return psm::stats::worker_snapshot{}; }, nullptr});
    balancer_t b(std::move(bindings));
    std::vector<bool> seen(b.size(), false);
    for (std::uint64_t h = 0; h < 256; ++h)
    {
        seen[b.select(static_cast<std::size_t>(h) * 0x9E3779B97F4A7C15ULL).worker_index] = true;
    }
    EXPECT_TRUE(seen[0]);
    EXPECT_TRUE(seen[1]);
}
