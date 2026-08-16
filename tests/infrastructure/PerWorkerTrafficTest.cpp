/**
 * @file PerWorkerTrafficTest.cpp
 * @brief 每 worker 流量统计测试（T5-2 O2）
 * @details 覆盖：
 *          - 单 worker / 多 worker 累加与聚合
 *          - 越界 worker 忽略
 *          - 16 worker 多线程并发累加无丢失
 *          - 按用户聚合（多身份 + 快照）
 *          - traffic_pod 合并语义
 */

#include <gtest/gtest.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include <common/core/runtime/per_worker_traffic.hpp>

namespace
{

    TEST(PerWorkerTraffic, SingleWorkerAdd)
    {
        psmtest::runtime::per_worker_traffic traffic(2);
        traffic.add(0, 10, 20);
        traffic.add(0, 5, 7);

        auto s0 = traffic.slot(0);
        EXPECT_EQ(s0.up, 15);
        EXPECT_EQ(s0.down, 27);
        auto s1 = traffic.slot(1);
        EXPECT_EQ(s1.up, 0);
        EXPECT_EQ(s1.down, 0);
    }

    TEST(PerWorkerTraffic, MultiWorkerAggregate)
    {
        psmtest::runtime::per_worker_traffic traffic(4);
        traffic.add(0, 1, 2);
        traffic.add(1, 3, 4);
        traffic.add(2, 5, 6);
        traffic.add(3, 7, 8);

        auto g = traffic.total();
        EXPECT_EQ(g.up, 16);
        EXPECT_EQ(g.down, 20);
        EXPECT_EQ(traffic.worker_count(), 4);
    }

    TEST(PerWorkerTraffic, OutOfRangeIgnored)
    {
        psmtest::runtime::per_worker_traffic traffic(2);
        traffic.add(99, 100, 100);
        EXPECT_EQ(traffic.total().up, 0);
        EXPECT_EQ(traffic.slot(99).up, 0);
    }

    TEST(PerWorkerTraffic, ConcurrentAddNoLoss)
    {
        constexpr std::size_t workers = 16;
        constexpr int threads_per = 4;
        constexpr int iters = 2000;
        constexpr std::uint64_t expect_per_worker =
            static_cast<std::uint64_t>(threads_per) * iters * 3; // 每次 add 3 上行

        psmtest::runtime::per_worker_traffic traffic(workers);
        std::vector<std::thread> threads;
        for (std::size_t t = 0; t < threads_per; ++t)
        {
            threads.emplace_back([&]()
                                 {
                for (int i = 0; i < iters; ++i)
                {
                    for (std::size_t w = 0; w < workers; ++w)
                    {
                        traffic.add(w, 3, 1);
                    }
                } });
        }
        for (auto &th : threads)
        {
            th.join();
        }

        for (std::size_t w = 0; w < workers; ++w)
        {
            EXPECT_EQ(traffic.slot(w).up, expect_per_worker);
            EXPECT_EQ(traffic.slot(w).down,
                      static_cast<std::uint64_t>(threads_per) * iters * 1);
        }
        EXPECT_EQ(traffic.total().up, expect_per_worker * workers);
    }

    TEST(IdentityTraffic, AggregateByIdentity)
    {
        psmtest::runtime::identity_traffic traffic;
        traffic.add("alice", 10, 20);
        traffic.add("alice", 5, 5);
        traffic.add("bob", 100, 1);

        auto a = traffic.per_identity("alice");
        EXPECT_EQ(a.up, 15);
        EXPECT_EQ(a.down, 25);
        auto b = traffic.per_identity("bob");
        EXPECT_EQ(b.up, 100);
        EXPECT_EQ(traffic.per_identity("nobody").up, 0);
        EXPECT_EQ(traffic.identity_count(), 2);
    }

    TEST(IdentityTraffic, SnapshotAll)
    {
        psmtest::runtime::identity_traffic traffic;
        traffic.add("a", 1, 2);
        traffic.add("b", 3, 4);

        auto all = traffic.all();
        EXPECT_EQ(all.size(), 2);
        std::uint64_t total_up = 0;
        for (const auto &[id, pod] : all)
        {
            (void)id;
            total_up += pod.up;
        }
        EXPECT_EQ(total_up, 4);
    }

    TEST(TrafficPod, MergeSemantics)
    {
        psmtest::runtime::traffic_pod a{1, 2};
        psmtest::runtime::traffic_pod b{3, 4};
        a += b;
        EXPECT_EQ(a.up, 4);
        EXPECT_EQ(a.down, 6);

        const auto c = psmtest::runtime::traffic_pod{1, 1} + psmtest::runtime::traffic_pod{2, 2};
        EXPECT_EQ(c.up, 3);
        EXPECT_EQ(c.down, 3);
    }

} // namespace
