/**
 * @file PerWorkerTrafficTest.cpp
 * @brief 每 worker 流量统计测试（T5-2 O2）
 * @details 覆盖：
 *          - 单 worker / 多 worker 累加与聚合
 *          - 越界 worker 忽略
 *          - 16 worker 多线程并发累加无丢失
 *          - 按用户聚合（多身份 + 快照）
 *          - TrafficPod 合并语义
 */

#include <gtest/gtest.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include <common/Core/Runtime/Statistics.hpp>

namespace
{

    TEST(PerWorkerTraffic, SingleWorkerAdd)
    {
        Preview::Runtime::PerWorkerTraffic traffic(2);
        traffic.Add(0, 10, 20);
        traffic.Add(0, 5, 7);

        auto s0 = traffic.Slot(0);
        EXPECT_EQ(s0.up, 15);
        EXPECT_EQ(s0.down, 27);
        auto s1 = traffic.Slot(1);
        EXPECT_EQ(s1.up, 0);
        EXPECT_EQ(s1.down, 0);
    }

    TEST(PerWorkerTraffic, MultiWorkerAggregate)
    {
        Preview::Runtime::PerWorkerTraffic traffic(4);
        traffic.Add(0, 1, 2);
        traffic.Add(1, 3, 4);
        traffic.Add(2, 5, 6);
        traffic.Add(3, 7, 8);

        auto g = traffic.Total();
        EXPECT_EQ(g.up, 16);
        EXPECT_EQ(g.down, 20);
        EXPECT_EQ(traffic.WorkerCount(), 4);
    }

    TEST(PerWorkerTraffic, OutOfRangeIgnored)
    {
        Preview::Runtime::PerWorkerTraffic traffic(2);
        traffic.Add(99, 100, 100);
        EXPECT_EQ(traffic.Total().up, 0);
        EXPECT_EQ(traffic.Slot(99).up, 0);
    }

    TEST(PerWorkerTraffic, ConcurrentAddNoLoss)
    {
        constexpr std::size_t workers = 16;
        constexpr int threads_per = 4;
        constexpr int iters = 2000;
        constexpr std::uint64_t expect_per_worker =
            static_cast<std::uint64_t>(threads_per) * iters * 3; // 每次 Add 3 上行

        Preview::Runtime::PerWorkerTraffic traffic(workers);
        std::vector<std::thread> threads;
        for (std::size_t t = 0; t < threads_per; ++t)
        {
            threads.emplace_back([&]()
                                 {
                for (int i = 0; i < iters; ++i)
                {
                    for (std::size_t w = 0; w < workers; ++w)
                    {
                        traffic.Add(w, 3, 1);
                    }
                } });
        }
        for (auto &th : threads)
        {
            th.join();
        }

        for (std::size_t w = 0; w < workers; ++w)
        {
            EXPECT_EQ(traffic.Slot(w).up, expect_per_worker);
            EXPECT_EQ(traffic.Slot(w).down,
                      static_cast<std::uint64_t>(threads_per) * iters * 1);
        }
        EXPECT_EQ(traffic.Total().up, expect_per_worker * workers);
    }

    TEST(IdentityTraffic, AggregateByIdentity)
    {
        Preview::Runtime::IdentityTraffic traffic;
        traffic.Add("alice", 10, 20);
        traffic.Add("alice", 5, 5);
        traffic.Add("bob", 100, 1);

        auto a = traffic.PerIdentity("alice");
        EXPECT_EQ(a.up, 15);
        EXPECT_EQ(a.down, 25);
        auto b = traffic.PerIdentity("bob");
        EXPECT_EQ(b.up, 100);
        EXPECT_EQ(traffic.PerIdentity("nobody").up, 0);
        EXPECT_EQ(traffic.IdentityCount(), 2);
    }

    TEST(IdentityTraffic, SnapshotAll)
    {
        Preview::Runtime::IdentityTraffic traffic;
        traffic.Add("a", 1, 2);
        traffic.Add("b", 3, 4);

        auto All = traffic.All();
        EXPECT_EQ(All.size(), 2);
        std::uint64_t total_up = 0;
        for (const auto &[Id, pod] : All)
        {
            (void)Id;
            total_up += pod.up;
        }
        EXPECT_EQ(total_up, 4);
    }

    TEST(TrafficPod, MergeSemantics)
    {
        Preview::Runtime::TrafficPod a{1, 2};
        Preview::Runtime::TrafficPod b{3, 4};
        a += b;
        EXPECT_EQ(a.up, 4);
        EXPECT_EQ(a.down, 6);

        const auto c = Preview::Runtime::TrafficPod{1, 1} + Preview::Runtime::TrafficPod{2, 2};
        EXPECT_EQ(c.up, 3);
        EXPECT_EQ(c.down, 3);
    }

} // namespace
