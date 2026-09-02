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

#include <preview/Runtime/Statistics.hpp>

namespace
{

    TEST(PerWorkerTraffic, SingleWorkerAdd)
    {
        Preview::Runtime::PerWorkerTraffic traffic(2);
        traffic.Add(0, 10, 20);
        traffic.Add(0, 5, 7);

        auto s0 = traffic.Slot(0);
        EXPECT_EQ(s0.Up, 15);
        EXPECT_EQ(s0.Down, 27);
        auto s1 = traffic.Slot(1);
        EXPECT_EQ(s1.Up, 0);
        EXPECT_EQ(s1.Down, 0);
    }

    TEST(PerWorkerTraffic, MultiWorkerAggregate)
    {
        Preview::Runtime::PerWorkerTraffic traffic(4);
        traffic.Add(0, 1, 2);
        traffic.Add(1, 3, 4);
        traffic.Add(2, 5, 6);
        traffic.Add(3, 7, 8);

        auto g = traffic.Total();
        EXPECT_EQ(g.Up, 16);
        EXPECT_EQ(g.Down, 20);
        EXPECT_EQ(traffic.WorkerCount(), 4);
    }

    TEST(PerWorkerTraffic, OutOfRangeIgnored)
    {
        Preview::Runtime::PerWorkerTraffic traffic(2);
        traffic.Add(99, 100, 100);
        EXPECT_EQ(traffic.Total().Up, 0);
        EXPECT_EQ(traffic.Slot(99).Up, 0);
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
            EXPECT_EQ(traffic.Slot(w).Up, expect_per_worker);
            EXPECT_EQ(traffic.Slot(w).Down,
                      static_cast<std::uint64_t>(threads_per) * iters * 1);
        }
        EXPECT_EQ(traffic.Total().Up, expect_per_worker * workers);
    }

    TEST(IdentityTraffic, AggregateByIdentity)
    {
        Preview::Runtime::IdentityTraffic traffic;
        traffic.Add("alice", 10, 20);
        traffic.Add("alice", 5, 5);
        traffic.Add("bob", 100, 1);

        auto a = traffic.PerIdentity("alice");
        EXPECT_EQ(a.Up, 15);
        EXPECT_EQ(a.Down, 25);
        auto b = traffic.PerIdentity("bob");
        EXPECT_EQ(b.Up, 100);
        EXPECT_EQ(traffic.PerIdentity("nobody").Up, 0);
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
            total_up += pod.Up;
        }
        EXPECT_EQ(total_up, 4);
    }

    TEST(IdentityTraffic, ConcurrentCopyOnWriteExactTotals)
    {
        constexpr int Writers = 8;
        constexpr int Rounds = 250;
        constexpr int SharedIdentities = 8;
        constexpr std::uint64_t SharedUp = static_cast<std::uint64_t>(Writers) * Rounds * 3;
        constexpr std::uint64_t SharedDown = static_cast<std::uint64_t>(Writers) * Rounds * 5;

        Preview::Runtime::IdentityTraffic traffic;
        std::vector<std::thread> threads;
        for (int writer = 0; writer < Writers; ++writer)
        {
            threads.emplace_back([&, writer]
                                 {
                                     for (int round = 0; round < Rounds; ++round)
                                     {
                                         for (int id = 0; id < SharedIdentities; ++id)
                                         {
                                             traffic.Add("shared-" + std::to_string(id), 3, 5);
                                             traffic.Add("writer-" + std::to_string(writer) + "-" +
                                                            std::to_string(id),
                                                        7, 11);
                                         }
                                     }
                                 });
        }
        for (auto &thread : threads)
        {
            thread.join();
        }

        EXPECT_EQ(traffic.IdentityCount(),
                  static_cast<std::size_t>(SharedIdentities + Writers * SharedIdentities));
        for (int id = 0; id < SharedIdentities; ++id)
        {
            const auto shared = traffic.PerIdentity("shared-" + std::to_string(id));
            EXPECT_EQ(shared.Up, SharedUp);
            EXPECT_EQ(shared.Down, SharedDown);
        }

        const auto snapshot = traffic.All();
        ASSERT_EQ(snapshot.size(), static_cast<std::size_t>(SharedIdentities * (Writers + 1)));
        std::uint64_t totalUp = 0;
        std::uint64_t totalDown = 0;
        for (const auto &[identity, pod] : snapshot)
        {
            (void)identity;
            totalUp += pod.Up;
            totalDown += pod.Down;
        }
        EXPECT_EQ(totalUp, SharedUp * SharedIdentities +
                               static_cast<std::uint64_t>(Writers * SharedIdentities * Rounds) * 7);
        EXPECT_EQ(totalDown, SharedDown * SharedIdentities +
                                 static_cast<std::uint64_t>(Writers * SharedIdentities * Rounds) * 11);

        traffic.Add("after-snapshot", 13, 17);
        EXPECT_EQ(snapshot.size(), static_cast<std::size_t>(SharedIdentities * (Writers + 1)));
        EXPECT_EQ(traffic.IdentityCount(),
                  static_cast<std::size_t>(SharedIdentities * (Writers + 1) + 1));
    }

    TEST(TrafficPod, MergeSemantics)
    {
        Preview::Runtime::TrafficPod a{1, 2};
        Preview::Runtime::TrafficPod b{3, 4};
        a += b;
        EXPECT_EQ(a.Up, 4);
        EXPECT_EQ(a.Down, 6);

        const auto c = Preview::Runtime::TrafficPod{1, 1} + Preview::Runtime::TrafficPod{2, 2};
        EXPECT_EQ(c.Up, 3);
        EXPECT_EQ(c.Down, 3);
    }

} // namespace
