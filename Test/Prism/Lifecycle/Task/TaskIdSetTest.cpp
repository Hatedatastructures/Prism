/**
 * @file TaskIdSetTest.cpp
 * @brief 任务身份集合的值语义、旧快照与并发发布行为。
 */

#include <Prism/Lifecycle/TaskIdSet.hpp>

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <set>
#include <stdexcept>
#include <thread>
#include <vector>

namespace
{
    using IdSet = Prism::Lifecycle::Detail::TaskIdSet;

    auto Values(const IdSet &Set) -> std::vector<std::uint64_t>
    {
        std::vector<std::uint64_t> Result;
        Set.ForEach([&Result](std::uint64_t Value) { Result.push_back(Value); });
        return Result;
    }

    TEST(TaskIdSet, KeepsOldSnapshotsAfterInsertAndErase)
    {
        IdSet Current;
        EXPECT_TRUE(Current.Insert(17));
        EXPECT_TRUE(Current.Insert(5));
        const auto Old = Current;
        EXPECT_FALSE(Current.Insert(17));
        EXPECT_TRUE(Current.Insert(23));
        EXPECT_TRUE(Current.Erase(5));
        EXPECT_FALSE(Current.Erase(5));
        EXPECT_EQ(Values(Old), (std::vector<std::uint64_t>{5, 17}));
        EXPECT_EQ(Values(Current), (std::vector<std::uint64_t>{17, 23}));
        EXPECT_EQ(Old.Size(), 2U);
        EXPECT_TRUE(Old.Contains(5));
        EXPECT_FALSE(Old.Contains(23));
    }

    TEST(TaskIdSet, HandlesNumericBoundariesAndEmptyRemoval)
    {
        IdSet Current;
        constexpr auto Maximum = (std::numeric_limits<std::uint64_t>::max)();
        EXPECT_FALSE(Current.Erase(0));
        EXPECT_TRUE(Current.Insert(Maximum));
        EXPECT_TRUE(Current.Insert(0));
        EXPECT_TRUE(Current.Insert(1));
        EXPECT_EQ(Values(Current), (std::vector<std::uint64_t>{0, 1, Maximum}));
        EXPECT_TRUE(Current.Erase(Maximum));
        EXPECT_TRUE(Current.Erase(0));
        EXPECT_TRUE(Current.Erase(1));
        EXPECT_EQ(Current.Size(), 0U);
        EXPECT_TRUE(Values(Current).empty());
    }

    TEST(TaskIdSet, ForEachVisitsEmptySingleAndMultipleValuesInOrder)
    {
        std::vector<std::uint64_t> Visited;
        const auto Append = [&Visited](const std::uint64_t Value) -> void
        {
            Visited.push_back(Value);
        };

        IdSet Empty;
        Empty.ForEach(Append);
        EXPECT_TRUE(Visited.empty());

        IdSet Single;
        ASSERT_TRUE(Single.Insert(9U));
        Single.ForEach(Append);
        EXPECT_EQ(Visited, (std::vector<std::uint64_t>{9U}));

        IdSet Multiple;
        ASSERT_TRUE(Multiple.Insert(12U));
        ASSERT_TRUE(Multiple.Insert(3U));
        ASSERT_TRUE(Multiple.Insert(8U));
        Multiple.ForEach([&Visited](const std::uint64_t Value) -> void
        {
            Visited.push_back(Value);
        });
        EXPECT_EQ(Visited, (std::vector<std::uint64_t>{9U, 3U, 8U, 12U}));
    }

    TEST(TaskIdSet, MatchesIndependentOrderedSetForMixedTrace)
    {
        IdSet Current;
        std::set<std::uint64_t> Expected;
        std::uint64_t Seed = 0x77D4A2B1;
        for (std::size_t Index = 0; Index < 10000; ++Index)
        {
            Seed = Seed * 6364136223846793005ULL + 1442695040888963407ULL;
            const auto Value = (Seed >> 17U) % 2048U;
            const auto Old = Current;
            const auto OldValues = Values(Old);
            if ((Seed & 1U) != 0U)
            {
                EXPECT_EQ(Current.Insert(Value), Expected.insert(Value).second);
            }
            else
            {
                EXPECT_EQ(Current.Erase(Value), Expected.erase(Value) != 0U);
            }
            EXPECT_EQ(Current.Contains(Value), Expected.contains(Value));
            EXPECT_EQ(Current.Size(), Expected.size());
            EXPECT_EQ(Values(Current),
                      std::vector<std::uint64_t>(Expected.begin(), Expected.end()));
            EXPECT_EQ(Values(Old), OldValues);
        }
    }

    /** @brief 每个线程保有自己的修改副本，发布成功后保留旧快照。 */
    auto PublishLane(std::atomic<std::shared_ptr<const IdSet>> &Published,
                     std::size_t Lane) -> void
    {
        for (std::size_t Index = 0; Index < 1024; ++Index)
        {
            const auto Value = Lane * 1024U + Index + 1U;
            auto Current = Published.load(std::memory_order_acquire);
            for (;;)
            {
                auto Next = std::make_shared<IdSet>(*Current);
                if (!Next->Insert(Value))
                {
                    throw std::runtime_error("重复任务身份");
                }
                std::shared_ptr<const IdSet> Immutable = std::move(Next);
                if (Published.compare_exchange_weak(Current, Immutable))
                {
                    break;
                }
            }
        }
    }

    TEST(TaskIdSet, ConcurrentPublicationPreservesEveryIdentity)
    {
        std::atomic<std::shared_ptr<const IdSet>> Published{std::make_shared<const IdSet>()};
        const auto Empty = Published.load();
        std::array<std::exception_ptr, 4> Failures{};
        std::array<std::jthread, 4> Threads;
        for (std::size_t Lane = 0; Lane < Threads.size(); ++Lane)
        {
            Threads[Lane] = std::jthread([&Published, &Failures, Lane]
            {
                try { PublishLane(Published, Lane); }
                catch (...) { Failures[Lane] = std::current_exception(); }
            });
        }
        for (auto &Thread : Threads) { Thread.join(); }
        for (const auto &Failure : Failures) { EXPECT_FALSE(Failure); }
        const auto Final = Published.load();
        ASSERT_EQ(Final->Size(), 4096U);
        for (std::uint64_t Value = 1; Value <= 4096; ++Value)
        {
            EXPECT_TRUE(Final->Contains(Value));
        }
        EXPECT_EQ(Empty->Size(), 0U);
        EXPECT_TRUE(Values(*Empty).empty());
    }
}
