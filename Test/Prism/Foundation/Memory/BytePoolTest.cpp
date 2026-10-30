/**
 * @file BytePoolTest.cpp
 * @brief 验证字节池小容量启动、按需分段增长和并发上限。
 */

#include <Prism/Foundation/Memory/BytePool.hpp>

#include <gtest/gtest.h>

#include <cstddef>
#include <latch>
#include <set>
#include <thread>
#include <utility>
#include <vector>

namespace
{
    TEST(BytePool, DefaultStartsSmallAndRetainsConfiguredLimit)
    {
        Prism::Memory::BytePool Pool;
        const auto Snapshot = Pool.Snapshot();
        EXPECT_EQ(Pool.CapacityBytes(), 4U * 1024U * 1024U);
        EXPECT_EQ(Pool.LimitBytes(), 128U * 1024U * 1024U);
        EXPECT_EQ(Snapshot.CapacityBytes, 4U * 1024U * 1024U);
        EXPECT_EQ(Snapshot.LimitBytes, 128U * 1024U * 1024U);
        EXPECT_EQ(Snapshot.PeakCapacityBytes, 4U * 1024U * 1024U);
        EXPECT_EQ(Snapshot.GrowthCount, 0U);
    }

    TEST(BytePool, GrowsOnDemandAndRetainsAllocatedSegments)
    {
        Prism::Memory::BytePool Pool(
            {.BlockSize = 64U, .BlockCount = 5U, .InitialBlockCount = 2U, .GrowthBlockCount = 2U});

        auto Snapshot = Pool.Snapshot();
        EXPECT_EQ(Pool.CapacityBytes(), 128U);
        EXPECT_EQ(Pool.LimitBytes(), 320U);
        EXPECT_EQ(Snapshot.CapacityBytes, 128U);
        EXPECT_EQ(Snapshot.LimitBytes, 320U);
        EXPECT_EQ(Snapshot.AvailableBytes, 128U);
        EXPECT_EQ(Snapshot.GrowthCount, 0U);

        auto First = Pool.TryAcquire(64U);
        auto Second = Pool.TryAcquire(64U);
        ASSERT_TRUE(First);
        ASSERT_TRUE(Second);
        Snapshot = Pool.Snapshot();
        EXPECT_EQ(Snapshot.UsedBytes, 128U);
        EXPECT_EQ(Snapshot.AvailableBytes, 0U);
        EXPECT_EQ(Snapshot.CapacityBytes, 128U);

        auto Third = Pool.TryAcquire(64U);
        ASSERT_TRUE(Third);
        Snapshot = Pool.Snapshot();
        EXPECT_EQ(Snapshot.CapacityBytes, 256U);
        EXPECT_EQ(Snapshot.GrowthCount, 1U);

        auto Fourth = Pool.TryAcquire(64U);
        ASSERT_TRUE(Fourth);
        auto Fifth = Pool.TryAcquire(64U);
        ASSERT_TRUE(Fifth);
        Snapshot = Pool.Snapshot();
        EXPECT_EQ(Snapshot.CapacityBytes, 320U);
        EXPECT_EQ(Snapshot.PeakCapacityBytes, 320U);
        EXPECT_EQ(Snapshot.GrowthCount, 2U);
        EXPECT_EQ(Snapshot.UsedBytes, 320U);
        EXPECT_EQ(Snapshot.AvailableBytes, 0U);

        const auto Exhausted = Pool.TryAcquire(1U);
        EXPECT_FALSE(Exhausted);
        EXPECT_EQ(Exhausted.error().Code, Prism::Fault::Code::ResourceUnavailable);

        Third->Release();
        Snapshot = Pool.Snapshot();
        EXPECT_EQ(Snapshot.CapacityBytes, 320U);
        EXPECT_EQ(Snapshot.AvailableBytes, 64U);
        EXPECT_EQ(Snapshot.GrowthCount, 2U);
    }

    TEST(BytePool, SmallConfiguredLimitKeepsImmediateCapacity)
    {
        Prism::Memory::BytePool Pool({.BlockSize = 64U, .BlockCount = 3U});
        const auto Snapshot = Pool.Snapshot();
        EXPECT_EQ(Snapshot.CapacityBytes, 192U);
        EXPECT_EQ(Snapshot.LimitBytes, 192U);
        EXPECT_EQ(Snapshot.AvailableBytes, 192U);
        EXPECT_EQ(Snapshot.GrowthCount, 0U);
    }

    TEST(BytePool, ConcurrentGrowthStopsAtConfiguredLimit)
    {
        constexpr std::size_t ThreadCount = 8U;
        constexpr std::size_t MaxBlocks = 65U;
        Prism::Memory::BytePool Pool(
            {.BlockSize = 64U, .BlockCount = MaxBlocks, .InitialBlockCount = 3U, .GrowthBlockCount = 7U});

        std::vector<std::vector<Prism::Memory::OwnedBytes>> Leases(ThreadCount);
        std::vector<std::thread> Threads;
        Threads.reserve(ThreadCount);
        std::latch Start(1);
        std::latch Finished(ThreadCount);
        for (std::size_t Index = 0; Index < ThreadCount; ++Index)
        {
            Threads.emplace_back(
                [&, Index]
                {
                    Start.wait();
                    for (;;)
                    {
                        auto Lease = Pool.TryAcquire(1U);
                        if (!Lease)
                        {
                            break;
                        }
                        Leases[Index].push_back(std::move(*Lease));
                    }
                    Finished.count_down();
                });
        }
        Start.count_down();
        Finished.wait();
        for (auto& Thread : Threads)
        {
            Thread.join();
        }

        std::size_t Total = 0;
        std::set<const std::byte*> Addresses;
        for (const auto& OwnerLeases : Leases)
        {
            for (const auto& Lease : OwnerLeases)
            {
                ++Total;
                Addresses.insert(Lease.Bytes().data());
            }
        }
        EXPECT_EQ(Total, MaxBlocks);
        EXPECT_EQ(Addresses.size(), MaxBlocks);

        const auto Snapshot = Pool.Snapshot();
        EXPECT_EQ(Snapshot.CapacityBytes, Snapshot.LimitBytes);
        EXPECT_EQ(Snapshot.UsedBytes, MaxBlocks * 64U);
        EXPECT_EQ(Snapshot.AvailableBytes, 0U);
        EXPECT_GT(Snapshot.GrowthCount, 0U);
    }
} // namespace
