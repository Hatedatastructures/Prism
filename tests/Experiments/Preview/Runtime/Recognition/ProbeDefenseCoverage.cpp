/**
 * @file ProbeDefenseCoverage.cpp
 * @brief ProbeDefense 与地址散列行为测试。
 */
#include <gtest/gtest.h>
#include <chrono>
#include <Experiments/Preview/Runtime/Recognition/ProbeDefense.hpp>
namespace
{
    std::chrono::steady_clock::time_point ProbeNow{};
    auto FakeProbeNow() -> std::chrono::steady_clock::time_point { return ProbeNow; }
}
TEST(CoreModules, AddressHashBasic)
    {
        const auto v4a = Preview::Experiments::Recognition::AddressHash::FromV4(0x7F000001);
        const auto v4b = Preview::Experiments::Recognition::AddressHash::FromV4(0x7F000001);
        const auto v4c = Preview::Experiments::Recognition::AddressHash::FromV4(0x7F000002);
        EXPECT_EQ(v4a, v4b);
        EXPECT_NE(v4a, v4c);

        const std::array<std::byte, 16> ip6{};
        EXPECT_EQ(Preview::Experiments::Recognition::AddressHash::FromV6(ip6),
                  Preview::Experiments::Recognition::AddressHash::FromV6(ip6));
    }

TEST(ProbeDefense, QueriesExpireRecordsWithoutExplicitExpireCall)
    {
        ProbeNow = {};
        const auto source = Preview::Experiments::Recognition::AddressHash::FromV4(0x7F000001);
        Preview::Experiments::Recognition::ProbeDefenseTracker tracker(10, 2, 8, FakeProbeNow);

        tracker.Record(source, 1);
        tracker.Record(source, 1);
        ASSERT_TRUE(tracker.ShouldChallenge(source));

        ProbeNow += std::chrono::seconds(11);
        EXPECT_EQ(tracker.FailCount(source), 0u);
        EXPECT_FALSE(tracker.ShouldChallenge(source));
    }

TEST(ProbeDefense, ZeroMaxRecordsDoesNotRetainSources)
    {
        Preview::Experiments::Recognition::ProbeDefenseTracker tracker(300, 1, 0, FakeProbeNow);
        const auto source = Preview::Experiments::Recognition::AddressHash::FromV4(0x7F000001);

        tracker.Record(source, 1);
        EXPECT_EQ(tracker.FailCount(source), 0u);
        EXPECT_FALSE(tracker.ShouldChallenge(source));
    }

