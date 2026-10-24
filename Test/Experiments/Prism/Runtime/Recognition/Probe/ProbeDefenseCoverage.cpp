/**
 * @file ProbeDefenseCoverage.cpp
 * @brief ProbeDefense 与地址散列行为测试。
 */
#include <gtest/gtest.h>
#include <chrono>
#include <Experiments/Prism/Runtime/Recognition/Probe/ProbeDefense.hpp>
namespace
{
    std::chrono::steady_clock::time_point ProbeNow{};
    auto FakeProbeNow() -> std::chrono::steady_clock::time_point { return ProbeNow; }
}
TEST(CoreModules, AddressHashBasic)
    {
        const auto v4a = Prism::Experiments::Recognition::AddressHash::FromV4(0x7F000001);
        const auto v4b = Prism::Experiments::Recognition::AddressHash::FromV4(0x7F000001);
        const auto v4c = Prism::Experiments::Recognition::AddressHash::FromV4(0x7F000002);
        EXPECT_EQ(v4a, v4b);
        EXPECT_NE(v4a, v4c);

        const std::array<std::byte, 16> ip6{};
        EXPECT_EQ(Prism::Experiments::Recognition::AddressHash::FromV6(ip6),
                  Prism::Experiments::Recognition::AddressHash::FromV6(ip6));
    }

TEST(ProbeDefense, QueriesExpireRecordsWithoutExplicitExpireCall)
    {
        ProbeNow = {};
        const auto source = Prism::Experiments::Recognition::AddressHash::FromV4(0x7F000001);
        Prism::Experiments::Recognition::ProbeDefenseTracker tracker(
            Prism::Experiments::Recognition::ProbeDefenseConfig{
                .TrackWindowSec = 10, .FailThreshold = 2, .MaxRecords = 8},
            FakeProbeNow);

        tracker.Record(source, 1);
        tracker.Record(source, 1);
        ASSERT_TRUE(tracker.ShouldChallenge(source));

        ProbeNow += std::chrono::seconds(11);
        EXPECT_EQ(tracker.FailCount(source), 0u);
        EXPECT_FALSE(tracker.ShouldChallenge(source));
    }

TEST(ProbeDefense, ZeroMaxRecordsDoesNotRetainSources)
    {
        Prism::Experiments::Recognition::ProbeDefenseTracker tracker(
            Prism::Experiments::Recognition::ProbeDefenseConfig{
                .TrackWindowSec = 300, .FailThreshold = 1, .MaxRecords = 0},
            FakeProbeNow);
        const auto source = Prism::Experiments::Recognition::AddressHash::FromV4(0x7F000001);

        tracker.Record(source, 1);
        EXPECT_EQ(tracker.FailCount(source), 0u);
        EXPECT_FALSE(tracker.ShouldChallenge(source));
    }
