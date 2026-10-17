/** @file AnalysisHistoryTest.cpp @brief 可合并延迟、历史窗口和协议归属口径测试。 */
#include <gtest/gtest.h>
#include <Preview/Statistics/Analysis/HistorySeries.hpp>

namespace
{
    namespace Statistics = Preview::Statistics;

    TEST(AnalysisHistogram, MergeUsesSampleRanksInsteadOfAveragingPercentiles)
    {
        Statistics::LatencyHistogram First;
        Statistics::LatencyHistogram Second;
        for (unsigned Index = 0; Index < 100; ++Index) First.Record(1U);
        Second.Record(1'000'000U);
        ASSERT_TRUE(First.Merge(Second));
        EXPECT_EQ(First.Count(), 101U);
        EXPECT_EQ(First.Percentile(95U), 1U);
        EXPECT_EQ(First.Maximum, 1'000'000U);
    }

    TEST(AnalysisHistogram, EmptyAndBoundarySamplesAreExplicit)
    {
        Statistics::LatencyHistogram Value;
        EXPECT_FALSE(Value.Percentile(95U));
        Value.Record(0U);
        Value.Record(300'000'001U);
        EXPECT_EQ(Value.RangeExceeded, 1U);
        EXPECT_EQ(Value.Percentile(100U), 300'000'001U);
        EXPECT_EQ(Value.Count(), 2U);
    }

    TEST(AnalysisHistory, DownsamplingPreservesTotalsAndMergesHistograms)
    {
        Statistics::HistoryRecord First;
        First.Key = "instance";
        First.Incarnation = "first";
        First.Timestamp = 10'000U;
        First.ResolutionMilliseconds = 1'000U;
        First.UpBytes = 5U;
        First.Latency.Record(2U);
        auto Second = First;
        Second.Timestamp = 11'000U;
        Second.UpBytes = 7U;
        Second.Latency = {};
        Second.Latency.Record(100U);
        const auto Result = Statistics::AggregateHistory({First, Second}, 10'000U);
        ASSERT_EQ(Result.size(), 1U);
        EXPECT_EQ(Result.front().UpBytes, 12U);
        EXPECT_EQ(Result.front().Latency.Count(), 2U);
        EXPECT_EQ(Result.front().Latency.Percentile(95U), 64U);
    }

    TEST(AnalysisHistory, RestartsAndGenerationChangesNeverMergeSilently)
    {
        Statistics::HistoryRecord First;
        First.Key = "process";
        First.Incarnation = "before";
        First.Timestamp = 1'000U;
        auto Second = First;
        Second.Timestamp = 2'000U;
        Second.Incarnation = "after";
        EXPECT_EQ(Statistics::AggregateHistory({First, Second}, 10'000U).size(), 2U);
        Second.Incarnation = First.Incarnation;
        Second.Generation = 2U;
        EXPECT_EQ(Statistics::AggregateHistory({First, Second}, 10'000U).size(), 2U);
    }

    TEST(AnalysisHistory, ResolutionUsesRetentionAndPointBudget)
    {
        constexpr auto Now = 40ULL * 24U * 60U * 60U * 1000U;
        Statistics::HistoryQuery Query;
        Query.From = Now - 30ULL * 24U * 60U * 60U * 1000U;
        Query.To = Now;
        Query.MaxPoints = 1200U;
        EXPECT_EQ(Statistics::HistoryResolution(Query, Now), 2'700'000U);
        Query.From = Now - 60'000U;
        EXPECT_EQ(Statistics::HistoryResolution(Query, Now), 1'000U);
        Query.MaxPoints = 0;
        EXPECT_FALSE(ValidStatistics::HistoryQuery(Query));
    }
}
