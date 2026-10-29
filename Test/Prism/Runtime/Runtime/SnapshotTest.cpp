/**
 * @file SnapshotTest.cpp
 * @brief Runtime 会话与流量快照 owner 测试。
 * @details 验证 SessionRegistry 和 TrafficCounter 发布当前运行时快照值。
 */

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>

#include <Prism/Runtime/Statistics.hpp>
#include <Prism/Runtime/Session/Registry.hpp>

TEST(RuntimeSnapshot, SessionListAndTrafficValues)
{
    Prism::Runtime::SessionRegistry Registry;
    Prism::Runtime::SessionInfo Info;
    Info.Id = 7;
    Info.identity = "alice";
    Info.peer = "10.0.0.1";
    Info.Target = "example.com:443";
    boost::asio::io_context Io;
    auto Control = std::make_shared<Prism::Runtime::SessionControl>(Io.get_executor());
    auto Registration = Registry.Register(Info, Control);
    ASSERT_TRUE(Registration);

    Prism::Runtime::TrafficCounter Traffic({
        .Process = Prism::ProcessId{1}, .Generation = Prism::GenerationId{1},
        .Workers = 1, .MaxCounterEntries = 256}, Io.get_executor());
    Traffic.Report(Prism::Foundation::TrafficEvent{
        .Generation = Prism::GenerationId{1}, .Worker = Prism::WorkerId{0},
        .Session = Prism::SessionId{7}, .Account = Prism::AccountId{7},
        .Up = 100, .Down = 200});
    Traffic.Flush();

    const auto Sessions = Registry.Snapshot();
    ASSERT_EQ(Sessions->size(), 1U);
    const auto &Session = Sessions->at(7);
    EXPECT_EQ(Session.identity, "alice");
    EXPECT_EQ(Session.peer, "10.0.0.1");
    EXPECT_EQ(Session.Target, "example.com:443");

    const auto Total = Traffic.Value(Prism::Statistics::Scope::Account, 7);
    EXPECT_EQ(Total.UpBytes, 100U);
    EXPECT_EQ(Total.DownBytes, 200U);
    EXPECT_EQ(Registry.Size(), 1U);
}

TEST(RuntimeSnapshot, EmptyValuesRemainEmpty)
{
    Prism::Runtime::SessionRegistry Registry;
    boost::asio::io_context Io;
    Prism::Runtime::TrafficCounter Traffic({
        .Process = Prism::ProcessId{1}, .Generation = Prism::GenerationId{1},
        .Workers = 1, .MaxCounterEntries = 256}, Io.get_executor());

    EXPECT_TRUE(Registry.Snapshot()->empty());
    EXPECT_EQ(Traffic.Value(Prism::Statistics::Scope::Account, 7).UpBytes, 0U);
    EXPECT_EQ(Registry.Size(), 0U);
}

TEST(RuntimeSnapshot, NumericTrafficCountsCurrentOwners)
{
    boost::asio::io_context Io;
    Prism::Runtime::TrafficCounter Counter({
        .Process = Prism::ProcessId{1}, .Generation = Prism::GenerationId{1},
        .Workers = 1, .MaxCounterEntries = 256}, Io.get_executor());
    Counter.Report(Prism::Foundation::TrafficEvent{
        .Generation = Prism::GenerationId{1}, .Worker = Prism::WorkerId{0},
        .Account = Prism::AccountId{1}, .Up = 10, .Down = 20});
    Counter.Report(Prism::Foundation::TrafficEvent{
        .Generation = Prism::GenerationId{1}, .Worker = Prism::WorkerId{0},
        .Account = Prism::AccountId{2}, .Up = 30, .Down = 40});
    Counter.Report(Prism::Foundation::TrafficEvent{
        .Generation = Prism::GenerationId{1}, .Worker = Prism::WorkerId{0},
        .Account = Prism::AccountId{3}, .Up = 1, .Down = 2});
    Counter.Flush();
    EXPECT_EQ(Counter.Value(Prism::Statistics::Scope::Account, 1).UpBytes, 10U);
    EXPECT_EQ(Counter.Value(Prism::Statistics::Scope::Account, 2).DownBytes, 40U);
    EXPECT_EQ(Counter.Value(Prism::Statistics::Scope::Account, 3).UpBytes, 1U);
}

TEST(RuntimeSnapshot, RecognitionLatencyTraversesQueueHistogramAndRecentTracer)
{
    boost::asio::io_context Io;
    Prism::Runtime::TrafficCounter Counter({
        .Process = Prism::ProcessId{1}, .Generation = Prism::GenerationId{1},
        .Workers = 1, .MaxCounterEntries = 256}, Io.get_executor());
    Counter.ReportRecognitionLatency({
        .Generation = Prism::GenerationId{1}, .Worker = Prism::WorkerId{0},
        .Session = Prism::SessionId{8}, .DurationMicroseconds = 52U});
    Counter.ReportRecognitionLatency({
        .Generation = Prism::GenerationId{1}, .Worker = Prism::WorkerId{0},
        .Session = Prism::SessionId{9}, .DurationMicroseconds = 49U});
    Counter.ReportRecognitionLatency({
        .Generation = Prism::GenerationId{1}, .Worker = Prism::WorkerId{0},
        .Session = Prism::SessionId{10}, .DurationMicroseconds = 300'000'001U});

    EXPECT_EQ(Counter.Accepted(), 3U);
    EXPECT_EQ(Counter.ConsumedObservations(), 0U);
    Counter.Flush();

    const auto Snapshot = Counter.RecognitionLatency(Prism::GenerationId{1});
    EXPECT_EQ(Counter.ConsumedObservations(), 3U);
    EXPECT_EQ(Counter.RecognitionLatencyQueueDrops(), 0U);
    EXPECT_EQ(Counter.RecognitionLatencyAggregationFailures(), 0U);
    EXPECT_EQ(Snapshot.Generation, Prism::GenerationId{1});
    EXPECT_EQ(Snapshot.SampleCount, 3U);
    EXPECT_EQ(Snapshot.TracerWrittenCount, 3U);
    EXPECT_EQ(Snapshot.TracerDroppedCount, 0U);
    EXPECT_EQ(Snapshot.HistogramRangeExceeded, 1U);
    ASSERT_EQ(Snapshot.RecentCount, 3U);
    EXPECT_EQ(Snapshot.RecentMicroseconds[0], 300'000'001U);
    EXPECT_EQ(Snapshot.RecentMicroseconds[1], 49U);
    EXPECT_EQ(Snapshot.RecentMicroseconds[2], 52U);
    ASSERT_TRUE(Snapshot.P50BucketLowerBoundMicroseconds.has_value());
    ASSERT_TRUE(Snapshot.MaximumObservedMicroseconds.has_value());
    EXPECT_LE(*Snapshot.P50BucketLowerBoundMicroseconds,
        *Snapshot.MaximumObservedMicroseconds);
    EXPECT_EQ(*Snapshot.MaximumObservedMicroseconds, 300'000'001U);
}
