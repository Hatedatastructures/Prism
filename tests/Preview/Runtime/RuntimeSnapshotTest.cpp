/**
 * @file RuntimeSnapshotTest.cpp
 * @brief Runtime 会话与流量快照 owner 测试。
 * @details 验证 SessionRegistry 和 TrafficCounter 发布当前运行时快照值。
 */

#include <gtest/gtest.h>

#include <Preview/Runtime/Statistics.hpp>
#include <Preview/Runtime/SessionRegistry.hpp>

TEST(RuntimeSnapshot, SessionListAndTrafficValues)
{
    Preview::Runtime::SessionRegistry Registry;
    Preview::Runtime::SessionInfo Info;
    Info.Id = 7;
    Info.identity = "alice";
    Info.peer = "10.0.0.1";
    Info.Target = "example.com:443";
    boost::asio::io_context Io;
    auto Control = std::make_shared<Preview::Runtime::SessionControl>(Io.get_executor());
    auto Registration = Registry.Register(Info, Control);
    ASSERT_TRUE(Registration);

    Preview::Runtime::TrafficCounter Traffic({
        .Process = Preview::ProcessId{1}, .Generation = Preview::GenerationId{1},
        .Workers = 1, .MaxCounterEntries = 256});
    Traffic.Report(Preview::Foundation::TrafficEvent{
        .Generation = Preview::GenerationId{1}, .Worker = Preview::WorkerId{0},
        .Session = Preview::SessionId{7}, .Account = Preview::AccountId{7},
        .Up = 100, .Down = 200});
    Traffic.Flush();

    const auto Sessions = Registry.Snapshot();
    ASSERT_EQ(Sessions->size(), 1U);
    const auto &Session = Sessions->at(7);
    EXPECT_EQ(Session.identity, "alice");
    EXPECT_EQ(Session.peer, "10.0.0.1");
    EXPECT_EQ(Session.Target, "example.com:443");

    const auto Total = Traffic.Value(Preview::Statistics::Scope::Account, 7);
    EXPECT_EQ(Total.UpBytes, 100U);
    EXPECT_EQ(Total.DownBytes, 200U);
    EXPECT_EQ(Registry.Size(), 1U);
}

TEST(RuntimeSnapshot, EmptyValuesRemainEmpty)
{
    Preview::Runtime::SessionRegistry Registry;
    Preview::Runtime::TrafficCounter Traffic({
        .Process = Preview::ProcessId{1}, .Generation = Preview::GenerationId{1},
        .Workers = 1, .MaxCounterEntries = 256});

    EXPECT_TRUE(Registry.Snapshot()->empty());
    EXPECT_EQ(Traffic.Value(Preview::Statistics::Scope::Account, 7).UpBytes, 0U);
    EXPECT_EQ(Registry.Size(), 0U);
}

TEST(RuntimeSnapshot, NumericTrafficCountsCurrentOwners)
{
    Preview::Runtime::TrafficCounter Counter({
        .Process = Preview::ProcessId{1}, .Generation = Preview::GenerationId{1},
        .Workers = 1, .MaxCounterEntries = 256});
    Counter.Report(Preview::Foundation::TrafficEvent{
        .Generation = Preview::GenerationId{1}, .Worker = Preview::WorkerId{0},
        .Account = Preview::AccountId{1}, .Up = 10, .Down = 20});
    Counter.Report(Preview::Foundation::TrafficEvent{
        .Generation = Preview::GenerationId{1}, .Worker = Preview::WorkerId{0},
        .Account = Preview::AccountId{2}, .Up = 30, .Down = 40});
    Counter.Report(Preview::Foundation::TrafficEvent{
        .Generation = Preview::GenerationId{1}, .Worker = Preview::WorkerId{0},
        .Account = Preview::AccountId{3}, .Up = 1, .Down = 2});
    Counter.Flush();
    EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Account, 1).UpBytes, 10U);
    EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Account, 2).DownBytes, 40U);
    EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Account, 3).UpBytes, 1U);
}
