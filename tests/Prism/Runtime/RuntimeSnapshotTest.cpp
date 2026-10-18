/**
 * @file RuntimeSnapshotTest.cpp
 * @brief Runtime 会话与流量快照 owner 测试。
 * @details 验证 SessionRegistry 和 TrafficCounter 发布当前运行时快照值。
 */

#include <gtest/gtest.h>

#include <Prism/Runtime/Statistics.hpp>
#include <Prism/Runtime/SessionRegistry.hpp>

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
        .Workers = 1, .MaxCounterEntries = 256});
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
    Prism::Runtime::TrafficCounter Traffic({
        .Process = Prism::ProcessId{1}, .Generation = Prism::GenerationId{1},
        .Workers = 1, .MaxCounterEntries = 256});

    EXPECT_TRUE(Registry.Snapshot()->empty());
    EXPECT_EQ(Traffic.Value(Prism::Statistics::Scope::Account, 7).UpBytes, 0U);
    EXPECT_EQ(Registry.Size(), 0U);
}

TEST(RuntimeSnapshot, NumericTrafficCountsCurrentOwners)
{
    Prism::Runtime::TrafficCounter Counter({
        .Process = Prism::ProcessId{1}, .Generation = Prism::GenerationId{1},
        .Workers = 1, .MaxCounterEntries = 256});
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
