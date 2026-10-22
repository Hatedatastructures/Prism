/** @file HistoryStoreTest.cpp @brief SQLite 历史追加、查询缺口、预算与保留边界。 */
#include "StorageTestSupport.hpp"

#include <Prism/Application/Storage/HistoryStore.hpp>
#include <Prism/Statistics/Analysis/HistoryModels.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <expected>
#include <string>
#include <utility>

namespace Prism::StorageTests
{
    namespace Statistics = Prism::Statistics;

    auto CurrentTimeMilliseconds() -> std::uint64_t
    {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    }

    auto AlignDown(const std::uint64_t Timestamp, const std::uint64_t Resolution) -> std::uint64_t
    {
        return Timestamp - Timestamp % Resolution;
    }

    auto AlignUp(const std::uint64_t Timestamp, const std::uint64_t Resolution) -> std::uint64_t
    {
        const auto Aligned = AlignDown(Timestamp, Resolution);
        return Aligned == Timestamp ? Timestamp : Aligned + Resolution;
    }

    auto MakeHistoryRecord(std::string Key, const std::uint64_t Timestamp,
                           const std::uint64_t Resolution) -> Statistics::HistoryRecord
    {
        Statistics::HistoryRecord Result;
        Result.Scope = Statistics::HistoryScope::Account;
        Result.Key = std::move(Key);
        Result.InstanceKey = "storage-test-instance";
        Result.Incarnation = "storage-test-incarnation";
        Result.Generation = 1U;
        Result.Timestamp = Timestamp;
        Result.ResolutionMilliseconds = Resolution;
        return Result;
    }

    auto MakeHistoryQuery(std::string Key, const std::uint64_t From, const std::uint64_t To)
        -> Statistics::HistoryQuery
    {
        Statistics::HistoryQuery Result;
        Result.Scope = Statistics::HistoryScope::Account;
        Result.Key = std::move(Key);
        Result.From = From;
        Result.To = To;
        Result.MaxPoints = 1U;
        return Result;
    }

    class HistoryStoreStorage : public StorageFixture
    {
    public:
        auto QueryRecord(const Statistics::HistoryRecord& Record)
            -> std::expected<Statistics::HistoryResult, Fault::Failure>
        {
            Application::Storage::HistoryStore Store(Owner);
            auto Request = MakeHistoryQuery(Record.Key, Record.Timestamp,
                Record.Timestamp + Record.ResolutionMilliseconds);
            return Run(Store.Query(std::move(Request)));
        }
    };

    TEST_F(HistoryStoreStorage, AppendUpsertsAWindowAndQueryReturnsReplacementValues)
    {
        Open();
        Application::Storage::HistoryStore Store(Owner);
        const auto Timestamp = AlignDown(CurrentTimeMilliseconds() - 60'000U, 10'000U);
        auto Record = MakeHistoryRecord("account-history", Timestamp, 10'000U);
        Record.UpBytes = 5U;
        Record.DownBytes = 7U;
        Record.Latency.Record(12U);
        ASSERT_TRUE(Run(Store.Append({Record})));

        Record.UpBytes = 17U;
        Record.DownBytes = 19U;
        Record.Latency = {};
        Record.Latency.Record(30U);
        ASSERT_TRUE(Run(Store.Append({Record})));

        auto Result = Run(Store.Query(MakeHistoryQuery(
            Record.Key, Timestamp, Timestamp + Record.ResolutionMilliseconds)));
        ASSERT_TRUE(Result);
        ASSERT_TRUE(Result->Available);
        ASSERT_EQ(Result->Items.size(), 1U);
        EXPECT_EQ(Result->Items.front().UpBytes, 17U);
        EXPECT_EQ(Result->Items.front().DownBytes, 19U);
        EXPECT_EQ(Result->Items.front().Latency.Count(), 1U);
        EXPECT_EQ(Result->Coverage, "complete");
        EXPECT_TRUE(Result->Gaps.empty());
    }

    TEST_F(HistoryStoreStorage, PersistedWindowSurvivesStorageRestart)
    {
        Open("history-before-restart");
        const auto Timestamp = AlignDown(CurrentTimeMilliseconds(), 10'000U);
        auto Record = MakeHistoryRecord("restart-history", Timestamp, 10'000U);
        Record.UpBytes = 23U;
        Record.DownBytes = 41U;
        Record.Events = 2U;
        Record.Errors = 1U;
        Record.Latency.Record(27U);
        const auto Request = MakeHistoryQuery(
            Record.Key, Timestamp, Timestamp + Record.ResolutionMilliseconds);
        {
            Application::Storage::HistoryStore Store(Owner);
            ASSERT_TRUE(Run(Store.Append({Record})));
        }

        Close();
        Open("history-after-restart");
        Application::Storage::HistoryStore Store(Owner);
        const auto Persisted = Run(Store.Query(Request));
        ASSERT_TRUE(Persisted);
        ASSERT_TRUE(Persisted->Available);
        ASSERT_EQ(Persisted->Items.size(), 1U);
        const auto& Restored = Persisted->Items.front();
        EXPECT_EQ(Restored.Timestamp, Timestamp);
        EXPECT_EQ(Restored.UpBytes, 23U);
        EXPECT_EQ(Restored.DownBytes, 41U);
        EXPECT_EQ(Restored.Events, 2U);
        EXPECT_EQ(Restored.Errors, 1U);
        EXPECT_EQ(Restored.Latency.Count(), 1U);
        EXPECT_EQ(Persisted->Coverage, "complete");
        EXPECT_TRUE(Persisted->Gaps.empty());
    }

    TEST_F(HistoryStoreStorage, QueryReportsMissingWindowsAndEnforcesPointBudget)
    {
        Open();
        Application::Storage::HistoryStore Store(Owner);
        const auto Now = CurrentTimeMilliseconds();
        const auto Base = (Now / 20'000U - 2U) * 20'000U + 10'000U;
        auto First = MakeHistoryRecord("point-budget", Base, 10'000U);
        First.UpBytes = 3U;
        auto Second = MakeHistoryRecord("point-budget", Base + 10'000U, 10'000U);
        Second.UpBytes = 5U;
        ASSERT_TRUE(Run(Store.Append({First, Second})));

        auto BudgetRequest = MakeHistoryQuery("point-budget", Base, Base + 15'000U);
        auto BudgetResult = Run(Store.Query(std::move(BudgetRequest)));
        ASSERT_TRUE(BudgetResult);
        EXPECT_EQ(BudgetResult->ResolutionMilliseconds, 20'000U);
        ASSERT_EQ(BudgetResult->Items.size(), 1U);
        const auto BudgetGap = std::find_if(BudgetResult->Gaps.begin(), BudgetResult->Gaps.end(),
            [](const auto& Gap) { return Gap.Reason == "point_budget"; });
        ASSERT_NE(BudgetGap, BudgetResult->Gaps.end());
        EXPECT_EQ(BudgetResult->Coverage, "partial");

        const auto GapBase = AlignDown(Now - 120'000U, 10'000U);
        auto BeforeGap = MakeHistoryRecord("missing-window", GapBase, 10'000U);
        auto AfterGap = MakeHistoryRecord("missing-window", GapBase + 20'000U, 10'000U);
        ASSERT_TRUE(Run(Store.Append({BeforeGap, AfterGap})));

        auto GapRequest = MakeHistoryQuery("missing-window", GapBase, GapBase + 30'000U);
        GapRequest.MaxPoints = 3U;
        const auto GapResult = Run(Store.Query(std::move(GapRequest)));
        ASSERT_TRUE(GapResult);
        ASSERT_EQ(GapResult->Items.size(), 2U);
        ASSERT_EQ(GapResult->Gaps.size(), 1U);
        EXPECT_EQ(GapResult->Gaps.front().From, GapBase + 10'000U);
        EXPECT_EQ(GapResult->Gaps.front().To, GapBase + 20'000U);
        EXPECT_EQ(GapResult->Gaps.front().Reason, "not_sampled");
        EXPECT_EQ(GapResult->Coverage, "partial");
    }

    TEST_F(HistoryStoreStorage, SmallHistoryBudgetRejectsAppendAndReportsCapacity)
    {
        const auto Opened = Run(Application::Storage::StorageRuntime::Open(
            {Directory, "small-history-budget", 1U}));
        ASSERT_TRUE(Opened);
        Owner = *Opened;
        Application::Storage::HistoryStore Store(Owner);
        const auto Timestamp = AlignDown(CurrentTimeMilliseconds() - 60'000U, 10'000U);
        auto Record = MakeHistoryRecord("budget-limited", Timestamp, 10'000U);

        const auto Appended = Run(Store.Append({Record}));
        ASSERT_FALSE(Appended);
        EXPECT_EQ(Appended.error().Code, Fault::Code::ResourceUnavailable);

        const auto Query = Run(Store.Query(MakeHistoryQuery(
            Record.Key, Timestamp, Timestamp + Record.ResolutionMilliseconds)));
        ASSERT_TRUE(Query);
        EXPECT_TRUE(Query->Available);
        EXPECT_EQ(Query->Coverage, "partial");
        EXPECT_EQ(Query->Failure, "history_capacity");
        EXPECT_TRUE(Query->Items.empty());
    }

    TEST_F(HistoryStoreStorage, PruneDeletesExpiredRowsAtEachStoredResolution)
    {
        Open();
        Application::Storage::HistoryStore Store(Owner);
        const auto Now = CurrentTimeMilliseconds();
        const auto TenSecond = MakeHistoryRecord("prune-ten-second",
            AlignDown(Now - 60'000U, 10'000U), 10'000U);
        const auto Minute = MakeHistoryRecord("prune-minute",
            AlignDown(Now - 2U * 24U * 60U * 60U * 1'000U, 60'000U), 60'000U);
        const auto QuarterHour = MakeHistoryRecord("prune-quarter-hour",
            AlignDown(Now - 8U * 24U * 60U * 60U * 1'000U, 900'000U), 900'000U);
        ASSERT_TRUE(Run(Store.Append({TenSecond, Minute, QuarterHour})));
        const auto BeforeTenSecond = QueryRecord(TenSecond);
        const auto BeforeMinute = QueryRecord(Minute);
        const auto BeforeQuarterHour = QueryRecord(QuarterHour);
        ASSERT_TRUE(BeforeTenSecond);
        ASSERT_TRUE(BeforeMinute);
        ASSERT_TRUE(BeforeQuarterHour);
        ASSERT_EQ(BeforeTenSecond->Items.size(), 1U);
        ASSERT_EQ(BeforeMinute->Items.size(), 1U);
        ASSERT_EQ(BeforeQuarterHour->Items.size(), 1U);

        const auto FutureNow = AlignUp(Now + Statistics::HistoryRetention + 900'000U, 900'000U);
        ASSERT_TRUE(Run(Store.Prune(FutureNow)));
        const auto AfterTenSecond = QueryRecord(TenSecond);
        const auto AfterMinute = QueryRecord(Minute);
        const auto AfterQuarterHour = QueryRecord(QuarterHour);
        ASSERT_TRUE(AfterTenSecond);
        ASSERT_TRUE(AfterMinute);
        ASSERT_TRUE(AfterQuarterHour);
        EXPECT_TRUE(AfterTenSecond->Items.empty());
        EXPECT_TRUE(AfterMinute->Items.empty());
        EXPECT_TRUE(AfterQuarterHour->Items.empty());
    }

    TEST_F(HistoryStoreStorage, PruneKeepsTheExactQuarterHourCutoff)
    {
        Open();
        Application::Storage::HistoryStore Store(Owner);
        const auto Now = CurrentTimeMilliseconds();
        constexpr std::uint64_t QuarterHour{900'000U};
        constexpr std::uint64_t OldAge{8U * 24U * 60U * 60U * 1'000U};
        const auto FutureNow = AlignUp(Now + Statistics::HistoryRetention - OldAge, QuarterHour);
        const auto Cutoff = FutureNow - Statistics::HistoryRetention;
        const auto Expired = MakeHistoryRecord("exact-prune-cutoff", Cutoff - QuarterHour, QuarterHour);
        const auto AtCutoff = MakeHistoryRecord("exact-prune-cutoff", Cutoff, QuarterHour);
        ASSERT_TRUE(Run(Store.Append({Expired, AtCutoff})));
        const auto BeforeExpired = QueryRecord(Expired);
        const auto BeforeCutoff = QueryRecord(AtCutoff);
        ASSERT_TRUE(BeforeExpired);
        ASSERT_TRUE(BeforeCutoff);
        ASSERT_EQ(BeforeExpired->Items.size(), 1U);
        ASSERT_EQ(BeforeCutoff->Items.size(), 1U);

        ASSERT_TRUE(Run(Store.Prune(FutureNow)));
        const auto AfterExpired = QueryRecord(Expired);
        ASSERT_TRUE(AfterExpired);
        EXPECT_TRUE(AfterExpired->Items.empty());
        const auto Retained = QueryRecord(AtCutoff);
        ASSERT_TRUE(Retained);
        ASSERT_EQ(Retained->Items.size(), 1U);
        EXPECT_EQ(Retained->Items.front().Timestamp, Cutoff);
    }
}
