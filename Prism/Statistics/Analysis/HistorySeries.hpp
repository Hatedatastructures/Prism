/** @file HistorySeries.hpp @brief 历史窗口合并、保留分辨率与缺测区间计算。 */
#pragma once
#include <Prism/Statistics/Analysis/HistoryModels.hpp>
#include <algorithm>
#include <limits>
#include <map>
#include <tuple>
#include <utility>

namespace Prism::Statistics
{
    [[nodiscard]] inline auto ValidHistoryQuery(const HistoryQuery &Query) noexcept -> bool
    { return Query.From < Query.To && Query.MaxPoints > 0 && Query.MaxPoints <= 1'200U; }

    /** @brief 选取满足存储保留层级和点数预算的整数倍分辨率。 */
    [[nodiscard]] inline auto HistoryResolution(const HistoryQuery &Query, std::uint64_t Now) noexcept
        -> std::uint64_t
    {
        if (!ValidHistoryQuery(Query)) return 0;
        const auto Age = Now > Query.From ? Now - Query.From : 0U;
        const auto Base = Age <= HistoryMemoryRetention ? 1'000U :
            Age <= HistoryTenSecondRetention ? 10'000U :
            Age <= HistoryMinuteRetention ? 60'000U : 900'000U;
        const auto Width = Query.To - Query.From;
        const auto Needed = Width / Query.MaxPoints + (Width % Query.MaxPoints != 0U);
        const auto Multiple = Needed / Base + (Needed % Base != 0U);
        return Base * (std::max)(Multiple, std::uint64_t{1});
    }

    /** @brief 序列隔离进程重启和 Generation；合并失败形成质量标记，不输出错误分位值。 */
    [[nodiscard]] inline auto MergeHistoryRecord(HistoryRecord &Target, const HistoryRecord &Value) noexcept -> bool
    {
        constexpr auto Limit = (std::numeric_limits<std::uint64_t>::max)();
        if (Value.UpBytes > Limit - Target.UpBytes || Value.DownBytes > Limit - Target.DownBytes ||
            Value.Events > Limit - Target.Events || Value.Errors > Limit - Target.Errors ||
            Value.Quality.Dropped > Limit - Target.Quality.Dropped ||
            Value.Quality.AggregationFailures > Limit - Target.Quality.AggregationFailures ||
            !Target.Latency.Merge(Value.Latency))
        { Target.Quality.Incomplete = true; return false; }
        Target.UpBytes += Value.UpBytes;
        Target.DownBytes += Value.DownBytes;
        Target.Events += Value.Events;
        Target.Errors += Value.Errors;
        Target.Active = Value.Active;
        Target.Quality.Dropped += Value.Quality.Dropped;
        Target.Quality.AggregationFailures += Value.Quality.AggregationFailures;
        Target.Quality.Incomplete = Target.Quality.Incomplete || Value.Quality.Incomplete;
        return true;
    }

    [[nodiscard]] inline auto AggregateHistory(std::vector<HistoryRecord> Records, std::uint64_t Resolution)
        -> std::vector<HistoryRecord>
    {
        if (Resolution == 0) return {};
        using Key = std::tuple<std::uint64_t, HistoryScope, std::string, std::string, std::string,
            std::uint64_t, HistoryMetric>;
        std::map<Key, HistoryRecord> Values;
        std::stable_sort(Records.begin(), Records.end(), [](const auto &Left, const auto &Right)
            { return Left.Timestamp < Right.Timestamp; });
        for (auto &Record : Records)
        {
            Record.Timestamp -= Record.Timestamp % Resolution;
            Record.ResolutionMilliseconds = Resolution;
            Key Identity{Record.Timestamp, Record.Scope, Record.Key, Record.InstanceKey,
                Record.Incarnation, Record.Generation, Record.Metric};
            const auto [It, Inserted] = Values.try_emplace(std::move(Identity), Record);
            if (!Inserted) (void)MergeHistoryRecord(It->second, Record);
        }
        std::vector<HistoryRecord> Result;
        Result.reserve(Values.size());
        for (auto &[Identity, Record] : Values) { (void)Identity; Result.push_back(std::move(Record)); }
        return Result;
    }

    /** @brief 仅根据实际窗口覆盖计算缺测；不补零、不把重启两端连成连续曲线。 */
    inline auto FindHistoryGaps(HistoryResult &Result) -> void
    {
        auto Cursor = Result.From;
        std::string Incarnation;
        for (const auto &Value : Result.Items)
        {
            if (Value.Timestamp > Cursor) Result.Gaps.push_back({Cursor, Value.Timestamp, "not_sampled"});
            if (!Incarnation.empty() && Incarnation != Value.Incarnation)
                Result.Gaps.push_back({Value.Timestamp, Value.Timestamp, "process_restart"});
            Incarnation = Value.Incarnation;
            const auto End = Value.Timestamp > (std::numeric_limits<std::uint64_t>::max)() -
                Value.ResolutionMilliseconds ? (std::numeric_limits<std::uint64_t>::max)() :
                Value.Timestamp + Value.ResolutionMilliseconds;
            Cursor = (std::max)(Cursor, End);
            if (Value.Quality.Incomplete) Result.Gaps.push_back(
                {Value.Timestamp, End, "observation_incomplete"});
        }
        if (Cursor < Result.To) Result.Gaps.push_back({Cursor, Result.To, "not_sampled"});
    }
}
