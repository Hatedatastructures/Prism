/** @file HistorySeries.hpp @brief 历史窗口合并、保留分辨率与缺测区间计算。 */
#pragma once

#include <Prism/Statistics/Analysis/HistoryModels.hpp>

#include <cstdint>
#include <vector>

namespace Prism::Statistics
{
    [[nodiscard]] auto ValidHistoryQuery(const HistoryQuery &Query) noexcept -> bool;
    /** @brief 选取满足存储保留层级和点数预算的整数倍分辨率。 */
    [[nodiscard]] auto HistoryResolution(const HistoryQuery &Query, std::uint64_t Now) noexcept
        -> std::uint64_t;
    /** @brief 序列隔离进程重启和 Generation；合并失败形成质量标记，不输出错误分位值。 */
    [[nodiscard]] auto MergeHistoryRecord(HistoryRecord &Target, const HistoryRecord &Value) noexcept -> bool;
    [[nodiscard]] auto AggregateHistory(std::vector<HistoryRecord> Records, std::uint64_t Resolution)
        -> std::vector<HistoryRecord>;
    /** @brief 仅根据实际窗口覆盖计算缺测；不补零、不把重启两端连成连续曲线。 */
    auto FindHistoryGaps(HistoryResult &Result) -> void;
}
