/** @file UsageCalendar.hpp
 * @brief 固定 UTC 偏移的自然日、周、月与不重置周期边界。
 */
#pragma once
#include <Prism/Account/PolicyConfiguration.hpp>
#include <Prism/Account/UsageModels.hpp>

#include <cstdint>
#include <expected>
#include <optional>

namespace Prism::Account
{
    /** @brief 输入 Unix 毫秒；支持 1970 到 9999 年，周起点为本地周一。 */
    [[nodiscard]] auto ResolveUsageCycle(const CycleConfiguration& Policy,
        const std::int64_t UnixMilliseconds) -> std::expected<UsageCycle, Fault::Failure>;

    /**
     * @brief 纯领域调度；存储实现必须把结果与周期 End 修订放进同一事务。
     * @details None 改自然周期时，以修改时的新下一自然边界截断旧周期，之前消耗不清零。
     */
    [[nodiscard]] auto AdvanceUsageSchedule(const std::optional<UsageSchedule>& Previous,
        const UsageCycleRequest& Request) -> std::expected<UsageSchedule, Fault::Failure>;
}
