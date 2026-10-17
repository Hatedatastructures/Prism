/** @file UsageCalendar.hpp
 * @brief 固定 UTC 偏移的自然日、周、月与不重置周期边界。
 */
#pragma once
#include <Preview/Account/PolicyConfiguration.hpp>
#include <Preview/Account/UsageModels.hpp>
#include <chrono>
#include <expected>

namespace Preview::Account
{
    /** @brief 输入 Unix 毫秒；支持 1970 到 9999 年，周起点为本地周一。 */
    [[nodiscard]] inline auto ResolveUsageCycle(const CycleConfiguration& Policy,
        const std::int64_t UnixMilliseconds) -> std::expected<UsageCycle, Fault::Failure>
    {
        using std::chrono::sys_days; using std::chrono::year; using std::chrono::December;
        using std::chrono::days; using std::chrono::milliseconds; using std::chrono::duration_cast;
        using std::chrono::minutes; using std::chrono::sys_time; using std::chrono::floor;
        using std::chrono::weekday; using std::chrono::year_month_day; using std::chrono::months;
        constexpr auto Last = sys_days{year{9999}/December/31} + days{1};
        if (UnixMilliseconds < 0 || UnixMilliseconds >= duration_cast<milliseconds>(Last.time_since_epoch()).count() ||
            Policy.OffsetMinutes < -840 || Policy.OffsetMinutes > 840 || Policy.Kind > CycleKind::None)
            return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
        if (Policy.Kind == CycleKind::None) return UsageCycle{};
        const auto Offset = minutes{Policy.OffsetMinutes};
        const auto Local = sys_time<milliseconds>{milliseconds{UnixMilliseconds}} + Offset;
        auto Start = floor<days>(Local);
        auto End = Start + days{1};
        if (Policy.Kind == CycleKind::Week)
        {
            Start -= days{weekday{Start}.iso_encoding() - 1U};
            End = Start + days{7};
        }
        else if (Policy.Kind == CycleKind::Month)
        {
            const year_month_day Date{Start};
            Start = sys_days{Date.year()/Date.month()/1};
            End = sys_days{year_month_day{Start} + months{1}};
        }
        return UsageCycle{duration_cast<milliseconds>((Start - Offset).time_since_epoch()).count(),
            duration_cast<milliseconds>((End - Offset).time_since_epoch()).count()};
    }

    /**
     * @brief 纯领域调度；存储实现必须把结果与周期 End 修订放进同一事务。
     * @details None 改自然周期时，以修改时的新下一自然边界截断旧周期，之前消耗不清零。
     */
    [[nodiscard]] inline auto AdvanceUsageSchedule(const std::optional<UsageSchedule>& Previous,
        const UsageCycleRequest& Request) -> std::expected<UsageSchedule, Fault::Failure>
    {
        const auto Desired = ResolveUsageCycle(Request.Desired, Request.Now);
        if (!Desired) return std::unexpected(Desired.error());
        if (!Previous) return UsageSchedule{*Desired, Request.Desired, Request.Desired};
        auto Result = *Previous;
        Result.Pending = Request.Desired;
        if (!Result.Current.End && Result.Active.Kind == CycleKind::None && Request.Desired.Kind != CycleKind::None)
        {
            Result.Current.End = Desired->End;
            return Result;
        }
        if (!Result.Current.End || Request.Now < *Result.Current.End) return Result;
        const auto Boundary = *Result.Current.End;
        const auto Next = ResolveUsageCycle(Request.Desired, Request.Now);
        if (!Next) return std::unexpected(Next.error());
        Result.Current = *Next;
        if (Result.Current.Start < Boundary) Result.Current.Start = Boundary;
        Result.Active = Request.Desired;
        return Result;
    }
}
