/** @file UsageCalendar.cpp
 * @brief 账户用量自然周期与调度边界实现。
 */
#include <Prism/Account/UsageCalendar.hpp>

#include <chrono>
#include <cstdint>
#include <expected>
#include <optional>

namespace Prism::Account
{
    auto ResolveUsageCycle(const CycleConfiguration& Policy,
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

    auto AdvanceUsageSchedule(const std::optional<UsageSchedule>& Previous,
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
