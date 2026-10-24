/** @file TrafficJson.cpp @brief 流量响应 JSON 私有编码辅助实现。 */
#include <Prism/Operations/Routes/TrafficJson.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <limits>
#include <string_view>

namespace Prism::Operations::HttpDetail
{
    auto AppendComma(JsonWriter& Writer, bool& First) -> bool
    {
        if (!First && !Writer.Append(",")) return false;
        First = false;
        return true;
    }

    auto AppendUtcTimestamp(JsonWriter& Writer, const std::uint64_t Milliseconds) -> bool
    {
        if (Milliseconds > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
            return Writer.Null();
        using MillisecondDuration = std::chrono::duration<std::int64_t, std::milli>;
        const std::chrono::system_clock::time_point Point{
            std::chrono::duration_cast<std::chrono::system_clock::duration>(
                MillisecondDuration{static_cast<std::int64_t>(Milliseconds)})};
        const auto Day = std::chrono::floor<std::chrono::days>(Point);
        const std::chrono::year_month_day Date{Day};
        if (!Date.ok()) return Writer.Null();
        const auto Time = Point - Day;
        const auto Hour = std::chrono::duration_cast<std::chrono::hours>(Time);
        const auto Minute = std::chrono::duration_cast<std::chrono::minutes>(Time - Hour);
        const auto Second = std::chrono::duration_cast<std::chrono::seconds>(Time - Hour - Minute);
        const auto Millisecond = std::chrono::duration_cast<std::chrono::milliseconds>(
            Time - Hour - Minute - Second);
        std::array<char, 32> Buffer{};
        const auto Count = std::snprintf(Buffer.data(), Buffer.size(),
            "%04d-%02u-%02uT%02lld:%02lld:%02lld.%03lldZ",
            static_cast<int>(Date.year()), static_cast<unsigned>(Date.month()),
            static_cast<unsigned>(Date.day()), static_cast<long long>(Hour.count()),
            static_cast<long long>(Minute.count()), static_cast<long long>(Second.count()),
            static_cast<long long>(Millisecond.count()));
        if (Count <= 0 || static_cast<std::size_t>(Count) >= Buffer.size()) return Writer.Null();
        return Writer.String(std::string_view(Buffer.data(), static_cast<std::size_t>(Count)));
    }

    auto AppendOptionalUtcTimestamp(JsonWriter& Writer, const std::uint64_t Milliseconds) -> bool
    {
        return Milliseconds == 0U ? Writer.Null() : AppendUtcTimestamp(Writer, Milliseconds);
    }

    auto AppendOptionalUtcTimestamp(
        JsonWriter& Writer, const std::optional<std::uint64_t> Milliseconds) -> bool
    {
        return Milliseconds ? AppendUtcTimestamp(Writer, *Milliseconds) : Writer.Null();
    }

    auto AppendTraffic(JsonWriter& Writer, const Prism::Statistics::TrafficValue& Value) -> bool
    {
        return Writer.Append("{") && Writer.Key("up_bytes") && Writer.Decimal(Value.UpBytes) &&
               Writer.Append(",") && Writer.Key("down_bytes") && Writer.Decimal(Value.DownBytes) &&
               Writer.Append(",") && Writer.Key("events") && Writer.Decimal(Value.Events) &&
               Writer.Append(",") && Writer.Key("errors") && Writer.Decimal(Value.Errors) &&
               Writer.Append("}");
    }
}
