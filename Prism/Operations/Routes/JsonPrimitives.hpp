/** @file JsonPrimitives.hpp @brief Operations JSON 值编码与数组分隔的共享无状态 owner。 */
#pragma once

#include <Prism/Operations/Http/JsonWriter.hpp>

#include <chrono>
#include <array>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <limits>
#include <optional>
#include <string_view>

namespace Prism::Operations::HttpDetail
{
    /** @brief 输出下一个数组项的分隔符；不持有 writer 之外的状态。 */
    [[nodiscard]] inline auto AppendComma(JsonWriter &Writer, bool &First) -> bool
    {
        if (!First && !Writer.Append(","))
        {
            return false;
        }
        First = false;
        return true;
    }

    /** @brief 将强类型 ID 按 JSON decimal-string 合同编码。 */
    template <typename Id>
    [[nodiscard]] inline auto AppendId(JsonWriter &Writer, const Id Value) -> bool
    {
        return Writer.Decimal(Value.Value());
    }

    /** @brief 以明确的 UTC 毫秒精度输出 ISO-8601 时间；非法范围输出 null。 */
    [[nodiscard]] inline auto AppendUtcTimestamp(JsonWriter &Writer, const std::uint64_t Milliseconds) -> bool
    {
        using namespace std::chrono;
        if (Milliseconds > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
        {
            return Writer.Null();
        }
        const system_clock::time_point Point{duration_cast<system_clock::duration>(
            duration<std::int64_t, std::milli>{static_cast<std::int64_t>(Milliseconds)})};
        const auto Day = floor<days>(Point);
        const year_month_day Date{Day};
        if (!Date.ok())
        {
            return Writer.Null();
        }
        const auto Time = Point - Day;
        const auto Hour = duration_cast<hours>(Time);
        const auto Minute = duration_cast<minutes>(Time - Hour);
        const auto Second = duration_cast<seconds>(Time - Hour - Minute);
        const auto Millisecond = duration_cast<milliseconds>(Time - Hour - Minute - Second);
        std::array<char, 32> Buffer{};
        const auto Count = std::snprintf(Buffer.data(), Buffer.size(), "%04d-%02u-%02uT%02lld:%02lld:%02lld.%03lldZ",
            static_cast<int>(Date.year()), static_cast<unsigned>(Date.month()),
            static_cast<unsigned>(Date.day()), static_cast<long long>(Hour.count()),
            static_cast<long long>(Minute.count()), static_cast<long long>(Second.count()),
            static_cast<long long>(Millisecond.count()));
        if (Count <= 0 || static_cast<std::size_t>(Count) >= Buffer.size())
        {
            return Writer.Null();
        }
        return Writer.String(std::string_view(Buffer.data(), static_cast<std::size_t>(Count)));
    }

    /** @brief 零值表示未记录时间，不伪造 epoch 时间。 */
    [[nodiscard]] inline auto AppendOptionalUtcTimestamp(JsonWriter &Writer,
                                                          const std::uint64_t Milliseconds) -> bool
    {
        return Milliseconds == 0U ? Writer.Null() : AppendUtcTimestamp(Writer, Milliseconds);
    }

    [[nodiscard]] inline auto AppendOptionalUtcTimestamp(
        JsonWriter &Writer, const std::optional<std::uint64_t> Milliseconds) -> bool
    {
        return Milliseconds ? AppendUtcTimestamp(Writer, *Milliseconds) : Writer.Null();
    }
}
