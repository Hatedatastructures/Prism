/**
 * @file HistoryModels.cpp
 * @brief 延迟直方图的有界记录、合并与分位数计算。
 */
#include <Prism/Statistics/Analysis/HistoryModels.hpp>

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>

namespace Prism::Statistics
{
    auto LatencyHistogram::Record(std::uint64_t Value) noexcept -> void
    {
        Maximum = (std::max)(Maximum, Value);
        if (Value > MaximumMicroseconds) ++RangeExceeded;
        const auto Index = static_cast<std::size_t>(std::bit_width(Value));
        if (Buckets[Index] != (std::numeric_limits<std::uint64_t>::max)()) ++Buckets[Index];
    }

    auto LatencyHistogram::Count() const noexcept -> std::uint64_t
    {
        std::uint64_t Result = 0;
        for (const auto Value : Buckets)
        {
            if (Value > (std::numeric_limits<std::uint64_t>::max)() - Result)
                return (std::numeric_limits<std::uint64_t>::max)();
            Result += Value;
        }
        return Result;
    }

    auto LatencyHistogram::Merge(const LatencyHistogram &Other) noexcept -> bool
    {
        constexpr auto Limit = (std::numeric_limits<std::uint64_t>::max)();
        if (Other.Count() > Limit - Count() || Other.RangeExceeded > Limit - RangeExceeded) return false;
        for (std::size_t Index = 0; Index < Buckets.size(); ++Index)
            if (Other.Buckets[Index] > Limit - Buckets[Index]) return false;
        for (std::size_t Index = 0; Index < Buckets.size(); ++Index) Buckets[Index] += Other.Buckets[Index];
        Maximum = (std::max)(Maximum, Other.Maximum);
        RangeExceeded += Other.RangeExceeded;
        return true;
    }

    auto LatencyHistogram::Percentile(unsigned Percent) const noexcept
        -> std::optional<std::uint64_t>
    {
        const auto Total = Count();
        if (Total == 0 || Percent == 0 || Percent > 100) return std::nullopt;
        if (Percent == 100) return Maximum;
        const auto Rank = (Total / 100U) * Percent + ((Total % 100U) * Percent + 99U) / 100U;
        std::uint64_t Seen = 0;
        for (std::size_t Index = 0; Index < Buckets.size(); ++Index)
        {
            Seen += Buckets[Index];
            if (Seen >= Rank) return Index == 0 ? 0U : std::uint64_t{1} << (Index - 1U);
        }
        return std::nullopt;
    }
}
