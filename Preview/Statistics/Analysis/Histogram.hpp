/** @file Histogram.hpp @brief 历史窗口拥有的可合并整数延迟直方图。 */
#pragma once
#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <limits>
#include <optional>

namespace Preview::Statistics
{
    /** @brief 控制 executor 串行拥有；桶下界是近似值，最大值保留真实样本。 */
    struct LatencyHistogram final
    {
        static constexpr std::uint64_t MaximumMicroseconds{300'000'000U};
        std::array<std::uint64_t, 65> Buckets{};
        std::uint64_t Maximum{0};
        std::uint64_t RangeExceeded{0};

        /** @brief 有界数值记录；不分配、不访问时钟，超量样本保留范围质量。 */
        auto Record(std::uint64_t Value) noexcept -> void
        {
            Maximum = (std::max)(Maximum, Value);
            if (Value > MaximumMicroseconds) ++RangeExceeded;
            const auto Index = static_cast<std::size_t>(std::bit_width(Value));
            if (Buckets[Index] != (std::numeric_limits<std::uint64_t>::max)()) ++Buckets[Index];
        }

        [[nodiscard]] auto Count() const noexcept -> std::uint64_t
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

        /** @brief 合并桶而非合并分位数；溢出时不修改目标并返回失败。 */
        [[nodiscard]] auto Merge(const LatencyHistogram &Other) noexcept -> bool
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

        /** @brief nearest-rank 桶下界；空窗口返回 null，P100 返回真实最大值。 */
        [[nodiscard]] auto Percentile(unsigned Percent) const noexcept -> std::optional<std::uint64_t>
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
    };
}
