/**
 * @file TaskIdSetMeasurement.hpp
 * @brief TaskIdSet 性能实验的窗口结果契约。
 */

#pragma once

#include <cstdint>
#include <functional>
#include <optional>

namespace Prism::Lifecycle::Perf
{

    struct ProcessMetrics final
    {
        std::uint64_t User100ns{0};
        std::uint64_t Kernel100ns{0};
        std::uint64_t WorkingSetBytes{0};
        std::uint64_t CommitBytes{0};
        bool Available{false};
    };

    struct MeasurementResult final
    {
        std::uint64_t Allocations{0};
        std::uint64_t AllocationBytes{0};
        std::uint64_t AlignedAllocations{0};
        std::uint64_t AlignedAllocationBytes{0};
        std::uint64_t ProcessSamples{0};
        std::uint64_t PeakWorkingSet{0};
        std::uint64_t PeakCommit{0};
        bool PeakAvailable{false};
        std::optional<ProcessMetrics> ProcessBefore;
        std::optional<ProcessMetrics> ProcessAfter;
        std::int64_t BeginNs{0};
        std::int64_t EndNs{0};
    };

    /** @brief 在 callback 生命周期内采集 allocation、CPU、RSS、commit 和窗口边界。 */
    [[nodiscard]] auto Measure(const std::function<void()> &Work) -> MeasurementResult;

} // namespace Prism::Lifecycle::Perf
