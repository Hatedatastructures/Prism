/**
 * @file SessionRegistryCompareSampling.hpp
 * @brief 注册表候选的并发采样与资源观测。
 */

#pragma once

#include "SessionRegistryCompareCorrectness.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace Preview::Runtime::Perf
{

    struct ProcessMetrics final
    {
        std::optional<std::uint64_t> UserTime100ns;
        std::optional<std::uint64_t> KernelTime100ns;
        std::optional<std::uint64_t> WorkingSetBytes;
        std::optional<std::uint64_t> CommitBytes;
    };

    struct Sample final
    {
        ModelKind Model{ModelKind::CurrentCow};
        std::size_t Round{0};
        std::size_t Operations{0};
        std::uint64_t TraceHash{0};
        std::uint64_t CorrectnessHash{0};
        std::uint64_t ObservationHash{0};
        std::uint64_t FinalSize{0};
        std::uint64_t Pending{0};
        std::uint64_t Allocations{0};
        std::uint64_t AllocationBytesValue{0};
        std::uint64_t AlignedAllocations{0};
        std::uint64_t AlignedAllocationBytesValue{0};
        std::uint64_t P50{0};
        std::uint64_t P95{0};
        std::uint64_t P99{0};
        double DurationSeconds{0};
        bool Invalid{false};
        std::optional<std::uint64_t> RssBefore;
        std::optional<std::uint64_t> RssAfter;
        std::optional<ProcessMetrics> ProcessBefore;
        std::optional<ProcessMetrics> ProcessAfter;
        std::optional<std::uint64_t> PeakWorkingSetBytes;
        std::optional<std::uint64_t> PeakCommitBytes;
        std::optional<std::uint64_t> ProcessMetricSamples;
        std::array<std::uint64_t, InvalidReasonCount> InvalidReasons{};
    };

    struct SampleRequest final
    {
        const Options &Settings;
        const Trace &TraceValue;
        ModelKind Kind{ModelKind::CurrentCow};
        std::size_t Round{0};
    };

} // namespace Preview::Runtime::Perf
