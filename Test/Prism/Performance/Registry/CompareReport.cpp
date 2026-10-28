/**
 * @file CompareReport.cpp
 * @brief 注册表候选采样结果报告实现。
 */

#include "CompareSampling.hpp"

#include <cstdint>
#include <cstdio>

namespace Prism::Runtime::Perf
{

    auto ModelName(const ModelKind Kind) -> const char *
    {
        switch (Kind)
        {
        case ModelKind::CurrentCow:
            return "A-current-cow";
        case ModelKind::ShardedCow:
            return "B-sharded-cow";
        case ModelKind::ExecutorTable:
            return "C-executor-table";
        case ModelKind::All:
            return "all";
        }
        return "unknown";
    }

    auto WorkloadName(const WorkloadKind Workload) -> const char *
    {
        return Workload == WorkloadKind::ReadHeavy ? "read-heavy" : "churn";
    }

    auto InvalidReasonName(const InvalidReason Reason) -> const char *
    {
        switch (Reason)
        {
        case InvalidReason::RegisterResult:
            return "RegisterResult";
        case InvalidReason::FindResult:
            return "FindResult";
        case InvalidReason::SizeExceeded:
            return "SizeExceeded";
        case InvalidReason::SnapshotValue:
            return "SnapshotValue";
        case InvalidReason::CancelResult:
            return "CancelResult";
        case InvalidReason::ResetResult:
            return "ResetResult";
        case InvalidReason::SnapshotIsolation:
            return "SnapshotIsolation";
        case InvalidReason::RetireResult:
            return "RetireResult";
        case InvalidReason::HookShape:
            return "HookShape";
        case InvalidReason::HookInstallFailure:
            return "HookInstallFailure";
        case InvalidReason::StaleHook:
            return "StaleHook";
        case InvalidReason::InFlightHook:
            return "InFlightHook";
        case InvalidReason::PendingResult:
            return "PendingResult";
        case InvalidReason::FinalSnapshot:
            return "FinalSnapshot";
        case InvalidReason::FinalSize:
            return "FinalSize";
        case InvalidReason::FinalPending:
            return "FinalPending";
        case InvalidReason::FinalLifecycle:
            return "FinalLifecycle";
        case InvalidReason::TokenState:
            return "TokenState";
        case InvalidReason::Count:
            break;
        }
        return "Unknown";
    }

    auto FirstInvalidReason(const Sample &Result) -> std::size_t
    {
        for (std::size_t Index = 0; Index < InvalidReasonCount; ++Index)
        {
            if (Result.InvalidReasons[Index] != 0)
            {
                return Index;
            }
        }
        return InvalidReasonCount;
    }

    auto PrintProcessMetrics(const Sample &Result) -> void
    {
        if (Result.ProcessBefore && Result.ProcessAfter &&
            Result.ProcessBefore->UserTime100ns.has_value() &&
            Result.ProcessAfter->UserTime100ns.has_value() &&
            Result.ProcessBefore->KernelTime100ns.has_value() &&
            Result.ProcessAfter->KernelTime100ns.has_value() &&
            Result.ProcessBefore->WorkingSetBytes.has_value() &&
            Result.ProcessAfter->WorkingSetBytes.has_value() &&
            Result.ProcessBefore->CommitBytes.has_value() &&
            Result.ProcessAfter->CommitBytes.has_value())
        {
            std::printf(
                "cpu_user_100ns_before=%llu cpu_user_100ns_after=%llu cpu_user_100ns_delta=%lld cpu_kernel_100ns_before=%llu cpu_kernel_100ns_after=%llu cpu_kernel_100ns_delta=%lld commit_before_bytes=%llu commit_after_bytes=%llu commit_delta_bytes=%lld\n",
                static_cast<unsigned long long>(*Result.ProcessBefore->UserTime100ns),
                static_cast<unsigned long long>(*Result.ProcessAfter->UserTime100ns),
                static_cast<long long>(*Result.ProcessAfter->UserTime100ns) -
                    static_cast<long long>(*Result.ProcessBefore->UserTime100ns),
                static_cast<unsigned long long>(*Result.ProcessBefore->KernelTime100ns),
                static_cast<unsigned long long>(*Result.ProcessAfter->KernelTime100ns),
                static_cast<long long>(*Result.ProcessAfter->KernelTime100ns) -
                    static_cast<long long>(*Result.ProcessBefore->KernelTime100ns),
                static_cast<unsigned long long>(*Result.ProcessBefore->CommitBytes),
                static_cast<unsigned long long>(*Result.ProcessAfter->CommitBytes),
                static_cast<long long>(*Result.ProcessAfter->CommitBytes) -
                    static_cast<long long>(*Result.ProcessBefore->CommitBytes));
            if (Result.PeakWorkingSetBytes && Result.PeakCommitBytes && Result.ProcessMetricSamples)
            {
                std::printf("peak_working_set_bytes=%llu peak_commit_bytes=%llu process_metric_samples=%llu sample_interval_ms=1\n",
                            static_cast<unsigned long long>(*Result.PeakWorkingSetBytes),
                            static_cast<unsigned long long>(*Result.PeakCommitBytes),
                            static_cast<unsigned long long>(*Result.ProcessMetricSamples));
            }
            else
            {
                std::puts("peak_process_metrics=null");
            }
        }
        else
        {
            std::puts("process_metrics=unavailable");
        }
    }

    auto PrintSample(const Sample &Result, const Options &Settings) -> void
    {
        const auto OpsPerSecond = Result.DurationSeconds == 0
                                      ? 0.0
                                      : static_cast<double>(Result.Operations) /
                                            Result.DurationSeconds;
        const auto ReasonIndex = FirstInvalidReason(Result);
        const auto ReasonName = ReasonIndex == InvalidReasonCount
                                    ? "none"
                                    : InvalidReasonName(static_cast<InvalidReason>(ReasonIndex));
        const auto ReasonCount = ReasonIndex == InvalidReasonCount
                                     ? std::uint64_t{0}
                                     : Result.InvalidReasons[ReasonIndex];
        std::printf(
            "variant=%s workload=%s round=%zu active=%zu executors=%zu operations=%zu trace_hash=%016llx ops_per_s=%.2f p50_ns=%llu p95_ns=%llu p99_ns=%llu allocations=%llu allocation_bytes=%llu aligned_allocations=%llu aligned_allocation_bytes=%llu correctness_hash=%016llx observation_hash=%016llx final_size=%llu pending_removals=%llu invalid=%s invalid_reason=%s invalid_reason_count=%llu\n",
            ModelName(Result.Model), WorkloadName(Settings.Workload), Result.Round,
            Settings.ActiveSessions, Settings.Executors, Result.Operations,
            static_cast<unsigned long long>(Result.TraceHash), OpsPerSecond,
            static_cast<unsigned long long>(Result.P50),
            static_cast<unsigned long long>(Result.P95),
            static_cast<unsigned long long>(Result.P99),
            static_cast<unsigned long long>(Result.Allocations),
            static_cast<unsigned long long>(Result.AllocationBytesValue),
            static_cast<unsigned long long>(Result.AlignedAllocations),
            static_cast<unsigned long long>(Result.AlignedAllocationBytesValue),
            static_cast<unsigned long long>(Result.CorrectnessHash),
            static_cast<unsigned long long>(Result.ObservationHash),
            static_cast<unsigned long long>(Result.FinalSize),
            static_cast<unsigned long long>(Result.Pending), Result.Invalid ? "true" : "false",
            ReasonName, static_cast<unsigned long long>(ReasonCount));
        if (Result.RssBefore && Result.RssAfter)
        {
            const auto Delta = static_cast<std::int64_t>(*Result.RssAfter) -
                               static_cast<std::int64_t>(*Result.RssBefore);
            std::printf("rss_before_bytes=%llu rss_after_bytes=%llu rss_delta_bytes=%lld\n",
                        static_cast<unsigned long long>(*Result.RssBefore),
                        static_cast<unsigned long long>(*Result.RssAfter),
                        static_cast<long long>(Delta));
        }
        else
        {
            std::puts("rss=unavailable");
        }
        if (Result.Operations != 0)
        {
            std::printf("latency_samples=%zu latency_sample_rate_percent=100.00\n",
                        Result.Operations);
        }
        else
        {
            std::puts("latency_samples=0 latency_sample_rate_percent=null");
        }
        std::puts("allocation_boundary=ordinary and aligned process-wide operator new/new[] calls in the timed window, reported by kind and requested bytes; setup, trace storage, allocator retention, and other malloc/native DLL callers are excluded");
        std::puts("process_metric_boundary=1ms sampler thread is created before TrackAllocations and samples only after timed Start; sampler CPU/RSS effects remain part of process metrics");
        PrintProcessMetrics(Result);
    }

} // namespace Prism::Runtime::Perf
