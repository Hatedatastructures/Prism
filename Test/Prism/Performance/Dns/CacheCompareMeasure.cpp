/**
 * @file CacheCompareMeasure.cpp
 * @brief DNS cache 对照实验的 trace replay、计时与报告 owner。
 */

#include "CacheScenario.hpp"
#include "CacheVariants.hpp"
#include "CacheMeasure.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <latch>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>


namespace Prism::Network::Dns::Compare
{
    auto AddressForVersion(const Scenario &Workload, std::uint32_t Version) -> boost::asio::ip::address;
}
namespace Prism::Network::Dns::Compare::Perf
{
    auto CurrentRssBytes() -> std::optional<std::uint64_t>;
    auto CurrentProcessMetrics() -> std::optional<ProcessMetrics>;
    auto RunProcessMetricSampler(ProcessSamplerState State) -> void;
}
namespace
{
    namespace Compare = Prism::Network::Dns::Compare;
    namespace Dns = Prism::Network::Dns;

    using Compare::Perf::ProcessMetrics;
    using Compare::Perf::ProcessSamplerState;
    using Compare::Perf::CurrentRssBytes;
    using Compare::Perf::CurrentProcessMetrics;
    using Compare::Perf::RunProcessMetricSampler;
    using Clock = std::chrono::steady_clock;
    using Compare::ClockCache;
    using Compare::CurrentCache;
    using Compare::IntrusiveCache;
    using Compare::Options;
    using Compare::Scenario;
    using Compare::Variant;
    using Compare::WorkloadKind;

    using Prism::Network::Dns::Compare::Perf::TrackAllocations;
    using Prism::Network::Dns::Compare::Perf::AllocationCount;
    using Prism::Network::Dns::Compare::Perf::AllocationBytes;
    using Prism::Network::Dns::Compare::Perf::AlignedAllocationCount;
    using Prism::Network::Dns::Compare::Perf::AlignedAllocationBytes;
    auto VariantName(const Variant Value) -> const char *
    {
        switch (Value)
        {
        case Variant::Current:
            return "A";
        case Variant::Intrusive:
            return "B";
        case Variant::Clock:
            return "C";
        }
        return "?";
    }

    auto DistributionName(const Compare::Distribution Value) -> const char *
    {
        return Value == Compare::Distribution::Uniform ? "uniform" : "hotspot";
    }

    auto MakeTimedCacheOptions(const std::size_t Capacity) -> Dns::CacheOptions
    {
        Dns::CacheOptions Result;
        Result.MaxEntries = Capacity;
        Result.TtlMin = std::chrono::seconds{0};
        Result.TtlMax = std::chrono::seconds{86400};
        Result.NegativeTtl = std::chrono::seconds{86400};
        Result.Policy = Dns::StalePolicy::Discard;
        return Result;
    }

    template <typename CacheType>
    auto MakeCache(const Dns::CacheOptions &Settings) -> std::unique_ptr<CacheType>
    {
        return std::make_unique<CacheType>(Settings);
    }

    template <typename CacheType>
    void FillCache(CacheType &Cache, const Scenario &Workload)
    {
        for (std::size_t Index = 0; Index < Workload.Settings.Capacity; ++Index)
        {
            const auto &Key = Workload.Keys[Index];
            if (Key.Negative)
            {
                Cache.PutNegative(Key.Domain, 1);
            }
            else
            {
                Dns::PutInput Input;
                Input.Domain = Key.Domain;
                Input.QType = 1;
                Input.Ips.push_back(Workload.ExpectedAddress);
                Input.Ttl = std::chrono::seconds{86400};
                Cache.Put(Input);
            }
        }
    }

    struct WorkerResult
    {
        std::uint64_t Hits{0};
        std::uint64_t Misses{0};
        std::uint64_t Gets{0};
        std::uint64_t Inserts{0};
        std::uint64_t Overwrites{0};
        std::uint64_t Expirations{0};
        std::uint64_t ExplicitEvictions{0};
        std::uint64_t CapacityPressureEvents{0};
        std::uint64_t ExpiredEvictions{0};
        std::uint64_t ValueMismatches{0};
        std::uint64_t Checksum{14695981039346656037ull};
    };

    struct MeasurementSummary
    {
        double DurationSeconds{0};
        std::uint64_t MeasuredOperations{0};
        std::vector<std::uint64_t> Latencies;
        std::vector<WorkerResult> Workers;
        std::uint64_t Allocations{0};
        std::uint64_t AllocatedBytes{0};
        std::uint64_t AlignedAllocations{0};
        std::uint64_t AlignedAllocatedBytes{0};
        std::optional<std::uint64_t> RssBefore;
        std::optional<std::uint64_t> RssAfter;
        std::optional<ProcessMetrics> ProcessBefore;
        std::optional<ProcessMetrics> ProcessAfter;
        std::optional<std::uint64_t> PeakWorkingSetBytes;
        std::optional<std::uint64_t> PeakCommitBytes;
        std::optional<std::uint64_t> ProcessMetricSamples;
    };

    struct SummaryTotals
    {
        std::uint64_t Hits{0};
        std::uint64_t Misses{0};
        std::uint64_t Gets{0};
        std::uint64_t Inserts{0};
        std::uint64_t Overwrites{0};
        std::uint64_t Expirations{0};
        std::uint64_t ExplicitEvictions{0};
        std::uint64_t CapacityPressureEvents{0};
        std::uint64_t ExpiredEvictions{0};
        std::uint64_t ValueMismatches{0};
        std::uint64_t Checksum{14695981039346656037ull};
    };

    struct LatencySummary
    {
        std::uint64_t P50{0};
        std::uint64_t P95{0};
        std::uint64_t P99{0};
        double OpsPerSecond{0};
    };

    auto Percentile(const std::vector<std::uint64_t> &SortedSamples,
                    const std::uint64_t Numerator,
                    const std::uint64_t Denominator) -> std::uint64_t
    {
        const auto Rank = (SortedSamples.size() * Numerator + Denominator - 1) / Denominator;
        return SortedSamples[std::max(std::size_t{1}, Rank) - 1];
    }

    void MixChecksum(WorkerResult &Result, const std::uint64_t Value)
    {
        Result.Checksum ^= Value;
        Result.Checksum *= 1099511628211ull;
    }

    auto WorkloadName(const WorkloadKind Value) -> const char *
    {
        return Value == WorkloadKind::GetOnly ? "get-only" : "mixed";
    }

    auto EvictionPolicyName(const Variant Value) -> const char *
    {
        return Value == Variant::Clock ? "CLOCK-second-chance" : "exact-LRU";
    }

    void PrintRss(const MeasurementSummary &Summary)
    {
        if (Summary.RssBefore.has_value() && Summary.RssAfter.has_value())
        {
            const auto Before = *Summary.RssBefore;
            const auto After = *Summary.RssAfter;
            const auto Delta = static_cast<std::int64_t>(After) - static_cast<std::int64_t>(Before);
            std::printf("rss_before_bytes=%llu rss_after_bytes=%llu rss_delta_bytes=%lld\n",
                        static_cast<unsigned long long>(Before),
                        static_cast<unsigned long long>(After), static_cast<long long>(Delta));
            return;
        }
        std::puts("rss=unavailable");
    }

    void PrintProcessMetrics(const MeasurementSummary &Summary)
    {
        if (Summary.ProcessBefore && Summary.ProcessAfter)
        {
            const auto &Before = *Summary.ProcessBefore;
            const auto &After = *Summary.ProcessAfter;
            std::printf(
                "cpu_user_100ns_before=%llu cpu_user_100ns_after=%llu cpu_user_100ns_delta=%lld cpu_kernel_100ns_before=%llu cpu_kernel_100ns_after=%llu cpu_kernel_100ns_delta=%lld commit_before_bytes=%llu commit_after_bytes=%llu commit_delta_bytes=%lld\n",
                static_cast<unsigned long long>(Before.UserTime100ns),
                static_cast<unsigned long long>(After.UserTime100ns),
                static_cast<long long>(After.UserTime100ns) -
                    static_cast<long long>(Before.UserTime100ns),
                static_cast<unsigned long long>(Before.KernelTime100ns),
                static_cast<unsigned long long>(After.KernelTime100ns),
                static_cast<long long>(After.KernelTime100ns) -
                    static_cast<long long>(Before.KernelTime100ns),
                static_cast<unsigned long long>(Before.CommitBytes),
                static_cast<unsigned long long>(After.CommitBytes),
                static_cast<long long>(After.CommitBytes) -
                    static_cast<long long>(Before.CommitBytes));
            if (Summary.PeakWorkingSetBytes && Summary.PeakCommitBytes &&
                Summary.ProcessMetricSamples)
            {
                std::printf("peak_working_set_bytes=%llu peak_commit_bytes=%llu process_metric_samples=%llu sample_interval_ms=1\n",
                            static_cast<unsigned long long>(*Summary.PeakWorkingSetBytes),
                            static_cast<unsigned long long>(*Summary.PeakCommitBytes),
                            static_cast<unsigned long long>(*Summary.ProcessMetricSamples));
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

    [[nodiscard]] auto AggregateWorkers(const MeasurementSummary &Summary) -> SummaryTotals
    {
        SummaryTotals Totals;
        for (const auto &Result : Summary.Workers)
        {
            Totals.Hits += Result.Hits;
            Totals.Misses += Result.Misses;
            Totals.Gets += Result.Gets;
            Totals.Inserts += Result.Inserts;
            Totals.Overwrites += Result.Overwrites;
            Totals.Expirations += Result.Expirations;
            Totals.ExplicitEvictions += Result.ExplicitEvictions;
            Totals.CapacityPressureEvents += Result.CapacityPressureEvents;
            Totals.ExpiredEvictions += Result.ExpiredEvictions;
            Totals.ValueMismatches += Result.ValueMismatches;
            Totals.Checksum ^= Result.Checksum;
            Totals.Checksum *= 1099511628211ull;
        }
        return Totals;
    }

    [[nodiscard]] auto SummarizeLatency(MeasurementSummary &Summary) -> LatencySummary
    {
        std::sort(Summary.Latencies.begin(), Summary.Latencies.end());
        return LatencySummary{
            Percentile(Summary.Latencies, 50, 100),
            Percentile(Summary.Latencies, 95, 100),
            Percentile(Summary.Latencies, 99, 100),
            static_cast<double>(Summary.MeasuredOperations) / Summary.DurationSeconds};
    }

    auto PrintScenarioSummary(const Scenario &Workload, const MeasurementSummary &Summary) -> void
    {
        if (Workload.Settings.Workload == WorkloadKind::Mixed)
        {
            std::printf("variant=%s workload=%s capacity=%zu get_selection_preference_percent=%u distribution=%s executors=%zu operations=%llu seed=%llu trace_hash=%016llx\n",
                        VariantName(Workload.Settings.Selected),
                        WorkloadName(Workload.Settings.Workload), Workload.Settings.Capacity,
                        Workload.Settings.HitPercent,
                        DistributionName(Workload.Settings.AccessDistribution),
                        Workload.Settings.Executors,
                        static_cast<unsigned long long>(Summary.MeasuredOperations),
                        static_cast<unsigned long long>(Workload.Settings.Seed),
                        static_cast<unsigned long long>(Workload.TraceHash));
        }
        else
        {
            std::printf("variant=%s workload=%s capacity=%zu target_hit_rate=%u distribution=%s executors=%zu operations=%llu seed=%llu trace_hash=%016llx\n",
                        VariantName(Workload.Settings.Selected),
                        WorkloadName(Workload.Settings.Workload), Workload.Settings.Capacity,
                        Workload.Settings.HitPercent,
                        DistributionName(Workload.Settings.AccessDistribution),
                        Workload.Settings.Executors,
                        static_cast<unsigned long long>(Summary.MeasuredOperations),
                        static_cast<unsigned long long>(Workload.Settings.Seed),
                        static_cast<unsigned long long>(Workload.TraceHash));
        }
    }

    auto PrintObservedSummary(
        const SummaryTotals &Totals,
        const LatencySummary &Latency,
        const MeasurementSummary &Summary) -> void
    {
        const auto ActualHitPercent = Totals.Gets == 0 ? 0 : Totals.Hits * 100 / Totals.Gets;
        std::printf("observed_hits=%llu observed_misses=%llu observed_hit_rate_percent=%llu ops_per_s=%.2f p50_ns=%llu p95_ns=%llu p99_ns=%llu allocations=%llu allocation_bytes=%llu aligned_allocations=%llu aligned_allocation_bytes=%llu checksum=%016llx value_mismatches=%llu\n",
                    static_cast<unsigned long long>(Totals.Hits),
                    static_cast<unsigned long long>(Totals.Misses),
                    static_cast<unsigned long long>(ActualHitPercent),
                    Latency.OpsPerSecond,
                    static_cast<unsigned long long>(Latency.P50),
                    static_cast<unsigned long long>(Latency.P95),
                    static_cast<unsigned long long>(Latency.P99),
                    static_cast<unsigned long long>(Summary.Allocations),
                    static_cast<unsigned long long>(Summary.AllocatedBytes),
                    static_cast<unsigned long long>(Summary.AlignedAllocations),
                    static_cast<unsigned long long>(Summary.AlignedAllocatedBytes),
                    static_cast<unsigned long long>(Totals.Checksum),
                    static_cast<unsigned long long>(Totals.ValueMismatches));
    }

    auto PrintOperationSummary(const Scenario &Workload, const SummaryTotals &Totals) -> void
    {
        const auto WorkerMultiplier = Workload.Settings.Workload == WorkloadKind::Mixed
                                           ? Workload.Settings.Executors
                                           : std::size_t{1};
        const auto DynamicGetPercent = Workload.Mix.Gets == 0
                                           ? 0.0
                                           : static_cast<double>(Workload.Mix.DynamicGets * 100) /
                                                 static_cast<double>(Workload.Mix.Gets);
        if (Workload.Settings.Workload == WorkloadKind::Mixed)
        {
            std::printf("operation_mix=gets:%llu inserts:%llu overwrites:%llu expirations:%llu explicit_evictions:%llu negative_writes:%llu required_hit_probes:%llu required_miss_probes:%llu dynamic_gets:%llu dynamic_get_percent:%.2f\n",
                        static_cast<unsigned long long>(Totals.Gets),
                        static_cast<unsigned long long>(Totals.Inserts),
                        static_cast<unsigned long long>(Totals.Overwrites),
                        static_cast<unsigned long long>(Totals.Expirations),
                        static_cast<unsigned long long>(Totals.ExplicitEvictions),
                        static_cast<unsigned long long>(Workload.Mix.NegativeInserts * WorkerMultiplier),
                        static_cast<unsigned long long>(Workload.Mix.RequiredHitProbes * WorkerMultiplier),
                        static_cast<unsigned long long>(Workload.Mix.RequiredMissProbes * WorkerMultiplier),
                        static_cast<unsigned long long>(Workload.Mix.DynamicGets * WorkerMultiplier),
                        DynamicGetPercent);
            std::printf("evictions=capacity_pressure_events:%llu expired_observed:%llu explicit_sweep_calls:%llu policy=%s\n",
                        static_cast<unsigned long long>(Totals.CapacityPressureEvents),
                        static_cast<unsigned long long>(Totals.ExpiredEvictions),
                        static_cast<unsigned long long>(Totals.ExplicitEvictions),
                        EvictionPolicyName(Workload.Settings.Selected));
            std::puts("eviction_note=capacity_pressure_events are inferred from trace state and pre-insert size, not internal victim counts; expired_observed includes Get-time discard and explicit sweeps");
        }
        else
        {
            std::printf("operation_mix=gets:%llu inserts:%llu overwrites:%llu expirations:%llu explicit_evictions:%llu negative_inserts:%llu\n",
                        static_cast<unsigned long long>(Totals.Gets),
                        static_cast<unsigned long long>(Totals.Inserts),
                        static_cast<unsigned long long>(Totals.Overwrites),
                        static_cast<unsigned long long>(Totals.Expirations),
                        static_cast<unsigned long long>(Totals.ExplicitEvictions),
                        static_cast<unsigned long long>(Workload.Mix.NegativeInserts));
            std::printf("evictions=capacity:%llu expired:%llu total:%llu policy=%s\n",
                        static_cast<unsigned long long>(Totals.CapacityPressureEvents),
                        static_cast<unsigned long long>(Totals.ExpiredEvictions),
                        static_cast<unsigned long long>(Totals.CapacityPressureEvents +
                                                         Totals.ExpiredEvictions),
                        EvictionPolicyName(Workload.Settings.Selected));
        }
    }

    auto PrintComparisonSummary(const Scenario &Workload) -> void
    {
        if (Workload.Settings.Selected == Variant::Clock)
        {
            std::puts("clock_comparison=CLOCK second-chance victim identity is intentionally not exact LRU; compare observed hit-rate, eviction counts, checksum, and tail latency using the same trace_hash");
        }
        else if (Workload.Settings.Workload == WorkloadKind::Mixed)
        {
            std::puts("clock_comparison=compare this exact trace_hash with variant C; CLOCK may trade victim precision for hit-rate and latency");
        }
    }

    auto PrintMeasurementBoundaries(
        const Scenario &Workload,
        const MeasurementSummary &Summary) -> void
    {
        std::puts("memory_boundary=timed process-wide ordinary and aligned C++ operator new/new[] calls; cache setup, trace storage, allocator retention, other malloc/native DLL callers, and RSS are excluded");
        std::puts("rss_boundary=working set and commit sampled immediately before Start and immediately after Finish; sampler peak is restricted to the timed window");
        std::puts("cache_owner=one independent cache per executor; mixed mode replays the same trace per cache; get-only mode preserves the D01 partition");
        std::puts("trace=get-only reads remain read-only; mixed mode measures Gets, inserts, overwrites, zero-TTL expiry writes, and explicit expiry sweeps");
        if (Workload.Settings.Workload == WorkloadKind::Mixed)
        {
            std::puts("semantic_preflight=trace generation and synchronized A/B/C replay occur before timing; A/B stepwise results, size, and explicit expiry counts match; C mandatory probes are fail-closed; CLOCK victims may differ from exact LRU");
        }
        else
        {
            std::puts("semantic_preflight=trace generation occurs before timing; candidate value correctness is checked during timing; CLOCK eviction victims may differ from exact LRU");
        }
        PrintRss(Summary);
        if (!Summary.Latencies.empty())
        {
            std::printf("latency_samples=%zu latency_sample_rate_percent=100.00\n",
                        Summary.Latencies.size());
        }
        else
        {
            std::puts("latency_samples=0 latency_sample_rate_percent=null");
        }
        std::puts("allocation_boundary=ordinary and aligned process-wide operator new/new[] calls in the timed window, reported by kind and requested bytes; setup, trace storage, allocator retention, and other malloc/native DLL callers are excluded");
        std::puts("process_metric_boundary=1ms sampler thread is created before TrackAllocations and samples only after timed Start; sampler CPU/RSS effects remain part of process metrics");
        PrintProcessMetrics(Summary);
    }

    auto PrintSummary(const Scenario &Workload, MeasurementSummary &Summary) -> void
    {
        const auto Totals = AggregateWorkers(Summary);
        const auto Latency = SummarizeLatency(Summary);
        PrintScenarioSummary(Workload, Summary);
        PrintObservedSummary(Totals, Latency, Summary);
        PrintOperationSummary(Workload, Totals);
        PrintComparisonSummary(Workload);
        PrintMeasurementBoundaries(Workload, Summary);
    }

    auto ResultMatches(const Scenario &Workload, const Compare::Operation &Operation,
                       const Compare::CacheResult &Value) -> bool
    {
        if (Workload.Settings.Workload == WorkloadKind::Mixed)
        {
            if (!Value.has_value())
            {
                return !Operation.RequireHit;
            }
            if (Operation.RequireMiss)
            {
                return false;
            }
            if (!Operation.ExpectedPresent)
            {
                return false;
            }
            if (Operation.ExpectedNegative)
            {
                return Value->empty();
            }
            return Value->size() == 1 &&
                   (*Value)[0] == Compare::AddressForVersion(Workload, Operation.ExpectedVersion);
        }
        if (!Operation.ExpectedHit)
        {
            return !Value.has_value();
        }
        if (!Value.has_value())
        {
            return false;
        }
        const auto &Key = Workload.Keys[Operation.KeyIndex];
        return Key.Negative ? Value->empty()
                            : Value->size() == 1 && (*Value)[0] == Workload.ExpectedAddress;
    }

    auto MakeWriteInput(const Scenario &Workload, const Compare::Operation &Operation)
        -> Dns::PutInput
    {
        Dns::PutInput Input;
        Input.Domain = Workload.Keys[Operation.KeyIndex].Domain;
        Input.QType = 1;
        Input.Ttl = std::chrono::seconds{Operation.TtlSeconds};
        Input.Failed = Operation.Negative;
        if (!Operation.Negative)
        {
            Input.Ips.push_back(Compare::AddressForVersion(Workload, Operation.ValueVersion));
        }
        return Input;
    }

    template <typename CacheType>
    struct WorkerExecution
    {
        CacheType &Cache;
        const Scenario &Workload;
        WorkerResult &Result;
    };

    template <typename CacheType>
    auto ExecuteOperation(WorkerExecution<CacheType> &Execution,
                          const Compare::Operation &Operation) -> bool
    {
        auto &Cache = Execution.Cache;
        const auto &Workload = Execution.Workload;
        auto &Result = Execution.Result;
        const auto &Key = Workload.Keys[Operation.KeyIndex];
        const auto SizeBefore = Cache.Size();
        MixChecksum(Result, static_cast<std::uint64_t>(Operation.Kind));
        MixChecksum(Result, Operation.KeyIndex);
        switch (Operation.Kind)
        {
        case Compare::OperationKind::Get:
        {
            ++Result.Gets;
            const auto Value = Cache.Get(Key.Domain, 1);
            const auto Hit = Value.has_value();
            if (Hit)
            {
                ++Result.Hits;
            }
            else
            {
                ++Result.Misses;
            }
            if (Cache.Size() < SizeBefore)
            {
                ++Result.ExpiredEvictions;
            }
            MixChecksum(Result, Hit ? 1ull : 0ull);
            MixChecksum(Result, Hit && Value->empty() ? 1ull : 0ull);
            if (!ResultMatches(Workload, Operation, Value))
            {
                ++Result.ValueMismatches;
                return false;
            }
            return true;
        }
        case Compare::OperationKind::Insert:
            ++Result.Inserts;
            if (Operation.Negative)
            {
                Cache.PutNegative(Key.Domain, 1);
            }
            else
            {
                Cache.Put(MakeWriteInput(Workload, Operation));
            }
            break;
        case Compare::OperationKind::Overwrite:
            ++Result.Overwrites;
            if (Operation.Negative)
            {
                Cache.PutNegative(Key.Domain, 1);
            }
            else
            {
                Cache.Put(MakeWriteInput(Workload, Operation));
            }
            break;
        case Compare::OperationKind::Expire:
            ++Result.Expirations;
            Cache.Put(MakeWriteInput(Workload, Operation));
            break;
        case Compare::OperationKind::EvictExpired:
        {
            ++Result.ExplicitEvictions;
            const auto Evicted = Cache.EvictExpired();
            Result.ExpiredEvictions += Evicted;
            MixChecksum(Result, Evicted);
            return true;
        }
        }
        if ((Operation.Kind == Compare::OperationKind::Insert ||
             Operation.Kind == Compare::OperationKind::Overwrite ||
             Operation.Kind == Compare::OperationKind::Expire) &&
            SizeBefore >= Workload.Settings.Capacity && !Operation.ExpectedPresent)
        {
            ++Result.CapacityPressureEvents;
        }
        MixChecksum(Result, Cache.Size());
        return true;
    }

    template <typename CacheType>
    struct WorkerContext
    {
        const Scenario &Workload;
        std::vector<std::unique_ptr<CacheType>> &Caches;
        std::vector<std::uint64_t> &Latencies;
        std::vector<WorkerResult> &Results;
        std::atomic<bool> &Failed;
        std::atomic<bool> &Go;
        std::latch &Ready;
        std::latch &Done;
        std::size_t WorkerCount;
    };

    template <typename CacheType>
    void RunWorker(WorkerContext<CacheType> &Context, const std::size_t Worker)
    {
        Context.Ready.count_down();
        Context.Go.wait(false, std::memory_order_acquire);
        const auto RepeatTrace = Context.Workload.Settings.Workload == WorkloadKind::Mixed;
        const auto Begin = RepeatTrace ? std::size_t{0}
                                       : Context.Workload.Trace.size() * Worker / Context.WorkerCount;
        const auto End = RepeatTrace ? Context.Workload.Trace.size()
                                     : Context.Workload.Trace.size() * (Worker + 1) /
                                           Context.WorkerCount;
        const auto LatencyOffset = RepeatTrace ? Context.Workload.Trace.size() * Worker : 0;
        try
        {
            auto &Cache = *Context.Caches[Worker];
            auto &WorkerStats = Context.Results[Worker];
            WorkerExecution<CacheType> Execution{Cache, Context.Workload, WorkerStats};
            if (!RepeatTrace)
            {
                for (auto Index = Begin; Index < End; ++Index)
                {
                    const auto &Operation = Context.Workload.Trace[Index];
                    const auto &Key = Context.Workload.Keys[Operation.KeyIndex];
                    const auto Start = Clock::now();
                    const auto Value = Cache.Get(Key.Domain, 1);
                    const auto ValueIsCorrect = ResultMatches(Context.Workload, Operation, Value);
                    const auto Finish = Clock::now();
                    Context.Latencies[Index] = static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::nanoseconds>(Finish - Start).count());

                    if (Operation.ExpectedHit)
                    {
                        ++WorkerStats.Hits;
                    }
                    else
                    {
                        ++WorkerStats.Misses;
                    }
                    if (!ValueIsCorrect)
                    {
                        Context.Failed.store(true, std::memory_order_relaxed);
                    }
                }
                WorkerStats.Gets = End - Begin;
            }
            else
            {
                for (auto Index = Begin; Index < End; ++Index)
                {
                    const auto &Operation = Context.Workload.Trace[Index];
                    const auto Start = Clock::now();
                    const auto ValueIsCorrect = ExecuteOperation(Execution, Operation);
                    const auto Finish = Clock::now();
                    Context.Latencies[LatencyOffset + Index] = static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::nanoseconds>(Finish - Start).count());

                    if (!ValueIsCorrect)
                    {
                        Context.Failed.store(true, std::memory_order_relaxed);
                    }
                }
            }
        }
        catch (...)
        {
            Context.Failed.store(true, std::memory_order_relaxed);
        }
        Context.Done.count_down();
    }

    template <typename CacheType>
    auto RunMeasurements(const Scenario &Workload) -> int
    {
        const auto WorkerCount = Workload.Settings.Executors;
        const auto CacheOptions = MakeTimedCacheOptions(Workload.Settings.Capacity);
        std::vector<std::unique_ptr<CacheType>> Caches;
        Caches.reserve(WorkerCount);
        for (std::size_t Worker = 0; Worker < WorkerCount; ++Worker)
        {
            auto Cache = MakeCache<CacheType>(CacheOptions);
            FillCache(*Cache, Workload);
            Caches.push_back(std::move(Cache));
        }

        const auto RepeatTrace = Workload.Settings.Workload == WorkloadKind::Mixed;
        const auto LatencyCount = Workload.Trace.size() * (RepeatTrace ? WorkerCount : 1);
        std::vector<std::uint64_t> Latencies(LatencyCount);
        std::vector<WorkerResult> Results(WorkerCount);
        std::vector<std::thread> Threads;
        Threads.reserve(WorkerCount);
        std::latch Ready{static_cast<std::ptrdiff_t>(WorkerCount)};
        std::latch Done{static_cast<std::ptrdiff_t>(WorkerCount)};
        std::atomic<bool> Go{false};
        std::atomic<bool> Failed{false};
        WorkerContext<CacheType> Context{
            Workload, Caches, Latencies, Results, Failed, Go, Ready, Done, WorkerCount};

        for (std::size_t Worker = 0; Worker < WorkerCount; ++Worker)
        {
            Threads.emplace_back([&Context, Worker] { RunWorker(Context, Worker); });
        }

        Ready.wait();
        std::atomic<bool> SampleProcess{false};
        std::atomic<bool> StopProcess{false};
        std::latch ProcessSamplerReady{1};
        std::atomic<std::int64_t> BeginNanoseconds{0};
        std::atomic<std::int64_t> EndNanoseconds{0};
        std::atomic<std::uint64_t> PeakWorkingSet{0};
        std::atomic<std::uint64_t> PeakCommit{0};
        std::atomic<std::uint64_t> ProcessMetricSamples{0};
        std::thread ProcessSampler(RunProcessMetricSampler,
            ProcessSamplerState{&SampleProcess, &StopProcess, &ProcessSamplerReady,
                                 &BeginNanoseconds, &EndNanoseconds, &PeakWorkingSet,
                                 &PeakCommit, &ProcessMetricSamples});
        ProcessSamplerReady.wait();
        const auto RssBefore = CurrentRssBytes();
        const auto ProcessBefore = CurrentProcessMetrics();
        AllocationCount.store(0, std::memory_order_relaxed);
        AllocationBytes.store(0, std::memory_order_relaxed);
        AlignedAllocationCount.store(0, std::memory_order_relaxed);
        AlignedAllocationBytes.store(0, std::memory_order_relaxed);
        TrackAllocations.store(true, std::memory_order_release);
        const auto Start = Clock::now();
        BeginNanoseconds.store(Start.time_since_epoch().count(), std::memory_order_release);
        SampleProcess.store(true, std::memory_order_release);
        Go.store(true, std::memory_order_release);
        Go.notify_all();
        Done.wait();
        // 先发布窗口终点，拒绝已进入采样但在业务结束后返回的样本。
        const auto Finish = Clock::now();
        EndNanoseconds.store(Finish.time_since_epoch().count(), std::memory_order_release);
        SampleProcess.store(false, std::memory_order_release);
        TrackAllocations.store(false, std::memory_order_release);
        const auto RssAfter = CurrentRssBytes();
        const auto ProcessAfter = CurrentProcessMetrics();
        StopProcess.store(true, std::memory_order_release);
        ProcessSampler.join();
        for (auto &Thread : Threads)
        {
            Thread.join();
        }

        if (Failed.load(std::memory_order_relaxed))
        {
            std::fprintf(stderr, "[FAIL] measured operation result differed from the trace\n");
            return 1;
        }

        MeasurementSummary Summary;
        Summary.DurationSeconds = std::chrono::duration<double>(Finish - Start).count();
        Summary.MeasuredOperations = static_cast<std::uint64_t>(Workload.Trace.size()) *
                                     (Workload.Settings.Workload == WorkloadKind::Mixed
                                          ? Workload.Settings.Executors
                                          : 1);
        Summary.Latencies = std::move(Latencies);
        Summary.Workers = std::move(Results);
        Summary.Allocations = AllocationCount.load(std::memory_order_relaxed);
        Summary.AllocatedBytes = AllocationBytes.load(std::memory_order_relaxed);
        Summary.AlignedAllocations = AlignedAllocationCount.load(std::memory_order_relaxed);
        Summary.AlignedAllocatedBytes = AlignedAllocationBytes.load(std::memory_order_relaxed);
        Summary.RssBefore = RssBefore;
        Summary.RssAfter = RssAfter;
        Summary.ProcessBefore = ProcessBefore;
        Summary.ProcessAfter = ProcessAfter;
        if (ProcessMetricSamples.load(std::memory_order_relaxed) != 0)
        {
            Summary.PeakWorkingSetBytes = PeakWorkingSet.load(std::memory_order_relaxed);
            Summary.PeakCommitBytes = PeakCommit.load(std::memory_order_relaxed);
            Summary.ProcessMetricSamples = ProcessMetricSamples.load(std::memory_order_relaxed);
        }
        PrintSummary(Workload, Summary);
        return 0;
    }

    template <typename CacheType>
    auto RunSelected(const Scenario &Workload) -> int
    {
        return RunMeasurements<CacheType>(Workload);
    }

    auto RunInternal(const Scenario &Workload) -> int
    {
        switch (Workload.Settings.Selected)
        {
        case Variant::Current:
            return RunSelected<CurrentCache>(Workload);
        case Variant::Intrusive:
            return RunSelected<IntrusiveCache>(Workload);
        case Variant::Clock:
            return RunSelected<ClockCache>(Workload);
        }
        return 1;
    }
} // namespace

namespace Prism::Network::Dns::Compare::Perf
{
    auto Run(const Scenario &Workload) -> int
    {
        return RunInternal(Workload);
    }
}
