/**
 * @file PerfReport.cpp
 * @brief TransferPerf 模块所有者。
 */

#include "TransferPerf.hpp"

namespace TransferPerf
{
    [[nodiscard]] auto ModeName(IoMode Mode) -> const char *;
    [[nodiscard]] auto RunIoPreflight(IoMode Mode) -> bool;
    [[nodiscard]] auto RunIoCompareRound(CompareRoundRequest Request)
        -> Net::awaitable<IoCompareResult>;
    [[nodiscard]] auto RunAllocationObserverPreflight() -> bool;
    [[nodiscard]] auto RunStartupFailurePreflight() -> bool;
    auto RunMeasuredCompareRound(CompareRoundRequest Request, IoCompareResult &Result)
        -> Net::awaitable<void>;
    auto RunStartupFailureRound(IoCompareResult &Result) -> Net::awaitable<void>
    {
        Result = co_await RunIoCompareRound(
            CompareRoundRequest{IoMode::Direct, 1, 1, 64, 0, PayloadHash(1), true});
    }

    auto RunMeasuredCompareRound(
        CompareRoundRequest Request, IoCompareResult &Result) -> Net::awaitable<void>
    {
        Result = co_await RunIoCompareRound(std::move(Request));
    }

    [[nodiscard]] auto RunStartupFailurePreflight() -> bool
    {
        Net::io_context IoContext;
        IoCompareResult Result;
        RunCoroutine(IoContext, RunStartupFailureRound(Result));
        const auto Passed = !Result.Completed && Result.Errors > 0;
        std::printf(
            "io-preflight startup-before-ready errors=%zu result=%s\n",
            Result.Errors, Passed ? "pass" : "fail");
        return Passed;
    }

    [[nodiscard]] auto Percentile(
        std::vector<std::int64_t> Samples, const std::size_t Numerator,
        const std::size_t Denominator) -> std::int64_t
    {
        if (Samples.empty())
        {
            return 0;
        }
        std::sort(Samples.begin(), Samples.end());
        const auto Rank = (Samples.size() * Numerator + Denominator - 1U) / Denominator;
        return Samples[(std::max)(std::size_t{1}, Rank) - 1U];
    }

    auto PrintGlobalAllocationMetrics(const ProcessMetrics &Process) -> void
    {
        std::printf(
            "  global-new(observer=included) ordinary=[%zu,%zu,%zu,%zu,%zu] aligned=[%zu,%zu,%zu,%zu,%zu] "
            "frees=[%zu,%zu,%zu,%zu,%zu]/[%zu,%zu,%zu,%zu,%zu] bytes=[%zu,%zu,%zu,%zu,%zu]/"
            "[%zu,%zu,%zu,%zu,%zu]\n",
            Process.GlobalAllocations[0].OrdinaryAllocations,
            Process.GlobalAllocations[1].OrdinaryAllocations,
            Process.GlobalAllocations[2].OrdinaryAllocations,
            Process.GlobalAllocations[3].OrdinaryAllocations,
            Process.GlobalAllocations[4].OrdinaryAllocations,
            Process.GlobalAllocations[0].AlignedAllocations,
            Process.GlobalAllocations[1].AlignedAllocations,
            Process.GlobalAllocations[2].AlignedAllocations,
            Process.GlobalAllocations[3].AlignedAllocations,
            Process.GlobalAllocations[4].AlignedAllocations,
            Process.GlobalAllocations[0].OrdinaryFrees,
            Process.GlobalAllocations[1].OrdinaryFrees,
            Process.GlobalAllocations[2].OrdinaryFrees,
            Process.GlobalAllocations[3].OrdinaryFrees,
            Process.GlobalAllocations[4].OrdinaryFrees,
            Process.GlobalAllocations[0].AlignedFrees,
            Process.GlobalAllocations[1].AlignedFrees,
            Process.GlobalAllocations[2].AlignedFrees,
            Process.GlobalAllocations[3].AlignedFrees,
            Process.GlobalAllocations[4].AlignedFrees,
            Process.GlobalAllocations[0].OrdinaryBytes,
            Process.GlobalAllocations[1].OrdinaryBytes,
            Process.GlobalAllocations[2].OrdinaryBytes,
            Process.GlobalAllocations[3].OrdinaryBytes,
            Process.GlobalAllocations[4].OrdinaryBytes,
            Process.GlobalAllocations[0].AlignedBytes,
            Process.GlobalAllocations[1].AlignedBytes,
            Process.GlobalAllocations[2].AlignedBytes,
            Process.GlobalAllocations[3].AlignedBytes,
            Process.GlobalAllocations[4].AlignedBytes);
    }

    auto PrintProcessMetrics(const ProcessMetrics &Process) -> void
    {
#ifdef _WIN32
        const auto Available = std::all_of(
            Process.Available.begin(), Process.Available.end(),
            [](const auto Value) { return Value; });
        if (Available)
        {
            std::printf(
                "  process cpu-user-ms=[%.2f,%.2f,%.2f,%.2f,%.2f] "
                "cpu-kernel-ms=[%.2f,%.2f,%.2f,%.2f,%.2f] "
                "working-set-peak=[%zu,%zu,%zu,%zu,%zu] private-peak=[%zu,%zu,%zu,%zu,%zu] "
                "sample-count=[%zu,%zu,%zu,%zu,%zu]\n",
                Process.CpuUser100ns[0] / 10000.0, Process.CpuUser100ns[1] / 10000.0,
                Process.CpuUser100ns[2] / 10000.0, Process.CpuUser100ns[3] / 10000.0,
                Process.CpuUser100ns[4] / 10000.0, Process.CpuKernel100ns[0] / 10000.0,
                Process.CpuKernel100ns[1] / 10000.0, Process.CpuKernel100ns[2] / 10000.0,
                Process.CpuKernel100ns[3] / 10000.0, Process.CpuKernel100ns[4] / 10000.0,
                Process.WorkingSet[0], Process.WorkingSet[1], Process.WorkingSet[2],
                Process.WorkingSet[3], Process.WorkingSet[4], Process.PrivateUsage[0],
                Process.PrivateUsage[1], Process.PrivateUsage[2], Process.PrivateUsage[3],
                Process.PrivateUsage[4], Process.SampleCount[0], Process.SampleCount[1],
                Process.SampleCount[2], Process.SampleCount[3], Process.SampleCount[4]);
            return;
        }
#else
        (void)Process;
#endif
        std::printf("  process metrics=unavailable\n");
    }

    auto PrintCompareMetrics(const CompareMetricsRequest &Request) -> bool
    {
        const auto P50 = Percentile(Request.BlockSamples, 50U, 100U);
        const auto P95 = Percentile(Request.BlockSamples, 95U, 100U);
        const auto P99 = Percentile(Request.BlockSamples, 99U, 100U);
        auto Sorted = Request.WallSamples;
        std::sort(Sorted.begin(), Sorted.end());
        std::int64_t TotalWallNs = 0;
        for (const auto Sample : Request.WallSamples)
        {
            TotalWallNs += Sample;
        }
        const auto ValidWall = std::all_of(
            Request.WallSamples.begin(), Request.WallSamples.end(),
            [](const auto Value) { return Value > 0; });
        const auto ValidAllocation = Request.Allocation.OrdinaryAllocations > 0 &&
                                     Request.Allocation.AlignedAllocations > 0 &&
                                     Request.Allocation.OrdinaryBytes > 0 &&
                                     Request.Allocation.AlignedBytes > 0;
        const auto GlobalValid = std::all_of(
            Request.Process.GlobalAllocations.begin(), Request.Process.GlobalAllocations.end(),
            [](const auto &Value)
            {
                const auto AlignedConsistent =
                    (Value.AlignedAllocations == 0 && Value.AlignedBytes == 0) ||
                    (Value.AlignedAllocations > 0 && Value.AlignedBytes > 0);
                return Value.OrdinaryAllocations > 0 && Value.OrdinaryBytes > 0 &&
                       AlignedConsistent;
            });
#ifdef _WIN32
        const auto ProcessValid = std::all_of(
            Request.Process.Available.begin(), Request.Process.Available.end(),
            [](const auto Value) { return Value; }) &&
                             std::all_of(Request.Process.SampleCount.begin(),
                                         Request.Process.SampleCount.end(),
                                         [](const auto Value) { return Value > 0; });
#else
        constexpr auto ProcessValid = true;
#endif
        const auto HashesValid = Request.ExpectedInputHash == Request.ServerInputHash &&
                                 Request.ExpectedInputHash == Request.ClientOutputHash;
        const auto Valid = ValidWall && !Request.BlockSamples.empty() && Request.Partial > 0 &&
                           ValidAllocation && GlobalValid && ProcessValid && HashesValid;
        const auto ConfirmedBytes = Request.ConfirmedBytesPerRound * Request.WallSamples.size();
        const auto Throughput = ValidWall && TotalWallNs > 0
                                    ? static_cast<double>(ConfirmedBytes) * 1e9 /
                                          static_cast<double>(TotalWallNs) / (1024.0 * 1024.0)
                                    : 0.0;
        std::printf(
            "io-compare %-18s lanes=%zu wall-p50=%.2fms wall-min=%.2fms wall-max=%.2fms "
            "throughput=%.1fMB/s block-p50=%.2fus block-p95=%.2fus block-p99=%.2fus "
            "pmr-alloc=%zu/%zu pmr-bytes=%zu/%zu partial=%zu valid=%s "
            "expected-hash=%016llx server-input-hash=%016llx client-output-hash=%016llx\n",
            Request.Name, Request.LaneCount, Sorted[2] / 1e6, Sorted[0] / 1e6, Sorted[4] / 1e6,
            Throughput,
            P50 / 1e3, P95 / 1e3, P99 / 1e3, Request.Allocation.OrdinaryAllocations,
            Request.Allocation.AlignedAllocations, Request.Allocation.OrdinaryBytes,
            Request.Allocation.AlignedBytes, Request.Partial,
            Valid ? "yes" : "no",
            static_cast<unsigned long long>(Request.ExpectedInputHash),
            static_cast<unsigned long long>(Request.ServerInputHash),
            static_cast<unsigned long long>(Request.ClientOutputHash));
        PrintGlobalAllocationMetrics(Request.Process);
        PrintProcessMetrics(Request.Process);
        return Valid;
    }

    auto RunIoCompare() -> int
    {
        const ComparePlan Plan;
        const auto ExpectedInputHash = PayloadHash(Plan.TotalBytes);
        constexpr std::array<IoMode, 3> Modes{
            IoMode::Direct, IoMode::AwaitableBridge, IoMode::ScatterGather};
        bool AllValid = true;
        std::size_t ExecutedGroups = 0;
        std::size_t ExecutedLanes = 0;
        if (!RunAllocationObserverPreflight())
        {
            std::printf("io-compare allocation observer preflight failed\n");
            return 1;
        }
        if (!RunStartupFailurePreflight())
        {
            std::printf("io-compare startup failure preflight failed\n");
            return 1;
        }
        for (const auto Mode : Modes)
        {
            if (!RunIoPreflight(Mode))
            {
                std::printf("io-compare preflight failed; no performance result is valid\n");
                return 1;
            }
        }
        for (const auto LaneCount : Plan.LaneCounts)
        {
            std::array<std::array<std::int64_t, CompareRoundCount>, 3> WallSamples{};
            std::array<std::vector<std::int64_t>, 3> BlockSamples;
            std::array<AllocationStats, 3> Allocations{};
            std::array<ProcessMetrics, 3> ProcessSamples{};
            std::array<std::size_t, 3> PartialCounts{};
            std::array<std::uint64_t, 3> ExpectedHashes{};
            std::array<std::uint64_t, 3> ServerHashes{};
            std::array<std::uint64_t, 3> ClientHashes{};
            for (std::size_t Round = 0; Round < Plan.Rounds; ++Round)
            {
                for (std::size_t ModeIndex = 0; ModeIndex < Modes.size(); ++ModeIndex)
                {
                    const auto ActualIndex = (Round % 2U) == 0U
                                                 ? ModeIndex
                                                 : Modes.size() - ModeIndex - 1U;
                    const auto Mode = Modes[ActualIndex];
                    Net::io_context IoContext;
                    IoCompareResult Result;
                    RunCoroutine(
                        IoContext,
                        RunMeasuredCompareRound(
                            CompareRoundRequest{
                                Mode, LaneCount, Plan.TotalBytes, Plan.BlockSize, Round,
                                ExpectedInputHash, false},
                            Result));
                    ++ExecutedGroups;
                    ExecutedLanes += LaneCount;
                    const auto HashesValid =
                        Result.ExpectedInputHash == ExpectedInputHash &&
                        Result.ServerInputHash == ExpectedInputHash &&
                        Result.ClientOutputHash == ExpectedInputHash;
                    if (!Result.Completed || Result.Sent != Plan.TotalBytes * LaneCount ||
                        Result.Received != Plan.TotalBytes * LaneCount || Result.Errors != 0 ||
                        Result.Partial == 0 || !HashesValid)
                    {
                        AllValid = false;
                        WallSamples[ActualIndex][Round] = 0;
                    }
                    else
                    {
                        WallSamples[ActualIndex][Round] = Result.WallNs;
                    }
                    BlockSamples[ActualIndex].insert(BlockSamples[ActualIndex].end(),
                                                   Result.BlockSamples.begin(), Result.BlockSamples.end());
                    Allocations[ActualIndex].OrdinaryAllocations += Result.OrdinaryAllocations;
                    Allocations[ActualIndex].AlignedAllocations += Result.AlignedAllocations;
                    Allocations[ActualIndex].OrdinaryBytes += Result.OrdinaryBytes;
                    Allocations[ActualIndex].AlignedBytes += Result.AlignedBytes;
                    PartialCounts[ActualIndex] += Result.Partial;
                    ProcessSamples[ActualIndex].CpuUser100ns[Round] = Result.CpuUser100ns;
                    ProcessSamples[ActualIndex].CpuKernel100ns[Round] = Result.CpuKernel100ns;
                    ProcessSamples[ActualIndex].WorkingSet[Round] = Result.PeakWorkingSet;
                    ProcessSamples[ActualIndex].PrivateUsage[Round] = Result.PeakPrivateUsage;
                    ProcessSamples[ActualIndex].SampleCount[Round] = Result.ProcessSampleCount;
                    ProcessSamples[ActualIndex].GlobalAllocations[Round] = Result.GlobalAllocations;
                    ProcessSamples[ActualIndex].Available[Round] = Result.ProcessAvailable;
                    if (Round == 0)
                    {
                        ExpectedHashes[ActualIndex] = Result.ExpectedInputHash;
                        ServerHashes[ActualIndex] = Result.ServerInputHash;
                        ClientHashes[ActualIndex] = Result.ClientOutputHash;
                    }
                    else if (ExpectedHashes[ActualIndex] != Result.ExpectedInputHash ||
                             ServerHashes[ActualIndex] != Result.ServerInputHash ||
                             ClientHashes[ActualIndex] != Result.ClientOutputHash)
                    {
                        AllValid = false;
                    }
                }
            }
            for (std::size_t ModeIndex = 0; ModeIndex < Modes.size(); ++ModeIndex)
            {
                AllValid = PrintCompareMetrics(CompareMetricsRequest{
                    ModeName(Modes[ModeIndex]), LaneCount, WallSamples[ModeIndex],
                    BlockSamples[ModeIndex], Allocations[ModeIndex], ProcessSamples[ModeIndex],
                    Plan.TotalBytes * LaneCount, PartialCounts[ModeIndex],
                    ExpectedHashes[ModeIndex], ServerHashes[ModeIndex], ClientHashes[ModeIndex]}) &&
                    AllValid;
            }
        }
        const auto PlanValid = ExecutedGroups == Plan.ExpectedGroups &&
                               ExecutedLanes == Plan.ExpectedLanes;
        std::printf(
            "io-compare-plan groups=%zu expected-groups=%zu lanes=%zu expected-lanes=%zu "
            "rounds=%zu fragment-bytes=%zu expected-input-hash=%016llx valid=%s\n",
            ExecutedGroups, Plan.ExpectedGroups, ExecutedLanes, Plan.ExpectedLanes,
            Plan.Rounds, Plan.FragmentBytes,
            static_cast<unsigned long long>(ExpectedInputHash), PlanValid ? "yes" : "no");
        AllValid = PlanValid && AllValid;
        return AllValid ? 0 : 1;
    }

    auto Report(
        const char *Name,
        const std::size_t Bytes,
        const Result &Measurement) -> void
    {
        const double Megabytes =
            static_cast<double>(Bytes) / (1024.0 * 1024.0);
        const auto MedianNs = Measurement.Median();
        const double Seconds =
            static_cast<double>(MedianNs) / 1e9;
        std::printf(
            "%-38s %7.1f MB  med=%7.2f ms (3 runs: %7.2f/%7.2f/%7.2f)  => %9.1f MB/s\n",
            Name,
            Megabytes,
            Seconds * 1000,
            Measurement.Samples[0] / 1e6,
            Measurement.Samples[1] / 1e6,
            Measurement.Samples[2] / 1e6,
            Megabytes / Seconds);
    }

    [[nodiscard]] auto Gate(
        const char *Name,
        const std::size_t Bytes,
        const Result &Measurement) -> bool
    {
        constexpr double MinMegabytesPerSecond = 50.0;
        Report(Name, Bytes, Measurement);
        const auto MedianNs = Measurement.Median();
        const auto HasIncompleteSample = std::any_of(
            Measurement.Samples.begin(),
            Measurement.Samples.end(),
            [](const std::int64_t Sample) -> bool
            {
                return Sample <= 0;
            });
        if (HasIncompleteSample)
        {
            std::printf(
                "FAIL %s: 存在数据面未完成运行（断链/死循环）\n",
                Name);
            return false;
        }
        const double MegabytesPerSecond =
            static_cast<double>(Bytes) /
            (1024.0 * 1024.0) /
            (static_cast<double>(MedianNs) / 1e9);
        if (MegabytesPerSecond < MinMegabytesPerSecond)
        {
            std::printf(
                "FAIL %s: 吞吐 %.1f MB/s < 下限 %.1f MB/s\n",
                Name,
                MegabytesPerSecond,
                MinMegabytesPerSecond);
            return false;
        }
        return true;
    }

}

