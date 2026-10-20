/**
 * @file ProtocolTransferBenchReport.cpp
 * @brief ProtocolTransferBench module owner.
 */

#include "ProtocolTransferBench.hpp"

namespace ProtocolTransferBench
{
    [[nodiscard]] auto Percentile(
        std::vector<std::int64_t> Samples,
        const std::size_t Numerator,
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

    /** @brief 输出五轮 Chunk 样本并执行原有 50 MB/s 性能门禁。 */
    auto Report(const char *Name, const std::size_t Bytes,
                const Result &Statistics) -> void
    {
        const double Megabytes = static_cast<double>(Bytes) / (1024.0 * 1024.0);
        const auto MedianNs = Statistics.Median();
        const double Seconds = static_cast<double>(MedianNs) / 1e9;
        std::printf(
            "%-44s %7.1f MB  med=%7.2f ms (runs %6.2f/%6.2f/%6.2f/%6.2f/%6.2f)  => %9.1f MB/s  %5.1f Gbps\n",
            Name, Megabytes, Seconds * 1000,
            Statistics.Samples[0] / 1e6, Statistics.Samples[1] / 1e6,
            Statistics.Samples[2] / 1e6, Statistics.Samples[3] / 1e6,
            Statistics.Samples[4] / 1e6, Megabytes / Seconds,
            Megabytes / Seconds * 8 / 1000);
    }

    /** @brief 全部样本完成且中位吞吐不低于 50 MB/s 时通过。 */
    [[nodiscard]] auto Gate(const char *Name, const std::size_t Bytes,
                            const Result &Statistics) -> bool
    {
        constexpr double MinMegabytesPerSecond = 50.0;
        Report(Name, Bytes, Statistics);
        const auto MedianNs = Statistics.Median();
        const auto HasIncompleteSample = std::any_of(
            Statistics.Samples.begin(), Statistics.Samples.end(),
            [](const std::int64_t Sample) { return Sample <= 0; });
        if (HasIncompleteSample)
        {
            std::printf("FAIL %s: 存在数据面未完成运行（断链/死循环）\n", Name);
            return false;
        }
        const double MegabytesPerSecond = static_cast<double>(Bytes) /
            (1024.0 * 1024.0) / (static_cast<double>(MedianNs) / 1e9);
        if (MegabytesPerSecond < MinMegabytesPerSecond)
        {
            std::printf("FAIL %s: 吞吐 %.1f MB/s < 下限 %.1f MB/s\n",
                        Name, MegabytesPerSecond, MinMegabytesPerSecond);
            return false;
        }
        return true;
    }

    auto PrintGlobalAllocationRounds(const ProtocolSeries &Series) -> void
    {
        std::printf(
            "  global-new ordinary=[%zu,%zu,%zu,%zu,%zu] aligned=[%zu,%zu,%zu,%zu,%zu] "
            "bytes=[%zu,%zu,%zu,%zu,%zu]/[%zu,%zu,%zu,%zu,%zu]\n",
            Series.Rounds[0].GlobalAllocations.OrdinaryAllocations,
            Series.Rounds[1].GlobalAllocations.OrdinaryAllocations,
            Series.Rounds[2].GlobalAllocations.OrdinaryAllocations,
            Series.Rounds[3].GlobalAllocations.OrdinaryAllocations,
            Series.Rounds[4].GlobalAllocations.OrdinaryAllocations,
            Series.Rounds[0].GlobalAllocations.AlignedAllocations,
            Series.Rounds[1].GlobalAllocations.AlignedAllocations,
            Series.Rounds[2].GlobalAllocations.AlignedAllocations,
            Series.Rounds[3].GlobalAllocations.AlignedAllocations,
            Series.Rounds[4].GlobalAllocations.AlignedAllocations,
            Series.Rounds[0].GlobalAllocations.OrdinaryBytes,
            Series.Rounds[1].GlobalAllocations.OrdinaryBytes,
            Series.Rounds[2].GlobalAllocations.OrdinaryBytes,
            Series.Rounds[3].GlobalAllocations.OrdinaryBytes,
            Series.Rounds[4].GlobalAllocations.OrdinaryBytes,
            Series.Rounds[0].GlobalAllocations.AlignedBytes,
            Series.Rounds[1].GlobalAllocations.AlignedBytes,
            Series.Rounds[2].GlobalAllocations.AlignedBytes,
            Series.Rounds[3].GlobalAllocations.AlignedBytes,
            Series.Rounds[4].GlobalAllocations.AlignedBytes);
    }

    auto PrintProtocolProcessMetrics(const ProtocolSeries &Series) -> void
    {
#ifdef _WIN32
        std::printf(
            "  process cpu-user-ms=[%.2f,%.2f,%.2f,%.2f,%.2f] cpu-kernel-ms=[%.2f,%.2f,%.2f,%.2f,%.2f] "
            "working-set=[%zu,%zu,%zu,%zu,%zu] private=[%zu,%zu,%zu,%zu,%zu] "
            "samples=[%zu,%zu,%zu,%zu,%zu]\n",
            Series.Rounds[0].CpuUser100ns / 10000.0, Series.Rounds[1].CpuUser100ns / 10000.0,
            Series.Rounds[2].CpuUser100ns / 10000.0, Series.Rounds[3].CpuUser100ns / 10000.0,
            Series.Rounds[4].CpuUser100ns / 10000.0, Series.Rounds[0].CpuKernel100ns / 10000.0,
            Series.Rounds[1].CpuKernel100ns / 10000.0, Series.Rounds[2].CpuKernel100ns / 10000.0,
            Series.Rounds[3].CpuKernel100ns / 10000.0, Series.Rounds[4].CpuKernel100ns / 10000.0,
            Series.Rounds[0].PeakWorkingSet, Series.Rounds[1].PeakWorkingSet,
            Series.Rounds[2].PeakWorkingSet, Series.Rounds[3].PeakWorkingSet,
            Series.Rounds[4].PeakWorkingSet, Series.Rounds[0].PeakPrivateUsage,
            Series.Rounds[1].PeakPrivateUsage, Series.Rounds[2].PeakPrivateUsage,
            Series.Rounds[3].PeakPrivateUsage, Series.Rounds[4].PeakPrivateUsage,
            Series.Rounds[0].ProcessSampleCount, Series.Rounds[1].ProcessSampleCount,
            Series.Rounds[2].ProcessSampleCount, Series.Rounds[3].ProcessSampleCount,
            Series.Rounds[4].ProcessSampleCount);
#else
        (void)Series;
        std::printf("  process metrics=unavailable\n");
#endif
    }

    [[nodiscard]] auto PrintProtocolSeries(const ProtocolSeriesPrintRequest &Request) -> bool
    {
        const auto &Series = *Request.Series;
        std::vector<std::int64_t> Wall;
        std::vector<std::int64_t> Blocks;
        Wall.reserve(Series.Rounds.size());
        std::size_t Sent = 0;
        std::size_t Echoed = 0;
        std::size_t Errors = 0;
        std::uint64_t ExpectedHash = InitialHash;
        std::uint64_t ServerInputHash = InitialHash;
        std::uint64_t ClientOutputHash = InitialHash;
        bool HasHash = false;
        std::size_t PartialIo = 0;
        bool Valid = true;
        bool GlobalValid = true;
#ifdef _WIN32
        bool ProcessValid = true;
#endif
        for (const auto &Round : Series.Rounds)
        {
            Wall.push_back(Round.WallNs);
            Blocks.insert(Blocks.end(), Round.BlockSamples.begin(), Round.BlockSamples.end());
            Sent += Round.Sent;
            Echoed += Round.Echoed;
            Errors += Round.Errors;
            PartialIo += Round.PartialIo;
            Valid = Valid && Round.Completed && Round.WallNs > 0;
            if (!HasHash)
            {
                ExpectedHash = Round.ExpectedInputHash;
                ServerInputHash = Round.ServerInputHash;
                ClientOutputHash = Round.ClientOutputHash;
                HasHash = true;
            }
            else if (ExpectedHash != Round.ExpectedInputHash ||
                     ServerInputHash != Round.ServerInputHash ||
                     ClientOutputHash != Round.ClientOutputHash)
            {
                Valid = false;
            }
            GlobalValid = GlobalValid && Round.GlobalAllocations.OrdinaryAllocations > 0 &&
                          Round.GlobalAllocations.AlignedAllocations > 0 &&
                          Round.GlobalAllocations.OrdinaryBytes > 0 &&
                          Round.GlobalAllocations.AlignedBytes > 0;
#ifdef _WIN32
            ProcessValid = ProcessValid && Round.ProcessAvailable;
#endif
        }
        std::sort(Wall.begin(), Wall.end());
        std::int64_t TotalWall = 0;
        for (const auto Value : Wall)
        {
            TotalWall += Value;
        }
        const auto Expected = Request.Total * Request.LaneCount * Series.Rounds.size();
        Valid = Valid && Errors == 0 && Sent == Expected && Echoed == Expected &&
                !Blocks.empty() && PartialIo > 0 && GlobalValid &&
                ExpectedHash == ServerInputHash && ExpectedHash == ClientOutputHash;
#ifdef _WIN32
        Valid = Valid && ProcessValid;
#endif
        const auto Throughput = TotalWall > 0
                                    ? static_cast<double>(Expected) * 1e9 /
                                          static_cast<double>(TotalWall) / (1024.0 * 1024.0)
                                    : 0.0;
        std::printf(
            "protocol %-12s lanes=%zu wall-p50=%.2fms wall-min=%.2fms wall-max=%.2fms "
            "throughput=%.1fMB/s block-p50=%.2fus block-p95=%.2fus block-p99=%.2fus "
            "sent=%zu echoed=%zu errors=%zu partial=%zu expected-hash=%016llx "
            "server-input-hash=%016llx client-output-hash=%016llx valid=%s\n",
            Request.Name, Request.LaneCount, Wall[2] / 1e6, Wall[0] / 1e6, Wall[4] / 1e6,
            Throughput, Percentile(Blocks, 50, 100) / 1e3,
            Percentile(Blocks, 95, 100) / 1e3, Percentile(Blocks, 99, 100) / 1e3,
            Sent, Echoed, Errors, PartialIo,
            static_cast<unsigned long long>(ExpectedHash),
            static_cast<unsigned long long>(ServerInputHash),
            static_cast<unsigned long long>(ClientOutputHash),
            Valid ? "yes" : "no");
        PrintGlobalAllocationRounds(Series);
        PrintProtocolProcessMetrics(Series);
        return Valid;
    }


}
