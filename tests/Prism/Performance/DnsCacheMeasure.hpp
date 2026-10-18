/**
 * @file DnsCacheMeasure.hpp
 * @brief DNS cache 多编译单元共享的分配窗口与真实进程采样数据。
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <latch>

namespace Prism::Network::Dns::Compare::Perf
{
    inline std::atomic<bool> TrackAllocations{false};
    inline std::atomic<std::uint64_t> AllocationCount{0};
    inline std::atomic<std::uint64_t> AllocationBytes{0};
    inline std::atomic<std::uint64_t> AlignedAllocationCount{0};
    inline std::atomic<std::uint64_t> AlignedAllocationBytes{0};
    struct ProcessMetrics final
    {
        std::uint64_t UserTime100ns{0};
        std::uint64_t KernelTime100ns{0};
        std::uint64_t WorkingSetBytes{0};
        std::uint64_t CommitBytes{0};
    };

    struct ProcessSamplerState final
    {
        std::atomic<bool> *Active;
        std::atomic<bool> *Stop;
        std::latch *Ready;
        std::atomic<std::int64_t> *BeginNanoseconds;
        std::atomic<std::int64_t> *EndNanoseconds;
        std::atomic<std::uint64_t> *PeakWorkingSet;
        std::atomic<std::uint64_t> *PeakCommit;
        std::atomic<std::uint64_t> *Samples;
    };
}

