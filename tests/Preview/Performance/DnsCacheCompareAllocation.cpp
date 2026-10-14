/**
 * @file DnsCacheCompareAllocation.cpp
 * @brief DNS cache 对照实验的分配计数与进程资源采样 owner。
 */

#include "DnsCacheScenario.hpp"
#include "DnsCacheVariants.hpp"
#include "DnsCacheMeasure.hpp"

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <latch>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#    if !defined(NOMINMAX)
#        define NOMINMAX
#    endif
#    include <windows.h>
#    include <malloc.h>
#    include <psapi.h>
#endif

namespace Preview::Network::Dns::Compare::Perf
{
    using Clock = std::chrono::steady_clock;
    auto CurrentRssBytes() -> std::optional<std::uint64_t>
    {
#if defined(_WIN32)
        PROCESS_MEMORY_COUNTERS Counters{};
        if (GetProcessMemoryInfo(GetCurrentProcess(), &Counters, sizeof(Counters)) != 0)
        {
            return static_cast<std::uint64_t>(Counters.WorkingSetSize);
        }
#endif
        return std::nullopt;
    }


    auto CurrentProcessMetrics() -> std::optional<ProcessMetrics>
    {
#if defined(_WIN32)
        FILETIME Creation{};
        FILETIME Exit{};
        FILETIME Kernel{};
        FILETIME User{};
        PROCESS_MEMORY_COUNTERS_EX Counters{};
        if (GetProcessTimes(GetCurrentProcess(), &Creation, &Exit, &Kernel, &User) == 0 ||
            GetProcessMemoryInfo(GetCurrentProcess(),
                                 reinterpret_cast<PROCESS_MEMORY_COUNTERS *>(&Counters),
                                 sizeof(Counters)) == 0)
        {
            return std::nullopt;
        }
        const auto ToValue = [](const FILETIME Value) -> std::uint64_t
        {
            return (static_cast<std::uint64_t>(Value.dwHighDateTime) << 32) |
                   static_cast<std::uint64_t>(Value.dwLowDateTime);
        };
        return ProcessMetrics{ToValue(User), ToValue(Kernel),
                              static_cast<std::uint64_t>(Counters.WorkingSetSize),
                              static_cast<std::uint64_t>(Counters.PrivateUsage)};
#else
        return std::nullopt;
#endif
    }

    auto UpdatePeak(std::atomic<std::uint64_t> &Peak, const std::uint64_t Value) -> void
    {
        auto Previous = Peak.load(std::memory_order_relaxed);
        while (Value > Previous &&
               !Peak.compare_exchange_weak(Previous, Value, std::memory_order_relaxed))
        {
        }
    }


    auto RunProcessMetricSampler(const ProcessSamplerState State) -> void
    {
        State.Ready->count_down();
        while (!State.Stop->load(std::memory_order_acquire))
        {
            if (State.Active->load(std::memory_order_acquire))
            {
                const auto SampleBegin = Clock::now().time_since_epoch().count();
                const auto Begin = State.BeginNanoseconds->load(std::memory_order_acquire);
                if (const auto Metrics = CurrentProcessMetrics())
                {
                    const auto SampleEnd = Clock::now().time_since_epoch().count();
                    const auto End = State.EndNanoseconds->load(std::memory_order_acquire);
                    if (Begin != 0 && SampleBegin >= Begin &&
                        (End == 0 || SampleEnd <= End))
                    {
                        UpdatePeak(*State.PeakWorkingSet, Metrics->WorkingSetBytes);
                        UpdatePeak(*State.PeakCommit, Metrics->CommitBytes);
                        State.Samples->fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
    }

    auto Require(const bool Condition, const std::string_view Message) -> void
    {
        if (!Condition)
        {
            throw std::runtime_error(std::string{Message});
        }
    }

}

namespace
{
    namespace Compare = Preview::Network::Dns::Compare;
    namespace Dns = Preview::Network::Dns;

    using Clock = std::chrono::steady_clock;
    using Compare::ClockCache;
    using Compare::CurrentCache;
    using Compare::IntrusiveCache;
    using Compare::Options;
    using Compare::Scenario;
    using Compare::Variant;
    using Compare::WorkloadKind;

    using Preview::Network::Dns::Compare::Perf::TrackAllocations;
    using Preview::Network::Dns::Compare::Perf::AllocationCount;
    using Preview::Network::Dns::Compare::Perf::AllocationBytes;
    using Preview::Network::Dns::Compare::Perf::AlignedAllocationCount;
    using Preview::Network::Dns::Compare::Perf::AlignedAllocationBytes;

    auto Allocate(const std::size_t Size) -> void *
    {
        const auto ActualSize = Size == 0 ? std::size_t{1} : Size;
        auto *Memory = std::malloc(ActualSize);
        if (Memory == nullptr)
        {
            throw std::bad_alloc{};
        }
        if (TrackAllocations.load(std::memory_order_relaxed))
        {
            AllocationCount.fetch_add(1, std::memory_order_relaxed);
            AllocationBytes.fetch_add(static_cast<std::uint64_t>(Size), std::memory_order_relaxed);
        }
        return Memory;
    }

    auto AllocateAligned(const std::size_t Size, const std::size_t Alignment) -> void *
    {
        const auto ActualSize = Size == 0 ? Alignment : Size;
        const auto Remainder = ActualSize % Alignment;
        if (Remainder > 0 && ActualSize > (std::numeric_limits<std::size_t>::max)() -
                                      (Alignment - Remainder))
        {
            throw std::bad_alloc{};
        }
        const auto RoundedSize = Remainder == 0 ? ActualSize : ActualSize + Alignment - Remainder;
#if defined(_WIN32)
        auto *Memory = _aligned_malloc(RoundedSize, Alignment);
#else
        auto *Memory = std::aligned_alloc(Alignment, RoundedSize);
#endif
        if (Memory == nullptr)
        {
            throw std::bad_alloc{};
        }
        if (TrackAllocations.load(std::memory_order_relaxed))
        {
            AlignedAllocationCount.fetch_add(1, std::memory_order_relaxed);
            AlignedAllocationBytes.fetch_add(static_cast<std::uint64_t>(Size),
                                             std::memory_order_relaxed);
        }
        return Memory;
    }

    auto ValidateAllocationInstrumentationInternal() -> void
    {
        constexpr auto OrdinaryBytes = std::size_t{23};
        constexpr auto OrdinaryArrayBytes = std::size_t{41};
        constexpr auto AlignedBytes = std::size_t{37};
        constexpr auto AlignedArrayBytes = std::size_t{53};
        constexpr auto Alignment = std::size_t{64};
        void *Ordinary = nullptr;
        void *OrdinaryArray = nullptr;
        void *Aligned = nullptr;
        void *AlignedArray = nullptr;
        AllocationCount.store(0, std::memory_order_relaxed);
        AllocationBytes.store(0, std::memory_order_relaxed);
        AlignedAllocationCount.store(0, std::memory_order_relaxed);
        AlignedAllocationBytes.store(0, std::memory_order_relaxed);
        try
        {
            TrackAllocations.store(true, std::memory_order_release);
            Ordinary = ::operator new(OrdinaryBytes);
            OrdinaryArray = ::operator new[](OrdinaryArrayBytes);
            Aligned = ::operator new(AlignedBytes, std::align_val_t{Alignment});
            AlignedArray = ::operator new[](AlignedArrayBytes, std::align_val_t{Alignment});
            TrackAllocations.store(false, std::memory_order_release);
        }
        catch (...)
        {
            TrackAllocations.store(false, std::memory_order_release);
            ::operator delete(Ordinary);
            ::operator delete[](OrdinaryArray);
            ::operator delete(Aligned, std::align_val_t{Alignment});
            ::operator delete[](AlignedArray, std::align_val_t{Alignment});
            throw;
        }
        const auto AlignmentValid = reinterpret_cast<std::uintptr_t>(Aligned) % Alignment == 0U &&
                                    reinterpret_cast<std::uintptr_t>(AlignedArray) % Alignment == 0U;
        ::operator delete(Ordinary);
        ::operator delete[](OrdinaryArray);
        ::operator delete(Aligned, std::align_val_t{Alignment});
        ::operator delete[](AlignedArray, std::align_val_t{Alignment});
        const auto ExpectedOrdinaryBytes =
            static_cast<std::uint64_t>(OrdinaryBytes + OrdinaryArrayBytes);
        const auto ExpectedAlignedBytes =
            static_cast<std::uint64_t>(AlignedBytes + AlignedArrayBytes);
        if (AllocationCount.load(std::memory_order_relaxed) != 2U ||
            AllocationBytes.load(std::memory_order_relaxed) != ExpectedOrdinaryBytes ||
            AlignedAllocationCount.load(std::memory_order_relaxed) != 2U ||
            AlignedAllocationBytes.load(std::memory_order_relaxed) != ExpectedAlignedBytes ||
            !AlignmentValid)
        {
            throw std::runtime_error("allocation instrumentation preflight failed");
        }
        std::printf("allocation_preflight=pass ordinary_count=%llu ordinary_bytes=%llu aligned_count=%llu aligned_bytes=%llu alignment=%zu\n",
                    static_cast<unsigned long long>(AllocationCount.load()),
                    static_cast<unsigned long long>(AllocationBytes.load()),
                    static_cast<unsigned long long>(AlignedAllocationCount.load()),
                    static_cast<unsigned long long>(AlignedAllocationBytes.load()), Alignment);
    }

} // namespace

void *operator new(const std::size_t Size)
{
    return Allocate(Size);
}

void *operator new[](const std::size_t Size)
{
    return Allocate(Size);
}

void *operator new(const std::size_t Size, const std::nothrow_t &) noexcept
{
    try
    {
        return ::operator new(Size);
    }
    catch (...)
    {
        return nullptr;
    }
}

void *operator new[](const std::size_t Size, const std::nothrow_t &) noexcept
{
    try
    {
        return ::operator new[](Size);
    }
    catch (...)
    {
        return nullptr;
    }
}

void operator delete(void *Memory) noexcept
{
    std::free(Memory);
}

void operator delete[](void *Memory) noexcept
{
    std::free(Memory);
}

void operator delete(void *Memory, const std::size_t) noexcept
{
    std::free(Memory);
}

void operator delete[](void *Memory, const std::size_t) noexcept
{
    std::free(Memory);
}

void operator delete(void *Memory, const std::nothrow_t &) noexcept
{
    std::free(Memory);
}

void operator delete[](void *Memory, const std::nothrow_t &) noexcept
{
    std::free(Memory);
}

void *operator new(const std::size_t Size, const std::align_val_t Alignment)
{
    return AllocateAligned(Size, static_cast<std::size_t>(Alignment));
}

void *operator new[](const std::size_t Size, const std::align_val_t Alignment)
{
    return AllocateAligned(Size, static_cast<std::size_t>(Alignment));
}

void *operator new(const std::size_t Size, const std::align_val_t Alignment,
                   const std::nothrow_t &) noexcept
{
    try
    {
        return ::operator new(Size, Alignment);
    }
    catch (...)
    {
        return nullptr;
    }
}

void *operator new[](const std::size_t Size, const std::align_val_t Alignment,
                    const std::nothrow_t &) noexcept
{
    try
    {
        return ::operator new[](Size, Alignment);
    }
    catch (...)
    {
        return nullptr;
    }
}

void operator delete(void *Memory, const std::align_val_t) noexcept
{
#if defined(_WIN32)
    _aligned_free(Memory);
#else
    std::free(Memory);
#endif
}

void operator delete[](void *Memory, const std::align_val_t Alignment) noexcept
{
    ::operator delete(Memory, Alignment);
}

void operator delete(void *Memory, const std::size_t, const std::align_val_t Alignment) noexcept
{
    ::operator delete(Memory, Alignment);
}

void operator delete[](void *Memory, const std::size_t, const std::align_val_t Alignment) noexcept
{
    ::operator delete[](Memory, Alignment);
}

void operator delete(void *Memory, const std::nothrow_t &, const std::align_val_t Alignment) noexcept
{
    ::operator delete(Memory, Alignment);
}

void operator delete[](void *Memory, const std::nothrow_t &, const std::align_val_t Alignment) noexcept
{
    ::operator delete[](Memory, Alignment);
}

namespace Preview::Network::Dns::Compare::Perf
{
    auto ValidateAllocationInstrumentation() -> void
    {
        ValidateAllocationInstrumentationInternal();
    }
}

