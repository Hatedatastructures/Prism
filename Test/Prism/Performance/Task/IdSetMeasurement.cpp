/**
 * @file IdSetMeasurement.cpp
 * @brief TaskIdSet 性能实验的 allocation 与进程窗口 owner。
 */

#include "IdSetMeasurement.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <latch>
#include <new>
#include <thread>

#if defined(_WIN32)
#    if !defined(NOMINMAX)
#        define NOMINMAX
#    endif
#    include <windows.h>
#    include <malloc.h>
#    include <psapi.h>
#endif

namespace Prism::Lifecycle::Perf
{

    namespace
    {

        using Clock = std::chrono::steady_clock;

        std::atomic<bool> TrackAllocations{false};
        std::atomic<std::uint64_t> AllocationCount{0};
        std::atomic<std::uint64_t> AllocationBytes{0};
        std::atomic<std::uint64_t> AlignedAllocationCount{0};
        std::atomic<std::uint64_t> AlignedAllocationBytes{0};

        auto CurrentProcessMetrics() -> std::optional<ProcessMetrics>
        {
#if defined(_WIN32)
            FILETIME Create{}, Exit{}, Kernel{}, User{};
            PROCESS_MEMORY_COUNTERS_EX Counters{};
            if (GetProcessTimes(GetCurrentProcess(), &Create, &Exit, &Kernel, &User) == 0 ||
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
                                  static_cast<std::uint64_t>(Counters.PrivateUsage), true};
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

        class Window final
        {
        public:
            Window() : Sampler_(&Window::RunSampler, this) { Ready_.wait(); }
            ~Window() noexcept { Stop(); }

            auto Begin() -> void
            {
                Before_ = CurrentProcessMetrics();
                AllocationCount.store(0, std::memory_order_relaxed);
                AllocationBytes.store(0, std::memory_order_relaxed);
                AlignedAllocationCount.store(0, std::memory_order_relaxed);
                AlignedAllocationBytes.store(0, std::memory_order_relaxed);
                TrackAllocations.store(true, std::memory_order_release);
                BeginNs_ = Clock::now().time_since_epoch().count();
                Begin_.store(BeginNs_, std::memory_order_release);
                Active_.store(true, std::memory_order_release);
            }

            auto Finish() -> MeasurementResult
            {
                const auto EndNs = Clock::now().time_since_epoch().count();
                End_.store(EndNs, std::memory_order_release);
                Active_.store(false, std::memory_order_release);
                TrackAllocations.store(false, std::memory_order_release);
                const auto After = CurrentProcessMetrics();
                Stop();
                return MeasurementResult{
                    AllocationCount.load(std::memory_order_relaxed),
                    AllocationBytes.load(std::memory_order_relaxed),
                    AlignedAllocationCount.load(std::memory_order_relaxed),
                    AlignedAllocationBytes.load(std::memory_order_relaxed),
                    Samples_.load(std::memory_order_relaxed),
                    PeakWorkingSet_.load(std::memory_order_relaxed),
                    PeakCommit_.load(std::memory_order_relaxed),
                    Samples_.load(std::memory_order_relaxed) != 0, Before_, After,
                    BeginNs_, EndNs};
            }

            auto Stop() noexcept -> void
            {
                Stop_.store(true, std::memory_order_release);
                if (Sampler_.joinable()) Sampler_.join();
            }

        private:
            static auto RunSampler(Window *Value) -> void
            {
                Value->Ready_.count_down();
                while (!Value->Stop_.load(std::memory_order_acquire))
                {
                    if (Value->Active_.load(std::memory_order_acquire))
                    {
                        const auto SampleBegin = Clock::now().time_since_epoch().count();
                        const auto Begin = Value->Begin_.load(std::memory_order_acquire);
                        const auto Metrics = CurrentProcessMetrics();
                        const auto SampleEnd = Clock::now().time_since_epoch().count();
                        const auto End = Value->End_.load(std::memory_order_acquire);
                        if (Metrics && Begin != 0 && SampleBegin >= Begin &&
                            (End == 0 || SampleEnd <= End))
                        {
                            UpdatePeak(Value->PeakWorkingSet_, Metrics->WorkingSetBytes);
                            UpdatePeak(Value->PeakCommit_, Metrics->CommitBytes);
                            Value->Samples_.fetch_add(1, std::memory_order_relaxed);
                        }
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds{1});
                }
            }

            std::atomic<bool> Active_{false};
            std::atomic<bool> Stop_{false};
            std::latch Ready_{1};
            std::atomic<std::int64_t> Begin_{0};
            std::atomic<std::int64_t> End_{0};
            std::atomic<std::uint64_t> Samples_{0};
            std::atomic<std::uint64_t> PeakWorkingSet_{0};
            std::atomic<std::uint64_t> PeakCommit_{0};
            std::thread Sampler_;
            std::int64_t BeginNs_{0};
            std::int64_t EndNs_{0};
            std::optional<ProcessMetrics> Before_;
        };

    } // namespace

    auto Measure(const std::function<void()> &Work) -> MeasurementResult
    {
        Window Value;
        Value.Begin();
        Work();
        return Value.Finish();
    }

    auto Allocate(const std::size_t Size) -> void *
    {
        const auto ActualSize = Size == 0 ? std::size_t{1} : Size;
        auto *Memory = std::malloc(ActualSize);
        if (Memory == nullptr) throw std::bad_alloc{};
        if (TrackAllocations.load(std::memory_order_relaxed))
        {
            AllocationCount.fetch_add(1, std::memory_order_relaxed);
            AllocationBytes.fetch_add(Size, std::memory_order_relaxed);
        }
        return Memory;
    }

    auto AllocateAligned(const std::size_t Size, const std::size_t Alignment) -> void *
    {
        const auto ActualSize = Size == 0 ? Alignment : Size;
        const auto Remainder = ActualSize % Alignment;
        const auto Rounded = Remainder == 0 ? ActualSize : ActualSize + Alignment - Remainder;
#if defined(_WIN32)
        auto *Memory = _aligned_malloc(Rounded, Alignment);
#else
        auto *Memory = std::aligned_alloc(Alignment, Rounded);
#endif
        if (Memory == nullptr) throw std::bad_alloc{};
        if (TrackAllocations.load(std::memory_order_relaxed))
        {
            AlignedAllocationCount.fetch_add(1, std::memory_order_relaxed);
            AlignedAllocationBytes.fetch_add(Size, std::memory_order_relaxed);
        }
        return Memory;
    }

} // namespace Prism::Lifecycle::Perf

void *operator new(const std::size_t Size) { return Prism::Lifecycle::Perf::Allocate(Size); }
void *operator new[](const std::size_t Size) { return Prism::Lifecycle::Perf::Allocate(Size); }
void *operator new(const std::size_t Size, const std::nothrow_t &) noexcept
{ try { return ::operator new(Size); } catch (...) { return nullptr; } }
void *operator new[](const std::size_t Size, const std::nothrow_t &) noexcept
{ try { return ::operator new[](Size); } catch (...) { return nullptr; } }
void *operator new(const std::size_t Size, const std::align_val_t Alignment)
{ return Prism::Lifecycle::Perf::AllocateAligned(Size, static_cast<std::size_t>(Alignment)); }
void *operator new[](const std::size_t Size, const std::align_val_t Alignment)
{ return Prism::Lifecycle::Perf::AllocateAligned(Size, static_cast<std::size_t>(Alignment)); }
void *operator new(const std::size_t Size, const std::align_val_t Alignment, const std::nothrow_t &) noexcept
{ try { return ::operator new(Size, Alignment); } catch (...) { return nullptr; } }
void *operator new[](const std::size_t Size, const std::align_val_t Alignment, const std::nothrow_t &) noexcept
{ try { return ::operator new[](Size, Alignment); } catch (...) { return nullptr; } }
void operator delete(void *Memory) noexcept { std::free(Memory); }
void operator delete[](void *Memory) noexcept { std::free(Memory); }
void operator delete(void *Memory, std::size_t) noexcept { std::free(Memory); }
void operator delete[](void *Memory, std::size_t) noexcept { std::free(Memory); }
void operator delete(void *Memory, const std::nothrow_t &) noexcept { std::free(Memory); }
void operator delete[](void *Memory, const std::nothrow_t &) noexcept { std::free(Memory); }
void operator delete(void *Memory, std::align_val_t) noexcept
{
#if defined(_WIN32)
    _aligned_free(Memory);
#else
    std::free(Memory);
#endif
}
void operator delete[](void *Memory, std::align_val_t Alignment) noexcept { ::operator delete(Memory, Alignment); }
void operator delete(void *Memory, std::size_t, std::align_val_t Alignment) noexcept { ::operator delete(Memory, Alignment); }
void operator delete[](void *Memory, std::size_t, std::align_val_t Alignment) noexcept { ::operator delete[](Memory, Alignment); }
void operator delete(void *Memory, const std::nothrow_t &, std::align_val_t Alignment) noexcept { ::operator delete(Memory, Alignment); }
void operator delete[](void *Memory, const std::nothrow_t &, std::align_val_t Alignment) noexcept { ::operator delete[](Memory, Alignment); }
