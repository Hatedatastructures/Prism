/**
 * @file RootMetrics.hpp
 * @brief 真实 Mux root 测量窗口的进程指标 owner。
 * @details 独立采样线程只在窗口激活时记录进程 CPU 时间、工作集与提交内存；
 *          窗口与停止标记负责跨线程同步，真实 root 生命周期由 fixture 管理。
 */
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <psapi.h>
#endif

namespace Prism::Testing::MuxRealRoot
{
    /** @brief 当前进程的 CPU 时间与内存观察值。 */
    struct RealProcessMetrics final
    {
        std::uint64_t UserTime100ns{0};
        std::uint64_t KernelTime100ns{0};
        std::uint64_t WorkingSetBytes{0};
        std::uint64_t CommitBytes{0};
    };

    /** @brief 读取当前进程观测值；平台不支持或查询失败时返回空。 */
    inline auto CurrentRealProcessMetrics() -> std::optional<RealProcessMetrics>
    {
#if defined(_WIN32)
        FILETIME Creation{};
        FILETIME Exit{};
        FILETIME Kernel{};
        FILETIME User{};
        PROCESS_MEMORY_COUNTERS_EX Counters{};
        using GetProcessMemoryInfoFunction = BOOL(WINAPI *)(HANDLE, PPROCESS_MEMORY_COUNTERS, DWORD);
        static const auto Module = LoadLibraryW(L"psapi.dll");
        static const auto ReadMemoryInfo = [ModuleValue = Module]() -> GetProcessMemoryInfoFunction
        {
            if (ModuleValue == nullptr) return nullptr;
            return reinterpret_cast<GetProcessMemoryInfoFunction>(
                GetProcAddress(ModuleValue, "GetProcessMemoryInfo"));
        }();
        if (GetProcessTimes(GetCurrentProcess(), &Creation, &Exit, &Kernel, &User) == 0 ||
            ReadMemoryInfo == nullptr ||
            ReadMemoryInfo(GetCurrentProcess(),
                           reinterpret_cast<PROCESS_MEMORY_COUNTERS *>(&Counters),
                           sizeof(Counters)) == 0)
        {
            return std::nullopt;
        }
        const auto ToValue = [](const FILETIME Value) -> std::uint64_t
        {
            return (static_cast<std::uint64_t>(Value.dwHighDateTime) << 32U) |
                   static_cast<std::uint64_t>(Value.dwLowDateTime);
        };
        return RealProcessMetrics{ToValue(User), ToValue(Kernel),
                                  static_cast<std::uint64_t>(Counters.WorkingSetSize),
                                  static_cast<std::uint64_t>(Counters.PrivateUsage)};
#else
        return std::nullopt;
#endif
    }

    /** @brief 以原子比较更新并发采样得到的最大观测值。 */
    inline auto UpdateRealPeak(std::atomic<std::uint64_t> &Peak, const std::uint64_t Value) -> void
    {
        auto Previous = Peak.load(std::memory_order_relaxed);
        while (Value > Previous &&
               !Peak.compare_exchange_weak(Previous, Value, std::memory_order_relaxed))
        {
        }
    }

    /** @brief 负责协调多个真实 Mux 测量 lane 与进程采样线程。 */
    struct RealMeasureWindow final
    {
        explicit RealMeasureWindow(const std::size_t LaneCount) : Lanes(LaneCount) {}

        const std::size_t Lanes;
        std::atomic<std::size_t> ReadyOrFailed{0};
        std::atomic<std::size_t> Ready{0};
        std::atomic<std::size_t> MeasureCompleted{0};
        std::atomic<std::size_t> MeasureFailed{0};
        std::atomic<std::size_t> ExitedLanes{0};
        std::atomic<bool> Active{false};
        std::atomic<bool> StopSampler{false};
        std::atomic<bool> SamplerReady{false};
        std::atomic<bool> SamplerFailed{false};
        std::atomic<bool> SamplerExited{false};
        std::atomic<std::int64_t> BeginNanoseconds{0};
        std::atomic<std::int64_t> EndNanoseconds{0};
        std::atomic<std::uint64_t> PeakWorkingSet{0};
        std::atomic<std::uint64_t> PeakCommit{0};
        std::atomic<std::uint64_t> Samples{0};
        std::mutex GateMutex;
        std::condition_variable GateChanged;
        std::optional<RealProcessMetrics> Before;
        std::optional<RealProcessMetrics> After;
    };

    /** @brief 唤醒等待测量窗口状态变化的 owner。 */
    inline auto NotifyRealMeasureWindow(const std::shared_ptr<RealMeasureWindow> &Window) -> void
    {
        Window->GateChanged.notify_all();
    }

    /** @brief 在专用采样线程中记录窗口内的进程峰值并通知最终退出。 */
    inline auto RunRealMetricSampler(const std::shared_ptr<RealMeasureWindow> &Window) -> void
    {
        try
        {
            (void)CurrentRealProcessMetrics();
            Window->SamplerReady.store(true, std::memory_order_release);
            NotifyRealMeasureWindow(Window);
            while (!Window->StopSampler.load(std::memory_order_acquire))
            {
                if (Window->Active.load(std::memory_order_acquire))
                {
                    const auto SampleBegin = std::chrono::steady_clock::now()
                                                 .time_since_epoch()
                                                 .count();
                    const auto Begin = Window->BeginNanoseconds.load(std::memory_order_acquire);
                    if (const auto Metrics = CurrentRealProcessMetrics())
                    {
                        const auto SampleEnd = std::chrono::steady_clock::now()
                                                   .time_since_epoch()
                                                   .count();
                        const auto End = Window->EndNanoseconds.load(std::memory_order_acquire);
                        if (Begin != 0 && SampleBegin >= Begin &&
                            (End == 0 || SampleEnd <= End))
                        {
                            UpdateRealPeak(Window->PeakWorkingSet, Metrics->WorkingSetBytes);
                            UpdateRealPeak(Window->PeakCommit, Metrics->CommitBytes);
                            Window->Samples.fetch_add(1, std::memory_order_relaxed);
                        }
                    }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
            }
            Window->SamplerExited.store(true, std::memory_order_release);
            NotifyRealMeasureWindow(Window);
        }
        catch (...)
        {
            Window->SamplerFailed.store(true, std::memory_order_release);
            Window->SamplerReady.store(true, std::memory_order_release);
            Window->SamplerExited.store(true, std::memory_order_release);
            NotifyRealMeasureWindow(Window);
        }
    }

}
