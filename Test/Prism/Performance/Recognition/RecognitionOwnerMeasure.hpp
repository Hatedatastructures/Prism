/**
 * @file RecognitionOwnerMeasure.hpp
 * @brief owner compare 的真实并发测量与报告共享 helper。
 */

#pragma once

#include "RecognitionPerf.hpp"

#if defined(_WIN32)
#    if !defined(NOMINMAX)
#        define NOMINMAX
#    endif
#    include <windows.h>
#    include <psapi.h>
#endif

#include <condition_variable>
#include <exception>
#include <functional>
#include <mutex>
#include <thread>

namespace Prism::Recognition::Perf
{
    [[nodiscard]] inline auto ReadPlatformSample() -> PlatformSample
    {
#ifdef _WIN32
        FILETIME Creation{}, Exit{}, Kernel{}, User{};
        PlatformSample Result;
        if (GetProcessTimes(GetCurrentProcess(), &Creation, &Exit, &Kernel, &User) != 0)
        {
            ULARGE_INTEGER Cpu{};
            Cpu.LowPart = Kernel.dwLowDateTime;
            Cpu.HighPart = Kernel.dwHighDateTime;
            const auto KernelValue = Cpu.QuadPart;
            Cpu.LowPart = User.dwLowDateTime;
            Cpu.HighPart = User.dwHighDateTime;
            Result.Cpu100ns = KernelValue + Cpu.QuadPart;
        }
        using ReadMemoryFn = BOOL(WINAPI *)(HANDLE, PPROCESS_MEMORY_COUNTERS, DWORD);
        static const auto Module = LoadLibraryW(L"psapi.dll");
        static const auto ReadMemory = Module == nullptr
            ? nullptr : reinterpret_cast<ReadMemoryFn>(GetProcAddress(Module, "GetProcessMemoryInfo"));
        PROCESS_MEMORY_COUNTERS_EX Counters{};
        if (ReadMemory != nullptr && ReadMemory(GetCurrentProcess(),
            reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&Counters), sizeof(Counters)) != 0)
        {
            Result.CurrentRssBytes = Counters.WorkingSetSize;
            Result.CurrentCommitBytes = Counters.PrivateUsage;
            Result.LifetimePeakRssBytes = Counters.PeakWorkingSetSize;
        }
        return Result;
#else
        return {};
#endif
    }
    inline auto UpdateMaximum(
        std::atomic<std::uint64_t> &Target,
        const std::uint64_t Value) noexcept -> void
    {
        auto Current = Target.load(std::memory_order_relaxed);
        while (Current < Value &&
               !Target.compare_exchange_weak(Current, Value, std::memory_order_relaxed,
                                             std::memory_order_relaxed))
        {
        }
    }

    struct OwnerMeasurementReport final
    {
        std::string_view Owner;
        std::string_view Variant;
        std::size_t Round;
        std::size_t Concurrency;
        std::string_view Order;
        const OwnerTrace &Trace;
        std::string_view Contract;
        std::string_view SemanticModel;
        std::size_t ExpectedOperations;
        const OwnerMeasurement &Measurement;
    };

    /**
     * @brief 输出一个 owner 测量记录。
     * @param Report 已冻结的 owner、trace、窗口和指标快照；所有引用由调用方持有至返回。
     * @return preflight、操作和测量均有效时返回 true。
     */
    [[nodiscard]] auto PrintOwnerMeasurement(const OwnerMeasurementReport &Report) -> bool;

    [[nodiscard]] auto JsonString(std::string_view Value) -> std::string;

    struct OwnerMeasurementOptions final
    {
        std::size_t Concurrency;
        std::size_t OperationKinds;
        std::size_t RepeatCycles;
    };

    template <typename Factory>
    struct OwnerMeasurementRun final
    {
        std::size_t Concurrency;
        std::size_t OperationKinds;
        std::size_t Operations;
        Factory FactoryValue;
        OwnerMeasurement Result;
        std::vector<std::vector<std::uint64_t>> Timings;
        std::vector<std::size_t> Errors;
        std::vector<std::thread> Threads;
        std::mutex GateMutex;
        std::condition_variable Gate;
        std::size_t Ready{0};
        std::size_t Done{0};
        std::size_t Exited{0};
        bool Begin{false};
        bool EndRecorded{false};
        std::exception_ptr SetupFailure;
        std::atomic<bool> Sampling{true};
        std::atomic<bool> SampleBegin{false};
        std::atomic<bool> HeapWindowOpen{false};
        std::atomic<bool> SamplerReady{false};
        std::atomic<std::uint64_t> MaxRss{0};
        std::atomic<std::uint64_t> MaxCommit{0};
        std::atomic<std::uint64_t> MaxLifetimeRss{0};
        std::atomic<std::size_t> PlatformSamples{0};
        std::thread Sampler;
    };

    struct OwnerSamplerState final
    {
        std::atomic<bool> *Sampling;
        std::atomic<bool> *SampleBegin;
        std::atomic<bool> *HeapWindowOpen;
        std::atomic<bool> *SamplerReady;
        std::atomic<std::uint64_t> *MaxRss;
        std::atomic<std::uint64_t> *MaxCommit;
        std::atomic<std::uint64_t> *MaxLifetimeRss;
        std::atomic<std::size_t> *PlatformSamples;
    };

    inline auto RunOwnerSampler(const OwnerSamplerState State) -> void
    {
        State.SamplerReady->store(true, std::memory_order_release);
        while (!State.SampleBegin->load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
        while (State.Sampling->load(std::memory_order_acquire))
        {
            const auto Sample = ReadPlatformSample();
            if (State.HeapWindowOpen->load(std::memory_order_acquire))
            {
                State.PlatformSamples->fetch_add(1U, std::memory_order_relaxed);
                if (Sample.CurrentRssBytes)
                {
                    UpdateMaximum(*State.MaxRss, *Sample.CurrentRssBytes);
                }
                if (Sample.CurrentCommitBytes)
                {
                    UpdateMaximum(*State.MaxCommit, *Sample.CurrentCommitBytes);
                }
                if (Sample.LifetimePeakRssBytes)
                {
                    UpdateMaximum(*State.MaxLifetimeRss, *Sample.LifetimePeakRssBytes);
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    template <typename Factory>
    auto RunOwnerWorker(OwnerMeasurementRun<Factory> &Run, const std::size_t Index) -> void
    {
        auto &Local = Run.Timings[Index];
        using WorkerType = decltype(Run.FactoryValue());
        std::optional<WorkerType> Worker;
        try
        {
            Local.reserve(Run.Operations);
            Worker.emplace(Run.FactoryValue());
        }
        catch (...)
        {
            std::lock_guard Lock(Run.GateMutex);
            if (!Run.SetupFailure)
            {
                Run.SetupFailure = std::current_exception();
            }
            ++Run.Ready;
            ++Run.Done;
            ++Run.Exited;
            Run.Gate.notify_all();
            return;
        }
        {
            std::lock_guard Lock(Run.GateMutex);
            ++Run.Ready;
        }
        Run.Gate.notify_all();
        {
            std::unique_lock Lock(Run.GateMutex);
            Run.Gate.wait(Lock, [&Run] { return Run.Begin; });
            if (Run.SetupFailure)
            {
                ++Run.Done;
                ++Run.Exited;
                Run.Gate.notify_all();
                return;
            }
        }
        for (std::size_t Operation = 0; Operation < Run.Operations; ++Operation)
        {
            const auto Started = std::chrono::steady_clock::now();
            bool Correct = false;
            try
            {
                Correct = (*Worker)(Operation % Run.OperationKinds);
            }
            catch (...)
            {
                Correct = false;
            }
            const auto Finished = std::chrono::steady_clock::now();
            Local.push_back(static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(Finished - Started).count()));
            if (!Correct)
            {
                ++Run.Errors[Index];
            }
        }
        bool Clean = false;
        try
        {
            Clean = (*Worker).Cleanup();
        }
        catch (...)
        {
            Clean = false;
        }
        if (!Clean)
        {
            ++Run.Errors[Index];
        }
        {
            std::lock_guard Lock(Run.GateMutex);
            ++Run.Done;
        }
        Run.Gate.notify_all();
        {
            std::unique_lock Lock(Run.GateMutex);
            Run.Gate.wait(Lock, [&Run] { return Run.EndRecorded; });
        }
        {
            std::lock_guard ExitLock(Run.GateMutex);
            ++Run.Exited;
        }
        Run.Gate.notify_all();
    }

    template <typename Factory>
    auto LaunchOwnerWorkers(OwnerMeasurementRun<Factory> &Run) -> void
    {
        Run.Threads.reserve(Run.Concurrency);
        for (std::size_t Index = 0; Index < Run.Concurrency; ++Index)
        {
            Run.Threads.emplace_back(RunOwnerWorker<Factory>, std::ref(Run), Index);
        }
    }

    template <typename Factory>
    auto WaitForOwnerReady(OwnerMeasurementRun<Factory> &Run) -> void
    {
        std::unique_lock Lock(Run.GateMutex);
        Run.Gate.wait(Lock, [&Run] { return Run.Ready == Run.Concurrency; });
    }

    template <typename Factory>
    auto WaitForOwnerDone(OwnerMeasurementRun<Factory> &Run) -> void
    {
        std::unique_lock Lock(Run.GateMutex);
        Run.Gate.wait(Lock, [&Run] { return Run.Done == Run.Concurrency; });
    }

    template <typename Factory>
    auto WaitForOwnerExited(OwnerMeasurementRun<Factory> &Run) -> void
    {
        std::unique_lock Lock(Run.GateMutex);
        Run.Gate.wait(Lock, [&Run] { return Run.Exited == Run.Concurrency; });
    }

    template <typename Factory>
    auto JoinOwnerWorkers(OwnerMeasurementRun<Factory> &Run) -> void
    {
        for (auto &Thread : Run.Threads)
        {
            Thread.join();
        }
    }

    template <typename Factory>
    auto CompleteOwnerSetupFailure(OwnerMeasurementRun<Factory> &Run) -> OwnerMeasurement
    {
        Run.Result.PreflightOk = false;
        try
        {
            std::rethrow_exception(Run.SetupFailure);
        }
        catch (const std::exception &Error)
        {
            Run.Result.PreflightError = Error.what();
        }
        catch (...)
        {
            Run.Result.PreflightError = "unknown setup exception";
        }
        {
            std::lock_guard Lock(Run.GateMutex);
            Run.Begin = true;
        }
        Run.Gate.notify_all();
        WaitForOwnerDone(Run);
        WaitForOwnerExited(Run);
        JoinOwnerWorkers(Run);
        return std::move(Run.Result);
    }

    template <typename Factory>
    auto StartOwnerMeasurement(OwnerMeasurementRun<Factory> &Run)
        -> std::chrono::steady_clock::time_point
    {
        while (!Run.SamplerReady.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
        AllocationMeasurementEnabled.store(false, std::memory_order_release);
        (void)ReadPlatformSample();
        Run.Result.Before = ReadPlatformSample();
        ResetAllocationCounters();
        AllocationMeasurementEnabled.store(true, std::memory_order_release);
        if (Run.Result.Before.CurrentRssBytes)
        {
            Run.MaxRss.store(*Run.Result.Before.CurrentRssBytes);
        }
        if (Run.Result.Before.CurrentCommitBytes)
        {
            Run.MaxCommit.store(*Run.Result.Before.CurrentCommitBytes);
        }
        if (Run.Result.Before.LifetimePeakRssBytes)
        {
            Run.MaxLifetimeRss.store(*Run.Result.Before.LifetimePeakRssBytes);
        }
        const auto Started = std::chrono::steady_clock::now();
        {
            std::lock_guard Lock(Run.GateMutex);
            Run.Begin = true;
        }
        Run.HeapWindowOpen.store(true, std::memory_order_release);
        Run.SampleBegin.store(true, std::memory_order_release);
        Run.Gate.notify_all();
        return Started;
    }

    template <typename Factory>
    auto CompleteOwnerMeasurement(
        OwnerMeasurementRun<Factory> &Run,
        const std::chrono::steady_clock::time_point Started) -> OwnerMeasurement
    {
        AllocationMeasurementEnabled.store(false, std::memory_order_release);
        Run.HeapWindowOpen.store(false, std::memory_order_release);
        const auto Finished = std::chrono::steady_clock::now();
        Run.Result.After = ReadPlatformSample();
        Run.Result.WallNanoseconds = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(Finished - Started).count());
        if (Run.Result.After.CurrentRssBytes)
        {
            UpdateMaximum(Run.MaxRss, *Run.Result.After.CurrentRssBytes);
        }
        if (Run.Result.After.CurrentCommitBytes)
        {
            UpdateMaximum(Run.MaxCommit, *Run.Result.After.CurrentCommitBytes);
        }
        if (Run.Result.After.LifetimePeakRssBytes)
        {
            UpdateMaximum(Run.MaxLifetimeRss, *Run.Result.After.LifetimePeakRssBytes);
        }
        if (Run.Result.Before.CurrentRssBytes || Run.Result.After.CurrentRssBytes)
        {
            Run.Result.RoundPeakRssBytes = Run.MaxRss.load(std::memory_order_relaxed);
        }
        if (Run.Result.Before.CurrentCommitBytes || Run.Result.After.CurrentCommitBytes)
        {
            Run.Result.RoundPeakCommitBytes = Run.MaxCommit.load(std::memory_order_relaxed);
        }
        if (Run.Result.Before.LifetimePeakRssBytes || Run.Result.After.LifetimePeakRssBytes)
        {
            Run.Result.LifetimePeakRssBytes = Run.MaxLifetimeRss.load(std::memory_order_relaxed);
        }
        Run.Sampling.store(false, std::memory_order_release);
        {
            std::lock_guard Lock(Run.GateMutex);
            Run.EndRecorded = true;
        }
        Run.Gate.notify_all();
        WaitForOwnerExited(Run);
        Run.Sampler.join();
        Run.Result.PlatformSamples = Run.PlatformSamples.load(std::memory_order_relaxed);
        JoinOwnerWorkers(Run);
#ifdef _WIN32
        if (Run.Result.PlatformSamples == 0U)
        {
            Run.Result.PreflightOk = false;
            Run.Result.PreflightError = "no 1ms platform sample captured";
        }
#endif
        if (!Run.Result.PreflightOk)
        {
            AllocationMeasurementEnabled.store(true, std::memory_order_release);
            return std::move(Run.Result);
        }
        for (auto &Local : Run.Timings)
        {
            Run.Result.Operations += Local.size();
            Run.Result.Timings.insert(Run.Result.Timings.end(), Local.begin(), Local.end());
        }
        for (const auto Error : Run.Errors)
        {
            Run.Result.Errors += Error;
        }
        Run.Result.Allocations = ReadAllocationCounters();
        AllocationMeasurementEnabled.store(true, std::memory_order_release);
        return std::move(Run.Result);
    }

    template <typename Factory>
    [[nodiscard]] auto MeasureOwner(const OwnerMeasurementOptions &Options,
                                    Factory FactoryValue) -> OwnerMeasurement
    {
        OwnerMeasurementRun<Factory> Run{
            Options.Concurrency,
            Options.OperationKinds,
            Options.OperationKinds * Options.RepeatCycles,
            std::move(FactoryValue)};
        Run.Timings.resize(Options.Concurrency);
        Run.Result.Timings.reserve(Options.Concurrency * Run.Operations);
        Run.Errors.assign(Options.Concurrency, 0);
        LaunchOwnerWorkers(Run);
        WaitForOwnerReady(Run);
        if (Run.SetupFailure)
        {
            return CompleteOwnerSetupFailure(Run);
        }
        const OwnerSamplerState SamplerState{
            &Run.Sampling,
            &Run.SampleBegin,
            &Run.HeapWindowOpen,
            &Run.SamplerReady,
            &Run.MaxRss,
            &Run.MaxCommit,
            &Run.MaxLifetimeRss,
            &Run.PlatformSamples};
        Run.Sampler = std::thread(RunOwnerSampler, SamplerState);
        const auto Started = StartOwnerMeasurement(Run);
        WaitForOwnerDone(Run);
        return CompleteOwnerMeasurement(Run, Started);
    }
}
