/**
 * @file RegistryCompareSampling.cpp
 * @brief 注册表候选的并发采样与资源观测实现。
 */

#include "RegistryCompareSampling.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <latch>
#include <limits>
#include <memory>
#include <new>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <vector>
#include <string_view>

#if defined(_WIN32)
#    if !defined(NOMINMAX)
#        define NOMINMAX
#    endif
#    include <windows.h>
#    include <malloc.h>
#    include <psapi.h>
#endif

namespace Prism::Runtime::Perf
{

    auto MakeModel(ModelKind Kind, std::size_t Executors) -> std::unique_ptr<IModel>;
    auto Setup(IModel &Model, const Options &Settings,
               std::array<LaneState, CompareLaneCount> &Lanes) -> void;
    auto ExpectedSnapshot(const std::array<LaneState, CompareLaneCount> &Lanes)
        -> SnapshotMap;
    auto SameSnapshot(const SnapshotMap &Left, const SnapshotMap &Right) -> bool;
    auto MarkInvalid(Statistics &Stats, std::atomic<bool> &Invalid,
                     InvalidReason Reason) -> void;

    namespace
    {
        using Clock = std::chrono::steady_clock;
        std::atomic<bool> TrackAllocations{false};
        std::atomic<std::uint64_t> AllocationCount{0};
        std::atomic<std::uint64_t> AllocationBytes{0};
        std::atomic<std::uint64_t> AlignedAllocationCount{0};
        std::atomic<std::uint64_t> AlignedAllocationBytes{0};
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
        /** @brief 只供冷路径验证暂停采样读；释放是幂等的，清理不会等待未释放的探针。 */
        struct ProcessSampleProbe final
        {
            std::atomic<bool> Entered{false};
            std::atomic<bool> Released{false};
            std::mutex Mutex;
            std::condition_variable Condition;
            auto Read() -> std::optional<ProcessMetrics>
            {
                Entered.store(true, std::memory_order_release);
                Entered.notify_all();
                Condition.notify_all();
                Released.wait(false);
                return ProcessMetrics{1, 2, 11, 13};
            }
            auto Release() noexcept -> void { Released.store(true); Released.notify_all(); }
            auto WaitUntilEntered() -> bool
            {
                std::unique_lock Lock(Mutex);
                return Condition.wait_for(
                    Lock, std::chrono::seconds{1},
                    [this] { return Entered.load(std::memory_order_acquire); });
            }
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
            std::mutex *WindowMutex;
            ProcessSampleProbe *Probe{nullptr};
        };
        auto RunProcessMetricSampler(const ProcessSamplerState State) -> void
        {
            State.Ready->count_down();
            while (!State.Stop->load(std::memory_order_acquire))
            {
                if (State.Active->load(std::memory_order_acquire))
                {
                    const auto SampleBegin = Clock::now().time_since_epoch().count();
                    const auto Begin = State.BeginNanoseconds->load(std::memory_order_acquire);
                    if (const auto Metrics = State.Probe ? State.Probe->Read() : CurrentProcessMetrics();
                        Metrics && Metrics->WorkingSetBytes && Metrics->CommitBytes)
                    {
                        const auto SampleEnd = Clock::now().time_since_epoch().count();
                        std::lock_guard Lock(*State.WindowMutex);
                        const auto End = State.EndNanoseconds->load(std::memory_order_acquire);
                        if (State.Active->load(std::memory_order_acquire) &&
                            Begin != 0 && SampleBegin >= Begin &&
                            (End == 0 || SampleEnd <= End))
                        {
                            UpdatePeak(*State.PeakWorkingSet, *Metrics->WorkingSetBytes);
                            UpdatePeak(*State.PeakCommit, *Metrics->CommitBytes);
                            State.Samples->fetch_add(1, std::memory_order_relaxed);
                        }
                    }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
            }
        }
        class ProcessMetricSampler final
        {
        public:
            explicit ProcessMetricSampler(ProcessSamplerState State, const bool FailStart = false)
                : State_(State)
            {
                if (FailStart)
                    throw std::system_error(std::make_error_code(std::errc::resource_unavailable_try_again));
                Thread_ = std::thread(RunProcessMetricSampler, State_);
                State_.Ready->wait();
            }
            ~ProcessMetricSampler() { Stop(); }
            auto Stop() noexcept -> void
            {
                State_.Stop->store(true, std::memory_order_release);
                if (State_.Probe) State_.Probe->Release();
                if (Thread_.joinable()) Thread_.join();
            }
        private:
            ProcessSamplerState State_;
            std::thread Thread_;
        };
        struct SamplerPreflightState final
        {
            std::atomic<bool> Active{false};
            std::atomic<bool> Stop{false};
            std::latch Ready{1};
            std::atomic<std::int64_t> Begin{0};
            std::atomic<std::int64_t> End{0};
            std::atomic<std::uint64_t> PeakWorkingSet{0};
            std::atomic<std::uint64_t> PeakCommit{0};
            std::atomic<std::uint64_t> Samples{0};
            std::mutex WindowMutex;
            ProcessSampleProbe Probe;
            ProcessSamplerState State;
            SamplerPreflightState()
                : State{&Active, &Stop, &Ready, &Begin, &End, &PeakWorkingSet,
                        &PeakCommit, &Samples, &WindowMutex, &Probe}
            {
            }
        };
        auto Percentile(std::vector<std::uint64_t> Values, const std::size_t Numerator,
                        const std::size_t Denominator) -> std::uint64_t
        {
            std::sort(Values.begin(), Values.end());
            const auto Rank = (Values.size() * Numerator + Denominator - 1) / Denominator;
            return Values[std::max<std::size_t>(1, Rank) - 1];
        }
        struct WorkerContext final
        {
            IModel &Model;
            const Trace &TraceValue;
            std::array<LaneState, CompareLaneCount> &Lanes;
            std::vector<std::uint64_t> &Latencies;
            std::vector<Statistics> &Stats;
            std::atomic<bool> &Invalid;
            std::size_t Workers{0};
            std::size_t MaxSessions{0};
        };
        auto RunWorker(WorkerContext &Context, const std::size_t Worker) -> void
        {
            std::array<ExecutionContext *, CompareLaneCount> LaneContexts{};
            std::array<ExecutionContext, CompareLaneCount> Contexts = {
                ExecutionContext{Context.Model, Context.Lanes[0], Context.Stats[Worker],
                                 Context.Invalid, Context.MaxSessions},
                ExecutionContext{Context.Model, Context.Lanes[1], Context.Stats[Worker],
                                 Context.Invalid, Context.MaxSessions},
                ExecutionContext{Context.Model, Context.Lanes[2], Context.Stats[Worker],
                                 Context.Invalid, Context.MaxSessions},
                ExecutionContext{Context.Model, Context.Lanes[3], Context.Stats[Worker],
                                 Context.Invalid, Context.MaxSessions}};
            for (std::size_t Lane = 0; Lane < CompareLaneCount; ++Lane)
            {
                LaneContexts[Lane] = &Contexts[Lane];
            }
            for (std::size_t Index = 0; Index < Context.TraceValue.Work.size(); ++Index)
            {
                const auto &Operation = Context.TraceValue.Work[Index];
                if (Operation.Lane % Context.Workers != Worker)
                {
                    continue;
                }
                const auto Start = Clock::now();
                Apply(Operation, *LaneContexts[Operation.Lane]);
                const auto Elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                          Clock::now() - Start)
                                          .count();
                Context.Latencies[Index] = static_cast<std::uint64_t>(Elapsed) + 1;
            }
        }
        /** @brief 只在预检注入启动/执行失败，并记录真实线程的退出与 join。 */
        struct SamplingWorkerProbe final
        {
            std::optional<std::size_t> FailThread;
            std::optional<std::size_t> FailWorker;
            std::atomic<std::size_t> Started{0}, Exited{0};
            std::size_t Joined{0};
        };
        class SamplingWorkers final
        {
        public:
            explicit SamplingWorkers(WorkerContext &Context, SamplingWorkerProbe *Probe = nullptr)
                : Context_(Context), Probe_(Probe), Ready_(Context.Workers), Done_(Context.Workers),
                  Failures_(Context.Workers)
            {
                Threads_.reserve(Context.Workers);
                try
                {
                    for (std::size_t Index = 0; Index < Context.Workers; ++Index)
                    {
                        if (Probe_ && Probe_->FailThread == Index)
                            throw std::system_error(std::make_error_code(std::errc::resource_unavailable_try_again));
                        Threads_.emplace_back(&SamplingWorkers::Run, this, Index);
                    }
                }
                catch (...)
                {
                    const auto Missing = static_cast<std::ptrdiff_t>(Context.Workers - Threads_.size());
                    if (Missing != 0) { Ready_.count_down(Missing); Done_.count_down(Missing); }
                    Cancel();
                    Join();
                    throw;
                }
            }
            ~SamplingWorkers() { Cancel(); Join(); }
            auto WaitReady() const -> void { Ready_.wait(); }
            auto Start() noexcept -> void { Go_.store(true, std::memory_order_release); Go_.notify_all(); }
            auto WaitDone() const -> void { Done_.wait(); }
            auto Join() noexcept -> void
            {
                for (auto &Thread : Threads_)
                    if (Thread.joinable()) { Thread.join(); if (Probe_) ++Probe_->Joined; }
            }
            auto RethrowFailure() const -> void
            {
                for (const auto &Failure : Failures_)
                    if (Failure) std::rethrow_exception(Failure);
            }
        private:
            auto Cancel() noexcept -> void { Aborted_.store(true, std::memory_order_release); Start(); }
            auto Run(const std::size_t Index) noexcept -> void
            {
                if (Probe_) Probe_->Started.fetch_add(1, std::memory_order_relaxed);
                Ready_.count_down();
                Go_.wait(false);
                try
                {
                    if (!Aborted_.load(std::memory_order_acquire))
                    {
                        if (Probe_ && Probe_->FailWorker == Index)
                            throw std::runtime_error("injected sampling worker failure");
                        RunWorker(Context_, Index);
                    }
                }
                catch (...) { Failures_[Index] = std::current_exception(); }
                Done_.count_down();
                if (Probe_) Probe_->Exited.fetch_add(1, std::memory_order_relaxed);
            }
            WorkerContext &Context_;
            SamplingWorkerProbe *Probe_;
            std::latch Ready_, Done_;
            std::atomic<bool> Go_{false}, Aborted_{false};
            std::vector<std::exception_ptr> Failures_;
            std::vector<std::thread> Threads_;
        };
        /** @brief 持有一次正式测量的进程窗口、采样器和边界快照。 */
        struct MeasurementWindow final
        {
            std::atomic<bool> Active{false};
            std::atomic<bool> Stop{false};
            std::latch Ready{1};
            std::atomic<std::int64_t> BeginNanoseconds{0};
            std::atomic<std::int64_t> EndNanoseconds{0};
            std::atomic<std::uint64_t> PeakWorkingSet{0};
            std::atomic<std::uint64_t> PeakCommit{0};
            std::atomic<std::uint64_t> Samples{0};
            std::mutex WindowMutex;
            ProcessMetricSampler Sampler;
            Clock::time_point BeginTime{};
            Clock::time_point EndTime{};
            std::optional<std::uint64_t> RssBeforeValue;
            std::optional<std::uint64_t> RssAfterValue;
            std::optional<ProcessMetrics> ProcessBeforeValue;
            std::optional<ProcessMetrics> ProcessAfterValue;
            MeasurementWindow()
                : Sampler(ProcessSamplerState{&Active, &Stop, &Ready, &BeginNanoseconds,
                                              &EndNanoseconds, &PeakWorkingSet, &PeakCommit,
                                              &Samples, &WindowMutex, nullptr})
            {
            }
            auto Prepare() -> void
            {
                RssBeforeValue = CurrentRssBytes();
                ProcessBeforeValue = CurrentProcessMetrics();
                AllocationCount.store(0, std::memory_order_relaxed);
                AllocationBytes.store(0, std::memory_order_relaxed);
                AlignedAllocationCount.store(0, std::memory_order_relaxed);
                AlignedAllocationBytes.store(0, std::memory_order_relaxed);
            }
            auto Begin() -> void
            {
                TrackAllocations.store(true, std::memory_order_release);
                BeginTime = Clock::now();
                BeginNanoseconds.store(BeginTime.time_since_epoch().count(),
                                       std::memory_order_release);
                Active.store(true, std::memory_order_release);
            }
            auto Close() -> void
            {
                TrackAllocations.store(false, std::memory_order_release);
                {
                    std::lock_guard Lock(WindowMutex);
                    EndTime = Clock::now();
                    EndNanoseconds.store(EndTime.time_since_epoch().count(),
                                         std::memory_order_release);
                    Active.store(false, std::memory_order_release);
                }
                RssAfterValue = CurrentRssBytes();
                ProcessAfterValue = CurrentProcessMetrics();
                Sampler.Stop();
            }
        };
        struct FinalObservation final
        {
            SnapshotMap Snapshot;
            std::size_t Size{0};
            std::size_t Pending{0};
            HookCounts Hooks;
            std::vector<std::uint64_t> Timings;
        };
        auto BuildTimings(const std::vector<std::uint64_t> &Latencies)
            -> std::vector<std::uint64_t>
        {
            std::vector<std::uint64_t> Timings;
            Timings.reserve(Latencies.size());
            for (const auto Value : Latencies)
            {
                if (Value != 0)
                {
                    Timings.push_back(Value);
                }
            }
            return Timings;
        }
        /** @brief 收集静态结果并执行窗口结束后的完整状态校验。 */
        struct SampleCollector final
        {
            IModel &Model;
            const SampleRequest &Request;
            const std::array<LaneState, CompareLaneCount> &Lanes;
            const std::vector<std::uint64_t> &Latencies;
            std::vector<Statistics> &Stats;
            std::atomic<bool> &Invalid;
            const MeasurementWindow &Window;
            auto ValidateFinalState() -> FinalObservation
            {
                const auto Expected = ExpectedSnapshot(Lanes);
                FinalObservation Observation;
                Observation.Snapshot = Model.Snapshot();
                Observation.Size = Model.Size();
                Observation.Pending = Model.PendingRemovals();
                Observation.Hooks = Model.HookSnapshot();
                auto &FinalStats = Stats.front();
                if (!SameSnapshot(Observation.Snapshot, Expected))
                {
                    MarkInvalid(FinalStats, Invalid, InvalidReason::FinalSnapshot);
                }
                if (Observation.Size != Expected.size())
                {
                    MarkInvalid(FinalStats, Invalid, InvalidReason::FinalSize);
                }
                if (Observation.Pending != 0)
                {
                    MarkInvalid(FinalStats, Invalid, InvalidReason::FinalPending);
                }
                for (const auto &Lane : Lanes)
                {
                    if (Lane.Shutdown)
                    {
                        MarkInvalid(FinalStats, Invalid, InvalidReason::FinalLifecycle);
                    }
                    for (const auto &[Id, TokenValue] : Lane.Active)
                    {
                        if (!TokenValue || TokenValue->Id != Id ||
                            !Model.TokenActive(TokenValue))
                        {
                            MarkInvalid(FinalStats, Invalid, InvalidReason::TokenState);
                        }
                    }
                    for (const auto &[Id, TokenValue] : Lane.Stale)
                    {
                        if (TokenValue && Model.TokenActive(TokenValue))
                        {
                            MarkInvalid(FinalStats, Invalid, InvalidReason::TokenState);
                        }
                    }
                }
                Observation.Timings = BuildTimings(Latencies);
                return Observation;
            }
            auto Collect() -> Sample
            {
                auto Observation = ValidateFinalState();
                std::uint64_t CorrectnessHash = HashSnapshot(Observation.Snapshot);
                Mix(CorrectnessHash, Observation.Size);
                Mix(CorrectnessHash, Observation.Pending);
                std::uint64_t ObservationHash = 14695981039346656037ull;
                for (const auto &StatsValue : Stats)
                {
                    Mix(ObservationHash, StatsValue.Checksum);
                    Mix(ObservationHash, StatsValue.SnapshotChecksum);
                }
                Mix(ObservationHash, Observation.Hooks.Errors);
                Mix(ObservationHash, Observation.Hooks.Metrics);
                Model.Shutdown();
                Sample Result;
                Result.Model = Request.Kind;
                Result.Round = Request.Round;
                Result.Operations = Observation.Timings.size();
                Result.TraceHash = Request.TraceValue.Hash;
                Result.CorrectnessHash = CorrectnessHash;
                Result.ObservationHash = ObservationHash;
                Result.FinalSize = Observation.Size;
                Result.Pending = Observation.Pending;
                Result.Allocations = AllocationCount.load(std::memory_order_relaxed);
                Result.AllocationBytesValue = AllocationBytes.load(std::memory_order_relaxed);
                Result.AlignedAllocations = AlignedAllocationCount.load(std::memory_order_relaxed);
                Result.AlignedAllocationBytesValue =
                    AlignedAllocationBytes.load(std::memory_order_relaxed);
                Result.DurationSeconds =
                    std::chrono::duration<double>(Window.EndTime - Window.BeginTime).count();
                Result.Invalid = Invalid.load(std::memory_order_acquire);
                for (const auto &StatsValue : Stats)
                {
                    for (std::size_t Index = 0; Index < InvalidReasonCount; ++Index)
                    {
                        Result.InvalidReasons[Index] += StatsValue.InvalidReasons[Index];
                    }
                }
                Result.P50 = Percentile(Observation.Timings, 50, 100);
                Result.P95 = Percentile(Observation.Timings, 95, 100);
                Result.P99 = Percentile(Observation.Timings, 99, 100);
                Result.RssBefore = Window.RssBeforeValue;
                Result.RssAfter = Window.RssAfterValue;
                Result.ProcessBefore = Window.ProcessBeforeValue;
                Result.ProcessAfter = Window.ProcessAfterValue;
                if (Window.Samples.load(std::memory_order_relaxed) != 0)
                {
                    Result.PeakWorkingSetBytes =
                        Window.PeakWorkingSet.load(std::memory_order_relaxed);
                    Result.PeakCommitBytes = Window.PeakCommit.load(std::memory_order_relaxed);
                    Result.ProcessMetricSamples = Window.Samples.load(std::memory_order_relaxed);
                }
                return Result;
            }
        };
        auto RequireSamplingContract(const bool Condition, const char *Message) -> void
        {
            if (!Condition)
            {
                throw std::runtime_error(Message);
            }
        }
        auto ValidatePartialWorkerStart(WorkerContext &Context) -> void
        {
            SamplingWorkerProbe Probe;
            Probe.FailThread = 2;
            bool Rejected = false;
            try
            {
                SamplingWorkers Workers(Context, &Probe);
            }
            catch (const std::system_error &Error)
            {
                Rejected = Error.code() ==
                           std::make_error_code(std::errc::resource_unavailable_try_again);
            }
            RequireSamplingContract(Rejected && Probe.Started.load() == 2 &&
                                         Probe.Exited.load() == 2 && Probe.Joined == 2,
                                     "sampling partial startup rollback failed");
        }
        auto ValidateWorkerFailure(WorkerContext &Context) -> void
        {
            SamplingWorkerProbe Probe;
            Probe.FailWorker = 1;
            SamplingWorkers Workers(Context, &Probe);
            Workers.WaitReady();
            Workers.Start();
            Workers.WaitDone();
            Workers.Join();
            bool Failed = false;
            try
            {
                Workers.RethrowFailure();
            }
            catch (const std::runtime_error &Error)
            {
                Failed = std::string_view(Error.what()) == "injected sampling worker failure";
            }
            RequireSamplingContract(Failed && Probe.Started.load() == Context.Workers &&
                                         Probe.Exited.load() == Context.Workers &&
                                         Probe.Joined == Context.Workers,
                                     "sampling worker failure cleanup failed");
        }
        auto ValidateSamplerCreationFailure() -> void
        {
            SamplerPreflightState Preflight;
            bool Rejected = false;
            try
            {
                ProcessMetricSampler Sampler(Preflight.State, true);
            }
            catch (const std::system_error &Error)
            {
                Rejected = Error.code() ==
                           std::make_error_code(std::errc::resource_unavailable_try_again);
            }
            RequireSamplingContract(Rejected && !Preflight.Stop.load(std::memory_order_acquire) &&
                                         Preflight.Samples.load(std::memory_order_relaxed) == 0,
                                     "process sampler creation failure contract failed");
        }
        auto ValidateSamplerEndBoundary() -> void
        {
            SamplerPreflightState Preflight;
            ProcessMetricSampler Sampler(Preflight.State);
            const auto BeginTime = Clock::now();
            Preflight.Begin.store(BeginTime.time_since_epoch().count(),
                                  std::memory_order_release);
            Preflight.Active.store(true, std::memory_order_release);
            RequireSamplingContract(Preflight.Probe.WaitUntilEntered(),
                                     "process sampler did not enter blocking probe");
            Preflight.End.store(Clock::now().time_since_epoch().count(),
                                std::memory_order_release);
            Sampler.Stop();
            Preflight.Active.store(false, std::memory_order_release);
            RequireSamplingContract(Preflight.Probe.Released.load(std::memory_order_acquire) &&
                                         Preflight.Samples.load(std::memory_order_relaxed) == 0 &&
                                         Preflight.PeakWorkingSet.load(std::memory_order_relaxed) == 0 &&
                                         Preflight.PeakCommit.load(std::memory_order_relaxed) == 0,
                                     "process sampler crossed measurement end");
        }
    } // namespace
    auto ValidateSamplingLifecycle() -> void
    {
        auto Model = MakeModel(ModelKind::CurrentCow, 3);
        Trace TraceValue;
        std::array<LaneState, CompareLaneCount> Lanes;
        std::vector<std::uint64_t> Latencies;
        std::vector<Statistics> Stats(3);
        std::atomic<bool> Invalid{false};
        WorkerContext Context{*Model, TraceValue, Lanes, Latencies, Stats,
                              Invalid, 3, 1};
        ValidatePartialWorkerStart(Context);
        ValidateWorkerFailure(Context);
        ValidateSamplerCreationFailure();
        ValidateSamplerEndBoundary();
        Model->Shutdown();
    }
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
            AllocationBytes.fetch_add(static_cast<std::uint64_t>(Size),
                                      std::memory_order_relaxed);
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
    auto ValidateAllocationInstrumentation() -> void
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
        ::operator delete(Ordinary);
        ::operator delete[](OrdinaryArray);
        ::operator delete(Aligned, std::align_val_t{Alignment});
        ::operator delete[](AlignedArray, std::align_val_t{Alignment});
        const auto ExpectedOrdinaryBytes =
            static_cast<std::uint64_t>(OrdinaryBytes + OrdinaryArrayBytes);
        const auto ExpectedAlignedBytes =
            static_cast<std::uint64_t>(AlignedBytes + AlignedArrayBytes);
        const auto AlignmentValid = reinterpret_cast<std::uintptr_t>(Aligned) % Alignment == 0U &&
                                    reinterpret_cast<std::uintptr_t>(AlignedArray) % Alignment == 0U;
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
    auto RunSample(const SampleRequest &Request) -> Sample
    {
        const auto &Settings = Request.Settings;
        const auto &TraceValue = Request.TraceValue;
        auto Model = MakeModel(Request.Kind, Settings.Executors);
        std::array<LaneState, CompareLaneCount> Lanes;
        Setup(*Model, Settings, Lanes);
        std::vector<std::uint64_t> Latencies(TraceValue.Work.size());
        std::vector<Statistics> Stats(Settings.Executors);
        std::atomic<bool> Invalid{false};
        WorkerContext Context{*Model, TraceValue, Lanes, Latencies, Stats,
                              Invalid, Settings.Executors, Settings.ActiveSessions};
        SamplingWorkers Workers(Context);
        Workers.WaitReady();
        MeasurementWindow Window;
        Window.Prepare();
        Window.Begin();
        Workers.Start();
        Workers.WaitDone();
        Window.Close();
        Workers.Join();
        Workers.RethrowFailure();
        return SampleCollector{*Model, Request, Lanes, Latencies, Stats, Invalid, Window}.Collect();
    }
} // namespace Prism::Runtime::Perf
