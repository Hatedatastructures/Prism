/**
 * @file TokenBucketCompare.cpp
 * @brief TokenBucket 正常路径同轨基线 CLI。
 * @details 固定时间点的 1/2/4 线程取令牌轨迹与单线程未跨 32 位边界的补发轨迹
 *          使用同一套预生成输入。该工具只用于修复前后的正常路径开销对照，
 *          不把性能结果当作跨界正确性证明。
 */

#include <Preview/Foundation/Utility/Rate/TokenBucket.hpp>

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
#include <mutex>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#if defined(_WIN32)
#    if !defined(NOMINMAX)
#        define NOMINMAX
#    endif
#    include <malloc.h>
#    include <windows.h>
#    include <psapi.h>
#elif defined(__linux__)
#    include <unistd.h>
#endif

namespace Preview::Rate::Perf
{

    namespace
    {

        using Clock = std::chrono::steady_clock;
        using Bucket = Preview::Rate::TokenBucket;

        constexpr std::uint64_t FnvOffset = 14695981039346656037ull;
        constexpr std::uint64_t FnvPrime = 1099511628211ull;
        constexpr std::uint64_t Uint32Max = std::numeric_limits<std::uint32_t>::max();
        constexpr std::size_t DefaultOperations = 100'000;
        constexpr std::size_t MaxOperations = 5'000'000;
        constexpr std::size_t MaxRounds = 100;
        constexpr std::uint64_t MaxRefillIntervalMs = 1'000'000'000;

        std::atomic<bool> TrackAllocations{false};
        std::atomic<std::uint64_t> OrdinaryAllocationCount{0};
        std::atomic<std::uint64_t> OrdinaryAllocationBytes{0};
        std::atomic<std::uint64_t> AlignedAllocationCount{0};
        std::atomic<std::uint64_t> AlignedAllocationBytes{0};

        struct Arguments final
        {
            int Count;
            char **Values;
        };

        struct Options final
        {
            std::size_t Threads{1};
            std::size_t Operations{DefaultOperations};
            std::size_t Capacity{0};
            std::uint64_t Now{0};
            std::uint64_t RefillIntervalMs{100};
            std::size_t Rounds{5};
            bool ValidateOnly{false};
        };

        struct Request final
        {
            std::uint64_t Now;
            std::size_t Count;
        };

        struct Trace final
        {
            std::vector<Request> Fixed;
            std::vector<Request> Refill;
            std::uint64_t FixedHash{FnvOffset};
            std::uint64_t RefillHash{FnvOffset};
            std::uint64_t CombinedHash{FnvOffset};
            std::size_t RequiredTokens{0};
            std::size_t Capacity{0};
        };

        struct ScenarioPlan final
        {
            std::string_view Name;
            std::span<const Request> Requests;
            std::size_t Threads;
            std::size_t Capacity;
            std::size_t ExpectedAvailable;
            std::uint64_t RefillIntervalMs;
            std::uint64_t TraceHash;
        };

        enum class FailureKind : std::uint8_t
        {
            Start,
            Worker,
        };

        struct FailurePlan final
        {
            FailureKind Kind;
            std::size_t Index{0};
        };

        struct LifecycleState final
        {
            std::atomic<bool> Stop{false};
            std::atomic<std::size_t> Failures{0};
            std::mutex Mutex;
            std::exception_ptr First;
        };

        struct Measurement final
        {
            std::size_t Round{0};
            std::uint64_t Attempts{0};
            std::uint64_t Successes{0};
            std::uint64_t Failures{0};
            std::uint64_t Available{0};
            std::uint64_t DurationNanoseconds{0};
            std::uint64_t P95Nanoseconds{0};
            double Throughput{0};
            std::uint64_t OrdinaryAllocations{0};
            std::uint64_t OrdinaryAllocationBytes{0};
            std::uint64_t AlignedAllocations{0};
            std::uint64_t AlignedAllocationBytes{0};
            std::optional<std::uint64_t> RssBefore;
            std::optional<std::uint64_t> RssAfter;
            bool Invalid{false};
            const char *InvalidReason{"none"};
            bool ThreadsJoined{false};
            std::size_t FailureCount{0};
            bool FirstFailureObserved{false};
        };

        struct WorkerContext final
        {
            Bucket &BucketValue;
            std::span<const Request> Requests;
            std::span<std::uint64_t> Latencies;
            std::atomic<std::uint64_t> &Successes;
            std::atomic<std::uint64_t> &Failures;
            std::size_t WorkerIndex;
            std::size_t WorkerCount;
            std::latch &Ready;
            std::latch &Start;
            std::latch &Done;
            LifecycleState &Lifecycle;
            const FailurePlan *Plan;
        };

        auto Require(const bool Condition, const std::string_view Message) -> void
        {
            if (!Condition)
            {
                throw std::invalid_argument(std::string{Message});
            }
        }

        auto ParseUnsigned(const std::string_view Text) -> std::uint64_t
        {
            std::uint64_t Value = 0;
            const auto Result = std::from_chars(Text.data(), Text.data() + Text.size(), Value);
            Require(Result.ec == std::errc{} && Result.ptr == Text.data() + Text.size(),
                    "invalid unsigned integer");
            return Value;
        }

        auto ParseOptions(const Arguments &CommandLine, Options &Settings) -> bool
        {
            bool Help = false;
            for (int Index = 1; Index < CommandLine.Count; ++Index)
            {
                const std::string_view Argument{CommandLine.Values[Index]};
                if (Argument == "--help" || Argument == "-h")
                {
                    Help = true;
                    continue;
                }
                if (Argument == "--validate-only")
                {
                    Settings.ValidateOnly = true;
                    continue;
                }
                Require(Index + 1 < CommandLine.Count, "option is missing its value");
                const std::string_view Value{CommandLine.Values[++Index]};
                if (Argument == "--threads")
                {
                    Settings.Threads = static_cast<std::size_t>(ParseUnsigned(Value));
                }
                else if (Argument == "--operations")
                {
                    Settings.Operations = static_cast<std::size_t>(ParseUnsigned(Value));
                }
                else if (Argument == "--capacity")
                {
                    const auto Parsed = ParseUnsigned(Value);
                    Require(Parsed > 0 && Parsed <= Uint32Max,
                            "capacity must be between 1 and UINT32_MAX");
                    Settings.Capacity = static_cast<std::size_t>(Parsed);
                }
                else if (Argument == "--now")
                {
                    Settings.Now = ParseUnsigned(Value);
                }
                else if (Argument == "--refill-interval-ms")
                {
                    Settings.RefillIntervalMs = ParseUnsigned(Value);
                }
                else if (Argument == "--rounds")
                {
                    Settings.Rounds = static_cast<std::size_t>(ParseUnsigned(Value));
                }
                else
                {
                    throw std::invalid_argument("unknown option");
                }
            }
            if (Help)
            {
                return false;
            }
            Require(Settings.Threads == 1 || Settings.Threads == 2 || Settings.Threads == 4,
                    "threads must be 1, 2, or 4");
            Require(Settings.Operations >= 1 && Settings.Operations <= MaxOperations,
                    "operations must be between 1 and 5000000");
            Require(Settings.RefillIntervalMs >= 1 &&
                        Settings.RefillIntervalMs <= MaxRefillIntervalMs,
                    "refill interval must be between 1 and 1000000000 milliseconds");
            Require(Settings.Rounds >= 1 && Settings.Rounds <= MaxRounds,
                    "rounds must be between 1 and 100");
            return true;
        }

        auto PrintUsage() -> void
        {
            std::puts("TokenBucketCompare [--threads 1|2|4] [--operations N]");
            std::puts("                   [--capacity N] [--now N]");
            std::puts("                   [--refill-interval-ms N] [--rounds N]");
            std::puts("TokenBucketCompare --validate-only [the same options]");
            std::puts("capacity defaults to the total requested tokens in the fixed-Now trace");
        }

        auto Mix(std::uint64_t &Hash, const std::uint64_t Value) -> void
        {
            Hash ^= Value;
            Hash *= FnvPrime;
        }

        auto MakeTrace(const Options &Settings) -> Trace
        {
            Trace Result;
            Result.Fixed.reserve(Settings.Operations);
            Result.Refill.reserve(Settings.Operations);
            Mix(Result.FixedHash, Settings.Operations);
            Mix(Result.FixedHash, Settings.Now);
            Mix(Result.RefillHash, Settings.Operations);
            Mix(Result.RefillHash, Settings.RefillIntervalMs);

            for (std::size_t Index = 0; Index < Settings.Operations; ++Index)
            {
                const auto Count = Index % 4 + 1;
                Result.Fixed.push_back(Request{Settings.Now, Count});
                Mix(Result.FixedHash, Index);
                Mix(Result.FixedHash, Settings.Now);
                Mix(Result.FixedHash, Count);
                Result.RequiredTokens += Count;

                if (Index > 0)
                {
                    Require(Settings.RefillIntervalMs <=
                                (Uint32Max - 1) / static_cast<std::uint64_t>(Index),
                            "refill trace crosses the 32-bit relative-time boundary");
                }
                const auto RefillNow =
                    static_cast<std::uint64_t>(Index) * Settings.RefillIntervalMs;
                Result.Refill.push_back(Request{RefillNow, 1});
                Mix(Result.RefillHash, Index);
                Mix(Result.RefillHash, RefillNow);
                Mix(Result.RefillHash, 1);
            }

            Result.Capacity = Settings.Capacity == 0 ? Result.RequiredTokens : Settings.Capacity;
            Mix(Result.CombinedHash, Result.FixedHash);
            Mix(Result.CombinedHash, Result.RefillHash);
            return Result;
        }

        auto ValidateTrace(const Options &Settings, const Trace &TraceValue) -> void
        {
            Require(TraceValue.Fixed.size() == Settings.Operations &&
                        TraceValue.Refill.size() == Settings.Operations,
                    "trace size mismatch");
            Require(TraceValue.RequiredTokens > 0 &&
                        TraceValue.RequiredTokens <= Uint32Max,
                    "fixed trace requested token total is out of range");
            Require(TraceValue.Capacity >= TraceValue.RequiredTokens &&
                        TraceValue.Capacity <= Uint32Max,
                    "capacity does not guarantee every fixed-Now request");

            std::size_t RequiredTokens = 0;
            for (std::size_t Index = 0; Index < TraceValue.Fixed.size(); ++Index)
            {
                const auto &RequestValue = TraceValue.Fixed[Index];
                Require(RequestValue.Now == Settings.Now && RequestValue.Count == Index % 4 + 1,
                        "fixed trace is not deterministic");
                RequiredTokens += RequestValue.Count;
                const auto &RefillRequest = TraceValue.Refill[Index];
                Require(RefillRequest.Count == 1 &&
                            RefillRequest.Now ==
                                static_cast<std::uint64_t>(Index) * Settings.RefillIntervalMs,
                        "refill trace is not deterministic");
                Require(RefillRequest.Now < Uint32Max,
                        "refill trace crosses the 32-bit relative-time boundary");
            }
            Require(RequiredTokens == TraceValue.RequiredTokens,
                    "fixed trace token total mismatch");
        }

        auto CurrentRssBytes() -> std::optional<std::uint64_t>
        {
#if defined(_WIN32)
            PROCESS_MEMORY_COUNTERS Counters{};
            if (GetProcessMemoryInfo(GetCurrentProcess(), &Counters, sizeof(Counters)) != 0)
            {
                return static_cast<std::uint64_t>(Counters.WorkingSetSize);
            }
#elif defined(__linux__)
            std::FILE *File = std::fopen("/proc/self/statm", "r");
            if (File == nullptr)
            {
                return std::nullopt;
            }
            unsigned long long TotalPages = 0;
            unsigned long long ResidentPages = 0;
            const auto Read = std::fscanf(File, "%llu %llu", &TotalPages, &ResidentPages);
            std::fclose(File);
            if (Read == 2)
            {
                const auto PageSize = sysconf(_SC_PAGESIZE);
                if (PageSize > 0)
                {
                    return static_cast<std::uint64_t>(ResidentPages) *
                           static_cast<std::uint64_t>(PageSize);
                }
            }
#endif
            return std::nullopt;
        }

        auto Percentile95(const std::span<const std::uint64_t> Samples) -> std::uint64_t
        {
            if (Samples.empty())
            {
                return 0;
            }
            std::vector<std::uint64_t> Sorted(Samples.begin(), Samples.end());
            std::sort(Sorted.begin(), Sorted.end());
            const auto Rank = (Sorted.size() * 95 + 99) / 100;
            return Sorted[std::max<std::size_t>(1, Rank) - 1];
        }

        auto CaptureFailure(LifecycleState &State, std::exception_ptr Exception) noexcept -> void
        {
            if (!Exception) return;
            State.Stop.store(true, std::memory_order_release);
            State.Failures.fetch_add(1, std::memory_order_relaxed);
            try
            {
                std::lock_guard Lock(State.Mutex);
                if (!State.First) State.First = std::move(Exception);
            }
            catch (...)
            {
                State.Stop.store(true, std::memory_order_release);
            }
        }

        auto RunWorker(WorkerContext &Context) -> void
        {
            Context.Ready.count_down();
            try
            {
                Context.Start.wait();
                if (Context.Plan && Context.Plan->Kind == FailureKind::Worker &&
                    Context.Plan->Index == Context.WorkerIndex)
                {
                    throw std::runtime_error("injected token bucket worker failure");
                }
                for (std::size_t Index = Context.WorkerIndex;
                     Index < Context.Requests.size() &&
                     !Context.Lifecycle.Stop.load(std::memory_order_acquire);
                     Index += Context.WorkerCount)
                {
                    const auto Started = Clock::now();
                    const auto &RequestValue = Context.Requests[Index];
                    const auto Success = Context.BucketValue.TryTake(RequestValue.Count, RequestValue.Now);
                    const auto Finished = Clock::now();
                    const auto Elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(Finished - Started).count();
                    Context.Latencies[Index] = static_cast<std::uint64_t>(std::max<std::int64_t>(1, Elapsed));
                    if (Success) Context.Successes.fetch_add(1, std::memory_order_relaxed);
                    else Context.Failures.fetch_add(1, std::memory_order_relaxed);
                }
            }
            catch (...)
            {
                CaptureFailure(Context.Lifecycle, std::current_exception());
            }
            Context.Done.count_down();
        }

        auto MarkInvalid(Measurement &Result, const char *Reason) -> void
        {
            if (!Result.Invalid)
            {
                Result.InvalidReason = Reason;
            }
            Result.Invalid = true;
        }

        auto RunScenario(const ScenarioPlan &Plan, const FailurePlan *Failure = nullptr) -> Measurement
        {
            Require(!Plan.Requests.empty(), "scenario trace must not be empty");
            Bucket BucketValue(Plan.Capacity, std::chrono::milliseconds(
                static_cast<std::int64_t>(Plan.RefillIntervalMs)), 1);
            Require(BucketValue.TryTake(0, Plan.Requests.front().Now),
                    "bucket initialization failed");

            std::vector<std::uint64_t> Latencies(Plan.Requests.size(), 0);
            std::atomic<std::uint64_t> Successes{0};
            std::atomic<std::uint64_t> Failures{0};
            LifecycleState Lifecycle;
            std::latch Ready(static_cast<std::ptrdiff_t>(Plan.Threads));
            std::latch Start(1);
            std::latch Done(static_cast<std::ptrdiff_t>(Plan.Threads));
            std::vector<WorkerContext> Contexts;
            Contexts.reserve(Plan.Threads);
            std::vector<std::thread> Threads;
            Threads.reserve(Plan.Threads);
            std::size_t StartedThreads = 0;
            bool Launching = true;

            for (std::size_t WorkerIndex = 0; WorkerIndex < Plan.Threads; ++WorkerIndex)
            {
                if (!Launching) { Ready.count_down(); Done.count_down(); continue; }
                try
                {
                    Contexts.push_back(WorkerContext{BucketValue, Plan.Requests,
                        std::span<std::uint64_t>(Latencies), Successes, Failures, WorkerIndex,
                        Plan.Threads, Ready, Start, Done, Lifecycle, Failure});
                    if (Failure && Failure->Kind == FailureKind::Start &&
                        Failure->Index == WorkerIndex)
                    {
                        throw std::runtime_error("injected token bucket thread start failure");
                    }
                    Threads.emplace_back([Context = &Contexts.back()] { RunWorker(*Context); });
                    ++StartedThreads;
                }
                catch (...)
                {
                    CaptureFailure(Lifecycle, std::current_exception());
                    Launching = false;
                    Ready.count_down();
                    Done.count_down();
                }
            }

            Ready.wait();
            const auto Measured = Failure == nullptr;
            std::optional<std::uint64_t> RssBefore;
            std::optional<Clock::time_point> Started, Finished;
            if (Measured)
            {
                RssBefore = CurrentRssBytes();
                OrdinaryAllocationCount.store(0, std::memory_order_relaxed);
                OrdinaryAllocationBytes.store(0, std::memory_order_relaxed);
                AlignedAllocationCount.store(0, std::memory_order_relaxed);
                AlignedAllocationBytes.store(0, std::memory_order_relaxed);
                TrackAllocations.store(true, std::memory_order_release);
                Started = Clock::now();
            }
            Start.count_down();
            Done.wait();
            if (Measured)
            {
                Finished = Clock::now();
                TrackAllocations.store(false, std::memory_order_release);
            }
            for (auto &Thread : Threads)
            {
                Thread.join();
            }
            const auto RssAfter = Measured ? CurrentRssBytes() : std::optional<std::uint64_t>{};

            Measurement Result;
            Result.Attempts = Plan.Requests.size();
            Result.Successes = Successes.load(std::memory_order_relaxed);
            Result.Failures = Failures.load(std::memory_order_relaxed);
            Result.Available = BucketValue.Available();
            if (Started && Finished)
            {
                Result.DurationNanoseconds = static_cast<std::uint64_t>(std::max<std::int64_t>(
                    1, std::chrono::duration_cast<std::chrono::nanoseconds>(*Finished - *Started).count()));
            }
            Result.P95Nanoseconds = Percentile95(Latencies);
            Result.Throughput = static_cast<double>(Result.Attempts) * 1'000'000'000.0 /
                                static_cast<double>(std::max<std::uint64_t>(1, Result.DurationNanoseconds));
            Result.OrdinaryAllocations = OrdinaryAllocationCount.load(std::memory_order_relaxed);
            Result.OrdinaryAllocationBytes = OrdinaryAllocationBytes.load(std::memory_order_relaxed);
            Result.AlignedAllocations = AlignedAllocationCount.load(std::memory_order_relaxed);
            Result.AlignedAllocationBytes = AlignedAllocationBytes.load(std::memory_order_relaxed);
            Result.RssBefore = RssBefore;
            Result.RssAfter = RssAfter;
            Result.ThreadsJoined = StartedThreads == Threads.size();
            Result.FailureCount = Lifecycle.Failures.load(std::memory_order_relaxed);
            { std::lock_guard Lock(Lifecycle.Mutex); Result.FirstFailureObserved = Lifecycle.First != nullptr; }

            if (Result.Successes + Result.Failures != Result.Attempts)
            {
                MarkInvalid(Result, "result_count");
            }
            if (Result.Successes != Result.Attempts)
            {
                MarkInvalid(Result, "success_count");
            }
            if (Result.Failures != 0)
            {
                MarkInvalid(Result, "failure_count");
            }
            if (Result.Available != Plan.ExpectedAvailable)
            {
                MarkInvalid(Result, "available_tokens");
            }
            if (Result.P95Nanoseconds == 0)
            {
                MarkInvalid(Result, "missing_latency");
            }
            if (Result.FirstFailureObserved) MarkInvalid(Result, "worker_exception");
            if (!Result.ThreadsJoined) MarkInvalid(Result, "threads_not_joined");
            return Result;
        }

        auto RunLifecyclePreflight(const ScenarioPlan &Plan) -> bool
        {
            std::size_t Cases = 0;
            std::size_t Passed = 0;
            const auto Check = [&](const ScenarioPlan &Probe, const FailurePlan &Failure)
            {
                ++Cases;
                const auto Result = RunScenario(Probe, &Failure);
                const auto Valid = Result.FirstFailureObserved && Result.FailureCount != 0 &&
                    Result.ThreadsJoined && Result.Invalid;
                if (Valid) ++Passed;
            };
            for (const auto Threads : {std::size_t{1}, std::size_t{2}, std::size_t{4}})
            {
                auto Probe = Plan;
                Probe.Threads = Threads;
                for (std::size_t Prefix = 0; Prefix < Threads; ++Prefix)
                    Check(Probe, FailurePlan{FailureKind::Start, Prefix});
                for (std::size_t Worker = 0; Worker < Threads; ++Worker)
                    Check(Probe, FailurePlan{FailureKind::Worker, Worker});
            }
            const auto Valid = Cases != 0 && Cases == Passed;
            std::printf("lifecycle_preflight_cases=%zu passed=%zu valid=%s\n",
                        Cases, Passed, Valid ? "true" : "false");
            return Valid;
        }

        auto PrintTrace(const Options &Settings, const Trace &TraceValue) -> void
        {
            std::printf(
                "trace_hash=%016llx fixed_trace_hash=%016llx refill_trace_hash=%016llx "
                "operations=%zu threads=%zu capacity=%zu required_tokens=%zu now=%llu "
                "refill_interval_ms=%llu rounds=%zu\n",
                static_cast<unsigned long long>(TraceValue.CombinedHash),
                static_cast<unsigned long long>(TraceValue.FixedHash),
                static_cast<unsigned long long>(TraceValue.RefillHash), Settings.Operations,
                Settings.Threads, TraceValue.Capacity, TraceValue.RequiredTokens,
                static_cast<unsigned long long>(Settings.Now),
                static_cast<unsigned long long>(Settings.RefillIntervalMs), Settings.Rounds);
            std::puts("fixed_trace_boundary=all requests use one caller-supplied Now; capacity is at least the total requested tokens; worker partition is index modulo thread count");
            std::puts("refill_trace_boundary=one worker uses Now=index*interval; Count=1; final Now is below 0xFFFFFFFF");
            std::puts("allocation_boundary=global ordinary and aligned new/new[] calls during timed TryTake work; setup, trace storage, thread creation, and latency sorting are excluded");
            std::puts("rss_boundary=working set sampled before and after timed TryTake work when the platform exposes it");
        }

        auto PrintRss(const Measurement &Result) -> void
        {
            if (Result.RssBefore.has_value() && Result.RssAfter.has_value())
            {
                const auto Before = *Result.RssBefore;
                const auto After = *Result.RssAfter;
                const auto Delta = static_cast<std::int64_t>(After) -
                                   static_cast<std::int64_t>(Before);
                std::printf("rss_before_bytes=%llu rss_after_bytes=%llu rss_delta_bytes=%lld\n",
                            static_cast<unsigned long long>(Before),
                            static_cast<unsigned long long>(After), static_cast<long long>(Delta));
            }
            else
            {
                std::puts("rss=unavailable");
            }
        }

        auto PrintMeasurement(const ScenarioPlan &Plan, const Measurement &Result) -> void
        {
            std::printf(
                "scenario=%.*s round=%zu threads=%zu attempts=%llu trace_hash=%016llx "
                "success=%llu failure=%llu available=%llu duration_ns=%llu "
                "throughput_ops_s=%.2f p95_ns=%llu ordinary_allocations=%llu "
                "ordinary_allocation_bytes=%llu aligned_allocations=%llu "
                "aligned_allocation_bytes=%llu invalid=%s invalid_reason=%s\n",
                static_cast<int>(Plan.Name.size()), Plan.Name.data(), Result.Round, Plan.Threads,
                static_cast<unsigned long long>(Result.Attempts),
                static_cast<unsigned long long>(Plan.TraceHash),
                static_cast<unsigned long long>(Result.Successes),
                static_cast<unsigned long long>(Result.Failures),
                static_cast<unsigned long long>(Result.Available),
                static_cast<unsigned long long>(Result.DurationNanoseconds), Result.Throughput,
                static_cast<unsigned long long>(Result.P95Nanoseconds),
                static_cast<unsigned long long>(Result.OrdinaryAllocations),
                static_cast<unsigned long long>(Result.OrdinaryAllocationBytes),
                static_cast<unsigned long long>(Result.AlignedAllocations),
                static_cast<unsigned long long>(Result.AlignedAllocationBytes),
                Result.Invalid ? "true" : "false", Result.InvalidReason);
            PrintRss(Result);
        }

        auto Run(const Options &Settings) -> int
        {
            const auto TraceValue = MakeTrace(Settings);
            ValidateTrace(Settings, TraceValue);
            PrintTrace(Settings, TraceValue);
            const ScenarioPlan FixedPlan{"fixed_now",
                                         TraceValue.Fixed,
                                         Settings.Threads,
                                         TraceValue.Capacity,
                                         TraceValue.Capacity - TraceValue.RequiredTokens,
                                         Settings.RefillIntervalMs,
                                         TraceValue.FixedHash};
            if (Settings.ValidateOnly)
            {
                const auto Valid = RunLifecyclePreflight(FixedPlan);
                if (Valid) std::puts("semantic_preflight=pass");
                return Valid ? 0 : 1;
            }

            const ScenarioPlan RefillPlan{"single_thread_refill",
                                          TraceValue.Refill,
                                          1,
                                          1,
                                          0,
                                          Settings.RefillIntervalMs,
                                          TraceValue.RefillHash};

            for (std::size_t Round = 1; Round <= Settings.Rounds; ++Round)
            {
                auto FixedResult = RunScenario(FixedPlan);
                FixedResult.Round = Round;
                PrintMeasurement(FixedPlan, FixedResult);
                if (FixedResult.Invalid)
                {
                    std::fprintf(stderr, "[FAIL] fixed-Now measurement validation failed: %s\n",
                                 FixedResult.InvalidReason);
                    return 1;
                }

                auto RefillResult = RunScenario(RefillPlan);
                RefillResult.Round = Round;
                PrintMeasurement(RefillPlan, RefillResult);
                if (RefillResult.Invalid)
                {
                    std::fprintf(stderr, "[FAIL] refill measurement validation failed: %s\n",
                                 RefillResult.InvalidReason);
                    return 1;
                }
            }
            return 0;
        }

    } // namespace

    auto Allocate(const std::size_t Size) -> void *
    {
        const auto ActualSize = Size == 0 ? std::size_t{1} : Size;
        auto *Memory = std::malloc(ActualSize);
        if (!Memory) throw std::bad_alloc{};
        if (TrackAllocations.load(std::memory_order_relaxed))
        {
            OrdinaryAllocationCount.fetch_add(1, std::memory_order_relaxed);
            OrdinaryAllocationBytes.fetch_add(Size, std::memory_order_relaxed);
        }
        return Memory;
    }

    auto AllocateAligned(const std::size_t Size, const std::size_t Alignment) -> void *
    {
        const auto ActualSize = Size == 0 ? std::size_t{1} : Size;
        void *Memory = nullptr;
#if defined(_WIN32)
        Memory = _aligned_malloc(ActualSize, Alignment);
#else
        Memory = std::aligned_alloc(Alignment, ((ActualSize + Alignment - 1) / Alignment) * Alignment);
#endif
        if (!Memory) throw std::bad_alloc{};
        if (TrackAllocations.load(std::memory_order_relaxed))
        {
            AlignedAllocationCount.fetch_add(1, std::memory_order_relaxed);
            AlignedAllocationBytes.fetch_add(Size, std::memory_order_relaxed);
        }
        return Memory;
    }

    auto ReleaseAligned(void *Memory) noexcept -> void
    {
#if defined(_WIN32)
        _aligned_free(Memory);
#else
        std::free(Memory);
#endif
    }

} // namespace Preview::Rate::Perf

auto operator new(const std::size_t Size) -> void * { return Preview::Rate::Perf::Allocate(Size); }
auto operator new[](const std::size_t Size) -> void * { return Preview::Rate::Perf::Allocate(Size); }
auto operator new(const std::size_t Size, const std::nothrow_t &) noexcept -> void *
{ try { return Preview::Rate::Perf::Allocate(Size); } catch (...) { return nullptr; } }
auto operator new[](const std::size_t Size, const std::nothrow_t &Tag) noexcept -> void *
{ return ::operator new(Size, Tag); }
auto operator new(const std::size_t Size, const std::align_val_t Alignment) -> void *
{ return Preview::Rate::Perf::AllocateAligned(Size, static_cast<std::size_t>(Alignment)); }
auto operator new[](const std::size_t Size, const std::align_val_t Alignment) -> void *
{ return ::operator new(Size, Alignment); }
auto operator new(const std::size_t Size, const std::align_val_t Alignment,
                  const std::nothrow_t &) noexcept -> void *
{ try { return Preview::Rate::Perf::AllocateAligned(Size, static_cast<std::size_t>(Alignment)); } catch (...) { return nullptr; } }
auto operator new[](const std::size_t Size, const std::align_val_t Alignment,
                    const std::nothrow_t &Tag) noexcept -> void *
{ return ::operator new(Size, Alignment, Tag); }
auto operator delete(void *Memory) noexcept -> void { std::free(Memory); }
auto operator delete[](void *Memory) noexcept -> void { std::free(Memory); }
auto operator delete(void *Memory, const std::size_t) noexcept -> void { std::free(Memory); }
auto operator delete[](void *Memory, const std::size_t) noexcept -> void { std::free(Memory); }
auto operator delete(void *Memory, const std::nothrow_t &) noexcept -> void { std::free(Memory); }
auto operator delete[](void *Memory, const std::nothrow_t &) noexcept -> void { std::free(Memory); }
auto operator delete(void *Memory, const std::align_val_t) noexcept -> void
{ Preview::Rate::Perf::ReleaseAligned(Memory); }
auto operator delete[](void *Memory, const std::align_val_t) noexcept -> void
{ Preview::Rate::Perf::ReleaseAligned(Memory); }
auto operator delete(void *Memory, const std::size_t, const std::align_val_t) noexcept -> void
{ Preview::Rate::Perf::ReleaseAligned(Memory); }
auto operator delete[](void *Memory, const std::size_t, const std::align_val_t) noexcept -> void
{ Preview::Rate::Perf::ReleaseAligned(Memory); }

auto main(const int Argc, char **Argv) -> int
{
    try
    {
        Preview::Rate::Perf::Options Settings;
        const Preview::Rate::Perf::Arguments CommandLine{Argc, Argv};
        if (!Preview::Rate::Perf::ParseOptions(CommandLine, Settings))
        {
            Preview::Rate::Perf::PrintUsage();
            return 0;
        }
        return Preview::Rate::Perf::Run(Settings);
    }
    catch (const std::exception &Error)
    {
        std::fprintf(stderr, "[FAIL] %s\n", Error.what());
        Preview::Rate::Perf::PrintUsage();
        return 2;
    }
}
