/**
 * @file MailboxCompareMeasure.cpp
 * @brief Mailbox 旧实现同 trace 测量、功能校验和资源观测。
 */

#include "MailboxCompare.hpp"
#include "MailboxCompareTrace.hpp"
#include <Prism/Runtime/Detail/Mailbox.hpp>
#include <Prism/Runtime/WorkerDispatchResult.hpp>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <latch>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <mutex>
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

namespace Prism::Runtime::Perf
{

    auto MakeTrace(const Options &Settings) -> Trace;

    namespace
    {

        using Clock = std::chrono::steady_clock;
        using Prism::Runtime::Detail::Mailbox;
        using Prism::Runtime::WorkerDispatchResult;

        constexpr Prism::GenerationId Generation{41};
        constexpr std::uint64_t FnvOffset = 14695981039346656037ull;
        constexpr std::uint64_t FnvPrime = 1099511628211ull;

        enum class FailureKind
        {
            Start,
            Consumer,
            Producer,
            Command,
        };

        struct FailurePlan final
        {
            FailureKind Kind;
            std::size_t Index{0};
        };

        std::atomic<bool> TrackAllocations{false};
        std::atomic<std::uint64_t> AllocationCount{0};
        std::atomic<std::uint64_t> AllocationBytes{0};

        auto Mix(std::uint64_t &Hash, const std::uint64_t Value) -> void
        {
            Hash ^= Value;
            Hash *= FnvPrime;
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

        auto Percentile(std::vector<std::uint64_t> Values, const std::size_t Numerator,
                        const std::size_t Denominator) -> std::uint64_t
        {
            if (Values.empty())
            {
                return 0;
            }
            std::sort(Values.begin(), Values.end());
            const auto Rank = (Values.size() * Numerator + Denominator - 1) / Denominator;
            return Values[std::max<std::size_t>(1, Rank) - 1];
        }

        struct Measurement final
        {
            std::size_t Producers{0};
            std::size_t Commands{0};
            std::uint64_t TraceHash{0};
            std::uint64_t Accepted{0};
            std::uint64_t Full{0};
            std::uint64_t Closed{0};
            std::uint64_t Unavailable{0};
            std::uint64_t Consumed{0};
            std::uint64_t DurationNanoseconds{0};
            double Throughput{0};
            std::uint64_t P50{0};
            std::uint64_t P95{0};
            std::uint64_t P99{0};
            std::uint64_t Allocations{0};
            std::uint64_t AllocationBytesValue{0};
            std::optional<std::uint64_t> RssBefore;
            std::optional<std::uint64_t> RssAfter;
            std::uint64_t CorrectnessHash{FnvOffset};
            bool Invalid{false};
            const char *InvalidReason{"none"};
            bool ThreadsJoined{false};
            bool BoxClosed{false};
            std::size_t FailureCount{0};
            bool FirstFailureObserved{false};
        };

        struct RunState final
        {
            const Trace &TraceValue;
            Mailbox Box;
            std::vector<Clock::time_point> PublishedAt;
            std::vector<std::uint8_t> AcceptedFlags;
            std::vector<std::uint8_t> ConsumedFlags;
            std::vector<std::uint64_t> Latencies;
            std::atomic<std::size_t> Attempts{0};
            std::atomic<std::size_t> Accepted{0};
            std::atomic<std::size_t> Full{0};
            std::atomic<std::size_t> Closed{0};
            std::atomic<std::size_t> Unavailable{0};
            std::atomic<std::size_t> RemainingProducers{0};
            std::atomic<bool> ProducersDone{false};
            std::atomic<bool> StopRequested{false};
            std::atomic<std::size_t> FailureCount{0};
            const std::size_t ProducerCount;
            std::mutex FailureMutex;
            std::exception_ptr FirstException;
            std::uint64_t CorrectnessHash{FnvOffset};
            bool Invalid{false};

            RunState(const Options &Settings, const Trace &TraceValueValue)
                : TraceValue(TraceValueValue),
                  Box(Mailbox::Options{Settings.Capacity, Generation}),
                  PublishedAt(TraceValue.Commands.size()),
                  AcceptedFlags(TraceValue.Commands.size(), 0),
                  ConsumedFlags(TraceValue.Commands.size(), 0),
                  RemainingProducers(Settings.Producers), ProducerCount(Settings.Producers)
            {
                Latencies.reserve(TraceValue.Commands.size());
            }
        };

        auto CaptureFailure(RunState &State, std::exception_ptr Exception) noexcept -> void
        {
            if (!Exception)
            {
                return;
            }
            try
            {
                State.StopRequested.store(true, std::memory_order_release);
                State.FailureCount.fetch_add(1, std::memory_order_relaxed);
                std::lock_guard Lock(State.FailureMutex);
                if (!State.FirstException) State.FirstException = std::move(Exception);
            }
            catch (...)
            {
                State.StopRequested.store(true, std::memory_order_release);
            }
        }

        auto CompleteProducer(RunState &State) -> void
        {
            if (State.RemainingProducers.fetch_sub(1, std::memory_order_acq_rel) == 1)
            {
                State.ProducersDone.store(true, std::memory_order_release);
            }
        }

        auto CloseAndDiscard(RunState &State) -> void
        {
            State.Box.Close();
            Mailbox::Command Command;
            while (State.Box.TryReceive(Command))
            {
                Command = {};
            }
        }

        auto ConsumeCommand(RunState &State, const std::size_t Index) -> void
        {
            if (Index >= State.ConsumedFlags.size() || State.ConsumedFlags[Index] != 0)
            {
                State.Invalid = true;
                return;
            }
            State.ConsumedFlags[Index] = 1;
            Mix(State.CorrectnessHash, Index);
            Mix(State.CorrectnessHash, State.TraceValue.Commands[Index].Payload);
            const auto Elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                      Clock::now() - State.PublishedAt[Index])
                                      .count();
            State.Latencies.push_back(static_cast<std::uint64_t>(std::max<std::int64_t>(1, Elapsed)));
        }

        auto RecordPostResult(RunState &State, const std::size_t Index,
                              const WorkerDispatchResult Result) -> void
        {
            State.Attempts.fetch_add(1, std::memory_order_relaxed);
            if (Result == WorkerDispatchResult::Accepted) { State.AcceptedFlags[Index] = 1; State.Accepted.fetch_add(1, std::memory_order_relaxed); }
            else if (Result == WorkerDispatchResult::Full) State.Full.fetch_add(1, std::memory_order_relaxed);
            else if (Result == WorkerDispatchResult::Closed) State.Closed.fetch_add(1, std::memory_order_relaxed);
            else State.Unavailable.fetch_add(1, std::memory_order_relaxed);
        }

        auto PostCommand(RunState &State, const std::size_t Index) -> void
        {
            State.PublishedAt[Index] = Clock::now();
            RecordPostResult(State, Index, State.Box.Post(
                Generation, [&State, Index] { ConsumeCommand(State, Index); }));
        }

        auto PostFailureCommand(RunState &State, const std::size_t Index) -> void
        {
            State.PublishedAt[Index] = Clock::now();
            RecordPostResult(State, Index, State.Box.Post(
                Generation, [] { throw std::runtime_error("injected mailbox command failure"); }));
        }

        auto RunProducer(RunState &State, const std::size_t Producer,
                         const FailurePlan *Plan = nullptr) -> void
        {
            try
            {
                if (Plan && Plan->Kind == FailureKind::Producer && Plan->Index == Producer)
                {
                    throw std::runtime_error("injected mailbox producer failure");
                }
                const auto InjectCommand = Plan && Plan->Kind == FailureKind::Command && Producer == 0;
                for (std::size_t Index = Producer; Index < State.TraceValue.Commands.size();
                     Index += State.ProducerCount)
                {
                    if (State.StopRequested.load(std::memory_order_acquire))
                    {
                        break;
                    }
                    if (InjectCommand && Index == Plan->Index) PostFailureCommand(State, Index);
                    else PostCommand(State, Index);
                }
            }
            catch (...)
            {
                CaptureFailure(State, std::current_exception());
            }
            CompleteProducer(State);
        }

        auto RunConsumer(RunState &State, const FailurePlan *Plan = nullptr) -> void
        {
            try
            {
                if (Plan && Plan->Kind == FailureKind::Consumer)
                {
                    throw std::runtime_error("injected mailbox consumer failure");
                }
                for (;;)
                {
                    if (State.StopRequested.load(std::memory_order_acquire))
                    {
                        return;
                    }
                    Mailbox::Command Command;
                    if (State.Box.TryReceive(Command))
                    {
                        if (Command) Command();
                        else State.Invalid = true;
                        continue;
                    }
                    if (State.ProducersDone.load(std::memory_order_acquire) && State.Box.Size() == 0)
                    {
                        return;
                    }
                    std::this_thread::yield();
                }
            }
            catch (...)
            {
                CaptureFailure(State, std::current_exception());
            }
        }

        auto MarkInvalid(Measurement &Result, const char *Reason) -> void
        {
            if (!Result.Invalid)
            {
                Result.InvalidReason = Reason;
            }
            Result.Invalid = true;
        }

        auto ValidateMeasurement(const Trace &TraceValue, const RunState &State,
                                Measurement &Result) -> void
        {
            const auto Attempts = State.Attempts.load(std::memory_order_relaxed);
            const auto Accepted = State.Accepted.load(std::memory_order_relaxed);
            const auto Full = State.Full.load(std::memory_order_relaxed);
            const auto Closed = State.Closed.load(std::memory_order_relaxed);
            const auto Unavailable = State.Unavailable.load(std::memory_order_relaxed);
            const auto Consumed = State.Latencies.size();
            if (Attempts != TraceValue.Commands.size())
            {
                MarkInvalid(Result, "attempt_count");
            }
            if (Accepted + Full + Closed + Unavailable != Attempts)
            {
                MarkInvalid(Result, "result_count");
            }
            if (TraceValue.Commands.size() < State.Box.Capacity())
            {
                if (Full != 0)
                {
                    MarkInvalid(Result, "full_before_capacity");
                }
                if (Accepted != TraceValue.Commands.size())
                {
                    MarkInvalid(Result, "not_all_accepted_before_capacity");
                }
            }
            if (Consumed != Accepted)
            {
                MarkInvalid(Result, "consumed_count");
            }
            if (State.Box.Size() != 0)
            {
                MarkInvalid(Result, "mailbox_not_empty");
            }
            if (Accepted == 0)
            {
                MarkInvalid(Result, "no_accepted_command");
            }
            for (std::size_t Index = 0; Index < TraceValue.Commands.size(); ++Index)
            {
                const auto WasAccepted = State.AcceptedFlags[Index] != 0;
                const auto WasConsumed = State.ConsumedFlags[Index];
                if ((WasAccepted && WasConsumed != 1) || (!WasAccepted && WasConsumed != 0))
                {
                    MarkInvalid(Result, "command_exactly_once");
                    break;
                }
            }
            if (State.Invalid)
            {
                MarkInvalid(Result, "command_callback");
            }
            if (!Result.ThreadsJoined)
            {
                MarkInvalid(Result, "threads_not_joined");
            }
            if (!Result.BoxClosed)
            {
                MarkInvalid(Result, "mailbox_not_closed");
            }
        }

        auto RunSample(const Options &Settings, const Trace &TraceValue,
                       const FailurePlan *Plan = nullptr) -> Measurement
        {
            RunState State(Settings, TraceValue);
            const auto ThreadCount = Settings.Producers + 1;
            std::latch Ready(static_cast<std::ptrdiff_t>(ThreadCount));
            std::latch Start(1);
            std::latch Done(static_cast<std::ptrdiff_t>(ThreadCount));
            std::vector<std::thread> Threads;
            Threads.reserve(ThreadCount);
            std::size_t StartedThreads = 0;
            auto Launch = [&](auto Body) -> bool
            {
                try { Threads.emplace_back([&Ready, &Start, &Done, &State, Body = std::move(Body)]() mutable
                    { Ready.count_down(); try { Start.wait(); Body(); } catch (...) { CaptureFailure(State, std::current_exception()); } Done.count_down(); }); return true; }
                catch (...) { CaptureFailure(State, std::current_exception()); return false; }
            };
            bool Launching = true;
            for (std::size_t Slot = 0; Slot < ThreadCount; ++Slot)
            {
                if (!Launching)
                {
                    Ready.count_down(); Done.count_down();
                    if (Slot != 0) CompleteProducer(State);
                    continue;
                }
                try
                {
                    if (Plan && Plan->Kind == FailureKind::Start && Plan->Index == Slot)
                    {
                        throw std::runtime_error("injected mailbox thread start failure");
                    }
                    const auto Started = Slot == 0
                        ? Launch([&State, Plan] { RunConsumer(State, Plan); })
                        : Launch([&State, Plan, Producer = Slot - 1]
                                 { RunProducer(State, Producer, Plan); });
                    if (!Started) Launching = false;
                    else ++StartedThreads;
                }
                catch (...)
                {
                    CaptureFailure(State, std::current_exception());
                    Launching = false;
                }
                if (!Launching)
                {
                    Ready.count_down();
                    Done.count_down();
                    if (Slot != 0) CompleteProducer(State);
                }
            }

            Ready.wait();
            const auto Measured = Plan == nullptr;
            std::optional<std::uint64_t> RssBefore;
            std::optional<Clock::time_point> Started, Finished;
            if (Measured)
            {
                RssBefore = CurrentRssBytes();
                AllocationCount.store(0, std::memory_order_relaxed);
                AllocationBytes.store(0, std::memory_order_relaxed);
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
            CloseAndDiscard(State);

            Measurement Result;
            Result.Producers = Settings.Producers;
            Result.Commands = TraceValue.Commands.size();
            Result.TraceHash = TraceValue.Hash;
            Result.Accepted = State.Accepted.load(std::memory_order_relaxed);
            Result.Full = State.Full.load(std::memory_order_relaxed);
            Result.Closed = State.Closed.load(std::memory_order_relaxed);
            Result.Unavailable = State.Unavailable.load(std::memory_order_relaxed);
            Result.Consumed = State.Latencies.size();
            Result.ThreadsJoined = StartedThreads == Threads.size();
            Result.BoxClosed = State.Box.IsClosed();
            Result.FailureCount = State.FailureCount.load(std::memory_order_relaxed);
            { std::lock_guard Lock(State.FailureMutex); Result.FirstFailureObserved = State.FirstException != nullptr; }
            if (Started && Finished)
            {
                Result.DurationNanoseconds = static_cast<std::uint64_t>(std::max<std::int64_t>(
                    1, std::chrono::duration_cast<std::chrono::nanoseconds>(*Finished - *Started).count()));
            }
            Result.Throughput = static_cast<double>(Result.Consumed) * 1'000'000'000.0 /
                                static_cast<double>(std::max<std::uint64_t>(1, Result.DurationNanoseconds));
            Result.P50 = Percentile(State.Latencies, 50, 100);
            Result.P95 = Percentile(State.Latencies, 95, 100);
            Result.P99 = Percentile(State.Latencies, 99, 100);
            Result.Allocations = AllocationCount.load(std::memory_order_relaxed);
            Result.AllocationBytesValue = AllocationBytes.load(std::memory_order_relaxed);
            Result.RssBefore = RssBefore;
            Result.RssAfter = Measured ? CurrentRssBytes() : std::nullopt;
            Result.CorrectnessHash = State.CorrectnessHash;
            if (Result.FirstFailureObserved) MarkInvalid(Result, "worker_exception");
            ValidateMeasurement(TraceValue, State, Result);
            return Result;
        }

        auto RunLifecyclePreflight(const Options &Settings, const Trace &TraceValue) -> bool
        {
            std::size_t Cases = 0;
            std::size_t Passed = 0;
            const auto Check = [&](const Options &Probe, const FailurePlan &Plan)
            {
                ++Cases;
                const auto Result = RunSample(Probe, TraceValue, &Plan);
                const auto Valid = Result.FirstFailureObserved && Result.FailureCount != 0 &&
                    Result.ThreadsJoined && Result.BoxClosed && Result.Invalid;
                if (Valid) ++Passed;
            };
            for (const auto Producers : {std::size_t{1}, std::size_t{2}, std::size_t{4}})
            {
                auto Probe = Settings;
                Probe.Producers = Producers;
                Probe.Capacity = (std::max)(Probe.Capacity, Probe.Commands + 1);
                for (std::size_t Prefix = 0; Prefix < Producers + 1; ++Prefix)
                    Check(Probe, FailurePlan{FailureKind::Start, Prefix});
                Check(Probe, FailurePlan{FailureKind::Consumer});
                for (std::size_t Producer = 0; Producer < Producers; ++Producer)
                    Check(Probe, FailurePlan{FailureKind::Producer, Producer});
                Check(Probe, FailurePlan{FailureKind::Command, 0});
            }
            const auto Valid = Cases != 0 && Cases == Passed;
            std::printf("lifecycle_preflight_cases=%zu passed=%zu valid=%s\n",
                        Cases, Passed, Valid ? "true" : "false");
            return Valid;
        }

        auto RunContractProbe() -> bool
        {
            Mailbox Box(Mailbox::Options{1, Generation});
            std::size_t Consumed = 0;
            const auto Accepted = Box.Post(Generation, [&Consumed] { ++Consumed; });
            const auto Full = Box.Post(Generation, [] {});
            Box.Close();
            const auto Closed = Box.Post(Generation, [] {});
            Mailbox::Command Command;
            while (Box.TryReceive(Command))
            {
                if (Command)
                {
                    Command();
                }
            }
            const auto Valid = Accepted == WorkerDispatchResult::Accepted &&
                               Full == WorkerDispatchResult::Full &&
                               Closed == WorkerDispatchResult::Closed && Consumed == 1 &&
                               Box.Size() == 0 && Box.IsClosed();
            std::printf("contract_accepted=%u contract_full=%u contract_closed=%u "
                        "contract_consumed=%zu contract_valid=%s\n",
                        Accepted == WorkerDispatchResult::Accepted ? 1U : 0U,
                        Full == WorkerDispatchResult::Full ? 1U : 0U,
                        Closed == WorkerDispatchResult::Closed ? 1U : 0U, Consumed,
                        Valid ? "true" : "false");
            return Valid;
        }

        auto PrintMeasurement(const Measurement &Result, const std::size_t Round) -> void
        {
            std::printf(
                "producers=%zu round=%zu commands=%zu trace_hash=%016llx accepted=%llu "
                "full=%llu closed=%llu unavailable=%llu consumed=%llu duration_ns=%llu "
                "throughput_ops_s=%.2f p50_ns=%llu p95_ns=%llu p99_ns=%llu "
                "allocations=%llu allocation_bytes=%llu correctness_hash=%016llx "
                "box_closed=%s threads_joined=%s invalid=%s invalid_reason=%s\n",
                Result.Producers, Round, Result.Commands,
                static_cast<unsigned long long>(Result.TraceHash),
                static_cast<unsigned long long>(Result.Accepted),
                static_cast<unsigned long long>(Result.Full),
                static_cast<unsigned long long>(Result.Closed),
                static_cast<unsigned long long>(Result.Unavailable),
                static_cast<unsigned long long>(Result.Consumed),
                static_cast<unsigned long long>(Result.DurationNanoseconds), Result.Throughput,
                static_cast<unsigned long long>(Result.P50),
                static_cast<unsigned long long>(Result.P95),
                static_cast<unsigned long long>(Result.P99),
                static_cast<unsigned long long>(Result.Allocations),
                static_cast<unsigned long long>(Result.AllocationBytesValue),
                static_cast<unsigned long long>(Result.CorrectnessHash),
                Result.BoxClosed ? "true" : "false", Result.ThreadsJoined ? "true" : "false",
                Result.Invalid ? "true" : "false", Result.InvalidReason);
            if (Result.RssBefore.has_value() && Result.RssAfter.has_value())
            {
                const auto Delta = static_cast<std::int64_t>(*Result.RssAfter) -
                                   static_cast<std::int64_t>(*Result.RssBefore);
                std::printf("rss_before_bytes=%llu rss_after_bytes=%llu rss_delta_bytes=%lld\n",
                            static_cast<unsigned long long>(*Result.RssBefore),
                            static_cast<unsigned long long>(*Result.RssAfter),
                            static_cast<long long>(Delta));
            }
            else
            {
                std::puts("rss=unavailable");
            }
        }

    } // namespace

    auto Run(const Options &Settings) -> int
    {
        const auto TraceValue = MakeTrace(Settings);
        std::printf("trace_hash=%016llx commands=%zu capacity=%zu producers=%zu seed=%llu\n",
                    static_cast<unsigned long long>(TraceValue.Hash), TraceValue.Commands.size(),
                    Settings.Capacity, Settings.Producers,
                    static_cast<unsigned long long>(Settings.Seed));
        std::puts("trace_boundary=one pre-generated command set is partitioned by index modulo producer count; producer count is excluded from trace_hash");
        std::puts("allocation_boundary=global ordinary and aligned new/new[] calls during timed queue work; setup, trace storage, thread creation and allocator retention are excluded");
        std::puts("rss_boundary=working set sampled before and after timed work when the platform exposes it");
        std::puts("close_race_boundary=public API cannot deterministically pause after ticket reservation; no production test hook is used, so the timed path reports observed Closed values only");
        if (TraceValue.Commands.size() != Settings.Commands || !RunContractProbe())
        {
            std::fprintf(stderr, "[FAIL] mailbox contract or trace validation failed\n");
            return 1;
        }
        if (Settings.ValidateOnly)
        {
            const auto Valid = RunLifecyclePreflight(Settings, TraceValue);
            if (Valid) std::puts("semantic_preflight=pass");
            return Valid ? 0 : 1;
        }

        for (std::size_t Round = 1; Round <= Settings.Rounds; ++Round)
        {
            const auto Result = RunSample(Settings, TraceValue);
            PrintMeasurement(Result, Round);
            if (Result.Invalid)
            {
                std::fprintf(stderr, "[FAIL] mailbox measurement validation failed: %s\n",
                             Result.InvalidReason);
                return 1;
            }
        }
        return 0;
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
        const auto ActualSize = Size == 0 ? std::size_t{1} : Size;
        void *Memory = nullptr;
#if defined(_WIN32)
        Memory = _aligned_malloc(ActualSize, Alignment);
#else
        const auto RoundedSize = ((ActualSize + Alignment - 1) / Alignment) * Alignment;
        Memory = std::aligned_alloc(Alignment, RoundedSize);
#endif
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

    auto ReleaseAligned(void *Memory) noexcept -> void
    {
#if defined(_WIN32)
        _aligned_free(Memory);
#else
        std::free(Memory);
#endif
    }

} // namespace Prism::Runtime::Perf

auto operator new(const std::size_t Size) -> void *
{
    return Prism::Runtime::Perf::Allocate(Size);
}

auto operator new[](const std::size_t Size) -> void *
{
    return Prism::Runtime::Perf::Allocate(Size);
}

auto operator new(const std::size_t Size, const std::nothrow_t &) noexcept -> void *
{
    try
    {
        return Prism::Runtime::Perf::Allocate(Size);
    }
    catch (...)
    {
        return nullptr;
    }
}

auto operator new[](const std::size_t Size, const std::nothrow_t &Tag) noexcept -> void *
{
    return ::operator new(Size, Tag);
}

auto operator new(const std::size_t Size, const std::align_val_t Alignment) -> void *
{
    return Prism::Runtime::Perf::AllocateAligned(Size, static_cast<std::size_t>(Alignment));
}

auto operator new[](const std::size_t Size, const std::align_val_t Alignment) -> void *
{
    return ::operator new(Size, Alignment);
}

auto operator new(const std::size_t Size, const std::align_val_t Alignment,
                  const std::nothrow_t &) noexcept -> void *
{
    try
    {
        return Prism::Runtime::Perf::AllocateAligned(Size,
                                                       static_cast<std::size_t>(Alignment));
    }
    catch (...)
    {
        return nullptr;
    }
}

auto operator new[](const std::size_t Size, const std::align_val_t Alignment,
                    const std::nothrow_t &Tag) noexcept -> void *
{
    return ::operator new(Size, Alignment, Tag);
}

auto operator delete(void *Memory) noexcept -> void
{
    std::free(Memory);
}

auto operator delete[](void *Memory) noexcept -> void
{
    std::free(Memory);
}

auto operator delete(void *Memory, const std::size_t) noexcept -> void
{
    std::free(Memory);
}

auto operator delete[](void *Memory, const std::size_t) noexcept -> void
{
    std::free(Memory);
}

auto operator delete(void *Memory, const std::nothrow_t &) noexcept -> void
{
    std::free(Memory);
}

auto operator delete[](void *Memory, const std::nothrow_t &) noexcept -> void
{
    std::free(Memory);
}

auto operator delete(void *Memory, const std::align_val_t) noexcept -> void
{
    Prism::Runtime::Perf::ReleaseAligned(Memory);
}

auto operator delete[](void *Memory, const std::align_val_t) noexcept -> void
{
    Prism::Runtime::Perf::ReleaseAligned(Memory);
}

auto operator delete(void *Memory, const std::size_t, const std::align_val_t) noexcept -> void
{
    Prism::Runtime::Perf::ReleaseAligned(Memory);
}

auto operator delete[](void *Memory, const std::size_t, const std::align_val_t) noexcept -> void
{
    Prism::Runtime::Perf::ReleaseAligned(Memory);
}
