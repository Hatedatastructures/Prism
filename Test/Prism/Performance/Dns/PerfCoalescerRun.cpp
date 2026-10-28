/**
 * @file PerfCoalescerRun.cpp
 * @brief coalescer preflight、round 编排与 1/2/4 owner 矩阵。
 */

#include "PerfCoalescer.hpp"

namespace DnsPerf
{
    [[nodiscard]] auto RunAllocationPreflight() -> bool;
    [[nodiscard]] auto RunSingleFlightPreflight(std::size_t WaiterCount, bool RequireAligned) -> bool;
    [[nodiscard]] auto RunResolverCancellationPreflight() -> bool;
    [[nodiscard]] auto RunResolverLastWaiterCancellationPreflight() -> bool;
    [[nodiscard]] auto RunResolverCachePreflight() -> bool;
    [[nodiscard]] auto PercentileNs(std::vector<std::uint64_t> Values, std::size_t Percent) -> std::uint64_t;
    [[nodiscard]] auto ErrorToken(std::string Value) -> std::string;
    [[nodiscard]] auto MakeCoalescerOwner() -> std::unique_ptr<CoalescerOwner>;
    [[nodiscard]] auto StartDnsProcessSampler() -> DnsSamplerHandle;
    auto BeginDnsProcessSampler(const DnsSamplerHandle &Sampler) -> void;
    [[nodiscard]] auto FinishDnsProcessSampler(
        const DnsSamplerHandle &Sampler, std::uint64_t EndNs) -> DnsSamplerMetrics;
#ifdef _WIN32
    [[nodiscard]] auto SampleDnsProcess() -> DnsProcessSample;
#endif
    auto PrintCoalescerRound(std::size_t OwnerCount, std::size_t Round,
                             const CoalescerRoundMetrics &Result) -> void;
    [[nodiscard]] auto RunOwnerWarmup(CoalescerOwner &Owner) -> bool
    {
        Owner.PrepareRound();
        const auto Signals = Owner.MakeRoundSignals();
        auto ReadyFuture = Signals->Ready->Promise.get_future();
        auto DoneFuture = Signals->Done->Promise.get_future();
        Owner.LaunchRound(1, Signals);
        if (ReadyFuture.wait_for(std::chrono::seconds(5)) != std::future_status::ready ||
            !ReadyFuture.get()) return false;
        Owner.OpenRound(Signals);
        if (DoneFuture.wait_for(std::chrono::seconds(10)) != std::future_status::ready)
        {
            Owner.AbortRound();
            return false;
        }
        return DoneFuture.get() && Signals->CompletedOperations == 1U;
    }

    [[nodiscard]] auto RunRoundCancellationPreflight() -> bool
    {
        auto Owner = MakeCoalescerOwner();
        if (!Owner->Start())
        {
            return false;
        }
        Owner->PrepareRound();
        const auto Signals = Owner->MakeRoundSignals();
        auto ReadyFuture = Signals->Ready->Promise.get_future();
        auto DoneFuture = Signals->Done->Promise.get_future();
        Owner->LaunchRound(1, Signals);
        const auto Ready = ReadyFuture.wait_for(std::chrono::seconds(5)) ==
                           std::future_status::ready && ReadyFuture.get();
        Owner->OpenRound(Signals);
        Owner->AbortRound();
        const auto Done = DoneFuture.wait_for(std::chrono::seconds(5)) ==
                          std::future_status::ready;
        const auto Canceled = Done && !DoneFuture.get();
        const auto Retired = Signals->Retired &&
            Signals->Retired->Promise.get_future().wait_for(std::chrono::seconds(5)) ==
                std::future_status::ready;
        const auto Stopped = Owner->Stop();
        const auto Passed = Ready && Canceled && Retired && Stopped;
        std::printf(
            "dns-preflight round-cancel ready=%s done=%s canceled=%s retired=%s stopped=%s result=%s\n",
            Ready ? "yes" : "no", Done ? "yes" : "no", Canceled ? "yes" : "no",
            Retired ? "yes" : "no", Stopped ? "yes" : "no", Passed ? "pass" : "fail");
        return Passed;
    }

    auto PrintCoalescerRound(
        const std::size_t OwnerCount, const std::size_t Round,
        const CoalescerRoundMetrics &Result) -> void
    {
        const auto Throughput = Result.WallNs == 0U
            ? 0.0 : static_cast<double>(Result.Operations) * 1e9 / Result.WallNs;
        std::printf(
            "dns-coalescer owners=%zu round=%zu trace_version=%.*s trace_hash=%016llx "
            "flights=%zu waiters=%zu operations=%llu wall_ns=%llu throughput_ops_sec=%.3f "
            "latency_p50_ns=%llu latency_p95_ns=%llu latency_p99_ns=%llu queries=%zu responses=%zu "
            "expected_queries=%zu ordinary_count=%zu ordinary_bytes=%zu aligned_count=%zu aligned_bytes=%zu "
            "sampler_samples=%zu sampler_valid=%s error_category=%s error_value=%d error_message=%s valid=%s\n",
            OwnerCount, Round + 1U, static_cast<int>(CoalescerTraceVersion.size()),
            CoalescerTraceVersion.data(), static_cast<unsigned long long>(TraceHash()),
            CoalescerFlights, CoalescerWaiters,
            static_cast<unsigned long long>(Result.Operations),
            static_cast<unsigned long long>(Result.WallNs), Throughput,
            static_cast<unsigned long long>(Result.LatencyP50),
            static_cast<unsigned long long>(Result.LatencyP95),
            static_cast<unsigned long long>(Result.LatencyP99), Result.Queries, Result.Responses,
            Result.ExpectedQueries, Result.Allocations.OrdinaryAllocations,
            Result.Allocations.OrdinaryBytes, Result.Allocations.AlignedAllocations,
            Result.Allocations.AlignedBytes, Result.SampleCount,
            Result.SamplerValid ? "yes" : "no", ErrorToken(Result.Error.Category).c_str(),
            Result.Error.Value, ErrorToken(Result.Error.Message).c_str(),
            Result.Valid ? "yes" : "no");
#ifdef _WIN32
        std::printf(
            "dns-coalescer-process owners=%zu round=%zu boundary=ready-before-after observer=included "
            "teardown=excluded cpu_user_100ns=%llu cpu_kernel_100ns=%llu "
            "working_set_before=%zu working_set_peak=%zu working_set_after=%zu "
            "private_before=%zu private_peak=%zu private_after=%zu\n",
            OwnerCount, Round + 1U,
            static_cast<unsigned long long>(Result.After.User100ns - Result.Before.User100ns),
            static_cast<unsigned long long>(Result.After.Kernel100ns - Result.Before.Kernel100ns),
            Result.Before.WorkingSet, Result.PeakWorkingSet, Result.After.WorkingSet,
            Result.Before.PrivateUsage, Result.PeakPrivateUsage, Result.After.PrivateUsage);
#else
        std::printf(
            "dns-coalescer-process owners=%zu round=%zu boundary=ready-before-after observer=included "
            "teardown=excluded cpu_user_100ns=null cpu_kernel_100ns=null "
            "working_set_before=null working_set_peak=null working_set_after=null "
            "private_before=null private_peak=null private_after=null metrics=unavailable\n",
            OwnerCount, Round + 1U);
#endif
    }

    struct CoalescerGroupState final
    {
        std::size_t OwnerCount{0};
        std::vector<std::unique_ptr<CoalescerOwner>> Owners;
        std::array<std::uint64_t, CoalescerRounds> Walls{};
        bool &AllValid;
    };

    struct CoalescerRoundState final
    {
        CoalescerGroupState &Group;
        std::size_t Round{0};
        CoalescerRoundMetrics Result;
        DnsSamplerHandle Sampler;
        std::vector<std::shared_ptr<CoalescerRoundSignals>> Signals;
        std::vector<std::future<bool>> ReadyFutures;
        std::vector<std::future<bool>> DoneFutures;
        std::array<bool, 4> DoneReady{true, true, true, true};
        bool Completed{true};
        bool CleanupComplete{true};
        std::uint64_t BeginNs{0};
        std::uint64_t EndNs{0};
    };

    [[nodiscard]] auto RunCoalescerPreflights() -> bool
    {
        struct PreflightCheck final
        {
            const char *Message;
            bool (*Check)();
        };
        const auto Checks = std::array<PreflightCheck, 5>{
            PreflightCheck{"coalescer-compare allocation preflight failed",
                           &RunAllocationPreflight},
            PreflightCheck{"coalescer-compare follower-cancellation preflight failed",
                           &RunResolverCancellationPreflight},
            PreflightCheck{"coalescer-compare all-pending cancellation preflight failed",
                           &RunResolverLastWaiterCancellationPreflight},
            PreflightCheck{"coalescer-compare cache preflight failed",
                           &RunResolverCachePreflight},
            PreflightCheck{"coalescer-compare round-cancellation preflight failed",
                           &RunRoundCancellationPreflight}};
        if (!RunSingleFlightPreflight(CoalescerWaiters, true))
        {
            std::printf("coalescer-compare single-flight preflight failed\n");
            return false;
        }
        for (const auto &Check : Checks)
        {
            if (!Check.Check())
            {
                std::printf("%s\n", Check.Message);
                return false;
            }
        }
        return true;
    }

    auto StartCoalescerGroup(CoalescerGroupState &Group) -> void
    {
        Group.Owners.reserve(Group.OwnerCount);
        for (std::size_t Index = 0; Index < Group.OwnerCount; ++Index)
        {
            auto Owner = MakeCoalescerOwner();
            if (!Owner->Start())
            {
                Group.AllValid = false;
                return;
            }
            Group.Owners.push_back(std::move(Owner));
        }
    }

    auto WarmupCoalescerGroup(CoalescerGroupState &Group) -> void
    {
        if (Group.Owners.size() != Group.OwnerCount)
        {
            return;
        }
        for (auto &Owner : Group.Owners)
        {
            if (!RunOwnerWarmup(*Owner))
            {
                Group.AllValid = false;
            }
        }
    }

    auto PrepareCoalescerRound(CoalescerRoundState &State) -> bool
    {
        State.Sampler = StartDnsProcessSampler();
        if (!State.Sampler)
        {
            State.Group.AllValid = false;
            return false;
        }
        State.Signals.reserve(State.Group.OwnerCount);
        State.ReadyFutures.reserve(State.Group.OwnerCount);
        State.DoneFutures.reserve(State.Group.OwnerCount);
        for (auto &Owner : State.Group.Owners)
        {
            Owner->PrepareRound();
            auto Signals = Owner->MakeRoundSignals();
            State.ReadyFutures.push_back(Signals->Ready->Promise.get_future());
            State.DoneFutures.push_back(Signals->Done->Promise.get_future());
            Owner->LaunchRound(CoalescerFlights, Signals);
            State.Signals.push_back(std::move(Signals));
        }
        bool Ready = true;
        for (auto &Future : State.ReadyFutures)
        {
            if (Future.wait_for(std::chrono::seconds(5)) != std::future_status::ready ||
                !Future.get())
            {
                Ready = false;
            }
        }
        if (Ready)
        {
            return true;
        }
        State.Result.Error = {"startup", 2, "owner_ready"};
        State.Group.AllValid = false;
        for (auto &Owner : State.Group.Owners)
        {
            Owner->AbortRound();
        }
        for (auto &Future : State.DoneFutures)
        {
            if (Future.wait_for(std::chrono::seconds(5)) != std::future_status::ready)
            {
                State.Group.AllValid = false;
            }
        }
        (void)FinishDnsProcessSampler(State.Sampler, NowNs());
        PrintCoalescerRound(State.Group.OwnerCount, State.Round, State.Result);
        return false;
    }

    auto RunCoalescerWindow(CoalescerRoundState &State) -> void
    {
#ifdef _WIN32
        State.Result.Before = SampleDnsProcess();
#endif
        DnsPerfAllocation::Start();
        State.BeginNs = NowNs();
        BeginDnsProcessSampler(State.Sampler);
        for (std::size_t Index = 0; Index < State.Group.OwnerCount; ++Index)
        {
            State.Group.Owners[Index]->OpenRound(State.Signals[Index]);
        }
        for (std::size_t Index = 0; Index < State.Group.OwnerCount; ++Index)
        {
            if (State.DoneFutures[Index].wait_for(std::chrono::seconds(120)) !=
                std::future_status::ready)
            {
                State.Completed = false;
                State.DoneReady[Index] = false;
                for (auto &Owner : State.Group.Owners)
                {
                    Owner->AbortRound();
                }
                if (State.DoneFutures[Index].wait_for(std::chrono::seconds(5)) !=
                    std::future_status::ready)
                {
                    State.CleanupComplete = false;
                }
                else
                {
                    State.DoneReady[Index] = true;
                }
            }
        }
        State.EndNs = NowNs();
        DnsPerfAllocation::Stop();
#ifdef _WIN32
        State.Result.After = SampleDnsProcess();
#endif
        const auto SamplerMetrics = FinishDnsProcessSampler(State.Sampler, State.EndNs);
        State.Result.WallNs = State.EndNs - State.BeginNs;
        State.Result.Allocations = DnsPerfAllocation::Read();
        State.Result.SampleCount = SamplerMetrics.SampleCount;
        State.Result.PeakWorkingSet = SamplerMetrics.PeakWorkingSet;
        State.Result.PeakPrivateUsage = SamplerMetrics.PeakPrivateUsage;
        State.Result.SamplerValid = SamplerMetrics.Valid;
    }

    auto FinalizeCoalescerRound(CoalescerRoundState &State) -> void
    {
        std::vector<std::uint64_t> Latencies;
        Latencies.reserve(State.Group.OwnerCount * CoalescerFlights);
        for (std::size_t Index = 0; Index < State.Group.OwnerCount; ++Index)
        {
            State.Result.Queries += State.Group.Owners[Index]->QueryDelta();
            State.Result.Responses += State.Group.Owners[Index]->ResponseDelta();
            State.Result.Operations += State.Signals[Index]->CompletedOperations *
                (CoalescerWaiters + 1U);
            const auto &OwnerLatencies = State.Group.Owners[Index]->Latencies();
            Latencies.insert(Latencies.end(), OwnerLatencies.begin(), OwnerLatencies.end());
            if (State.Signals[Index]->Error.Category != "none" &&
                State.Result.Error.Category == "none")
            {
                State.Result.Error = State.Signals[Index]->Error;
            }
            if (State.DoneReady[Index] && State.DoneFutures[Index].valid() &&
                !State.DoneFutures[Index].get())
            {
                State.Completed = false;
            }
            State.Completed = State.Completed &&
                State.Signals[Index]->CompletedOperations == CoalescerFlights;
        }
        State.Result.ExpectedQueries = State.Group.OwnerCount * CoalescerFlights * 2U;
        State.Result.LatencyP50 = PercentileNs(Latencies, 50);
        State.Result.LatencyP95 = PercentileNs(Latencies, 95);
        State.Result.LatencyP99 = PercentileNs(Latencies, 99);
        State.Result.Valid = State.Completed &&
            State.Result.Queries == State.Result.ExpectedQueries &&
            State.Result.Responses == State.Result.ExpectedQueries &&
            State.Result.Operations == State.Group.OwnerCount * CoalescerFlights *
                (CoalescerWaiters + 1U) &&
            State.Result.Allocations.OrdinaryAllocations > 0U &&
            State.Result.Allocations.OrdinaryBytes > 0U &&
            (State.Result.Allocations.AlignedAllocations != 0U ||
             State.Result.Allocations.AlignedBytes == 0U) &&
            Latencies.size() == State.Group.OwnerCount * CoalescerFlights &&
            State.Result.Error.Category == "none";
#ifdef _WIN32
        State.Result.Valid = State.Result.Valid && State.Result.Before.Available &&
            State.Result.After.Available && State.Result.SampleCount > 0U &&
            State.Result.SamplerValid;
#endif
    }

    auto RunCoalescerRound(CoalescerGroupState &Group, const std::size_t Round) -> void
    {
        if (Group.Owners.size() != Group.OwnerCount)
        {
            CoalescerRoundState State{Group, Round};
            State.Result.Error = {"startup", 2, "owner_start"};
            State.Result.Valid = false;
            Group.AllValid = false;
            PrintCoalescerRound(Group.OwnerCount, Round, State.Result);
            return;
        }
        CoalescerRoundState State{Group, Round};
        if (!PrepareCoalescerRound(State))
        {
            return;
        }
        RunCoalescerWindow(State);
        if (!State.CleanupComplete)
        {
            State.Result.Error = {"timeout", 1, "round_done"};
            State.Result.Valid = false;
            Group.AllValid = false;
            PrintCoalescerRound(Group.OwnerCount, Round, State.Result);
            return;
        }
        FinalizeCoalescerRound(State);
        PrintCoalescerRound(Group.OwnerCount, Round, State.Result);
        Group.Walls[Round] = State.Result.WallNs;
        Group.AllValid = Group.AllValid && State.Result.Valid;
    }

    auto PrintCoalescerSummary(const CoalescerGroupState &Group) -> void
    {
        const std::vector<std::uint64_t> WallValues(Group.Walls.begin(), Group.Walls.end());
        std::printf(
            "dns-coalescer-summary owners=%zu trace_version=%.*s trace_hash=%016llx "
            "wall_p50_ns=%llu wall_p95_ns=%llu wall_p99_ns=%llu valid=%s\n",
            Group.OwnerCount, static_cast<int>(CoalescerTraceVersion.size()),
            CoalescerTraceVersion.data(), static_cast<unsigned long long>(TraceHash()),
            static_cast<unsigned long long>(PercentileNs(WallValues, 50)),
            static_cast<unsigned long long>(PercentileNs(WallValues, 95)),
            static_cast<unsigned long long>(PercentileNs(WallValues, 99)),
            Group.AllValid ? "yes" : "no");
    }

    auto StopCoalescerGroup(CoalescerGroupState &Group) -> void
    {
        for (auto &Owner : Group.Owners)
        {
            if (!Owner->Stop())
            {
                Group.AllValid = false;
            }
        }
    }

    // 计时窗口结束后再输出报告，避免报告分配进入测量结果。
    [[nodiscard]] auto RunCoalescerCompare() -> int
    {
        if (!RunAllocationPreflight() || !RunSingleFlightPreflight(CoalescerWaiters, true) ||
            !RunResolverCancellationPreflight() ||
            !RunResolverLastWaiterCancellationPreflight() ||
            !RunResolverCachePreflight() || !RunRoundCancellationPreflight())
        {
            std::printf("coalescer-compare preflight failed\n");
            return 1;
        }
        bool AllValid = true;
#ifdef _WIN32
        (void)SampleDnsProcess();
#endif
        for (const auto OwnerCount : {std::size_t{1}, std::size_t{2}, std::size_t{4}})
        {
            CoalescerGroupState Group{OwnerCount, {}, {}, AllValid};
            StartCoalescerGroup(Group);
            WarmupCoalescerGroup(Group);
            for (std::size_t Round = 0; Round < CoalescerRounds; ++Round)
            {
                RunCoalescerRound(Group, Round);
            }
            PrintCoalescerSummary(Group);
            StopCoalescerGroup(Group);
        }
        return AllValid ? 0 : 1;
    }

}
