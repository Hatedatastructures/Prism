/**
 * @file DnsPerfRuntime.cpp
 * @brief fake DNS server、resolver preflight 与 runtime helper 所有者。
 */

#include "DnsPerfRuntime.hpp"

namespace DnsPerf
{
    struct SingleFlightWaiterRequest final
    {
        const std::shared_ptr<GateChannel> &Started;
        const std::shared_ptr<GateChannel> &Done;
        Prism::Network::Dns::Resolver &Resolver;
        std::vector<bool> &Results;
        std::size_t Index{0};
    };

    auto RunSingleFlightWaiter(SingleFlightWaiterRequest Request) -> Net::awaitable<void>
    {
        (void)Request.Started->try_send(boost::system::error_code{});
        const auto Addresses = co_await Request.Resolver.AsyncResolve(
            "singleflight.perf.example.com");
        Request.Results[Request.Index] = Addresses && Addresses->Size() == 1;
        (void)Request.Done->try_send(boost::system::error_code{});
    }

    struct SingleFlightScenarioRequest final
    {
        Net::io_context &IoContext;
        PerfDnsRuntime &Runtime;
        Prism::Network::Dns::Resolver &Resolver;
        const std::shared_ptr<GateChannel> &Release;
        const std::shared_ptr<GateChannel> &QuerySignal;
        std::size_t WaiterCount{0};
        std::vector<bool> &Results;
        bool &ScenarioOk;
    };

    auto RunSingleFlightScenario(SingleFlightScenarioRequest Request)
        -> Net::awaitable<void>
    {
        const auto Started = std::make_shared<GateChannel>(
            Request.IoContext.get_executor(), Request.WaiterCount);
        const auto Done = std::make_shared<GateChannel>(
            Request.IoContext.get_executor(), Request.WaiterCount);
        for (std::size_t Index = 0; Index < Request.WaiterCount; ++Index)
        {
            Net::co_spawn(
                Request.IoContext,
                RunSingleFlightWaiter(SingleFlightWaiterRequest{
                    Started, Done, Request.Resolver, Request.Results, Index}),
                Net::detached);
        }
        for (std::size_t Index = 0; Index < Request.WaiterCount; ++Index)
        {
            co_await Started->async_receive(Net::use_awaitable);
        }
        co_await Request.QuerySignal->async_receive(Net::use_awaitable);
        const auto OneUpstreamQuery = Request.Runtime.Server()->QueryCount() == 1;
        Net::post(Request.Runtime.IoContext(), [Release = Request.Release]
        { (void)Release->try_send(boost::system::error_code{}); });
        for (std::size_t Index = 0; Index < Request.WaiterCount; ++Index)
        {
            co_await Done->async_receive(Net::use_awaitable);
        }
        const auto AllSucceeded = std::all_of(
            Request.Results.begin(), Request.Results.end(),
            [](const auto Value) { return Value; });
        const auto Isolated = co_await Request.Resolver.AsyncResolve(
            "isolated.perf.example.com");
        Request.ScenarioOk = OneUpstreamQuery && AllSucceeded && Isolated &&
            Isolated->Size() == 1 && Request.Runtime.Server()->QueryCount() == 2 &&
            Request.Runtime.Server()->ResponseCount() == 2;
    }

    [[nodiscard]] auto RunAllocationPreflight() -> bool
    {
        auto *Ordinary = new std::uint8_t[17];
        auto *OrdinaryNoThrow = new (std::nothrow) std::uint8_t[19];
        const auto OrdinaryOk = Ordinary != nullptr && OrdinaryNoThrow != nullptr;
        delete[] Ordinary;
        delete[] OrdinaryNoThrow;

        auto *Aligned = new DnsAlignedProbe;
        auto *AlignedArray = new DnsAlignedProbe[2];
        auto *AlignedNoThrow = new (std::nothrow) DnsAlignedProbe;
        auto *AlignedArrayNoThrow = new (std::nothrow) DnsAlignedProbe[2];
        const auto AlignedOk = Aligned != nullptr && AlignedArray != nullptr &&
            AlignedNoThrow != nullptr && AlignedArrayNoThrow != nullptr &&
            (reinterpret_cast<std::uintptr_t>(Aligned) % alignof(DnsAlignedProbe)) == 0U &&
            (reinterpret_cast<std::uintptr_t>(AlignedArray) % alignof(DnsAlignedProbe)) == 0U &&
            (reinterpret_cast<std::uintptr_t>(AlignedNoThrow) % alignof(DnsAlignedProbe)) == 0U &&
            (reinterpret_cast<std::uintptr_t>(AlignedArrayNoThrow) % alignof(DnsAlignedProbe)) == 0U;
        delete Aligned;
        delete[] AlignedArray;
        delete AlignedNoThrow;
        delete[] AlignedArrayNoThrow;
        return OrdinaryOk && AlignedOk;
    }

    [[nodiscard]] auto RunSingleFlightPreflight(
        const std::size_t WaiterCount,
        const bool EmitResult) -> bool
    {
        Net::io_context IoContext;
        PerfDnsRuntime Runtime;
        std::vector<DnsAlignedProbe> AllocationProbe(1);
        AllocationProbe[0].Bytes[0] = std::byte{0x5A};
        const auto Release = std::make_shared<GateChannel>(Runtime.IoContext().get_executor(), 1);
        const auto QuerySignal = std::make_shared<GateChannel>(IoContext.get_executor(), 1);
        Runtime.Server()->HoldFirstResponse(Release);
        Runtime.Server()->ObserveQueries(IoContext, QuerySignal);
        if (!Runtime.Start()) return false;
        Prism::Network::Dns::Resolver Resolver(
            IoContext.get_executor(), MakeResolverConfig(ResolverConfigRequest{*Runtime.Server(), true}));
        std::vector<bool> Results(WaiterCount, false);
        bool ScenarioOk = false;
        RunDnsCoroutine(IoContext, RunSingleFlightScenario(SingleFlightScenarioRequest{
            IoContext, Runtime, Resolver, Release, QuerySignal, WaiterCount,
            Results, ScenarioOk}));
        if (EmitResult)
        {
            std::printf(
                "dns-preflight singleflight waiters=%zu upstream=%zu responses=%zu isolated=yes result=%s\n",
                WaiterCount, Runtime.Server()->QueryCount(), Runtime.Server()->ResponseCount(),
                ScenarioOk ? "pass" : "fail");
        }
        return ScenarioOk;
    }

    struct CancellationCallState final
    {
        bool Canceled{false};
        bool Completed{false};
        ErrorInfo Error{};
    };

    struct CancellationCallRequest final
    {
        Net::io_context *IoContext{nullptr};
        std::shared_ptr<Prism::Network::Dns::Resolver> ResolverOwner;
        std::shared_ptr<CancellationCallState> State;
        std::string Domain;
        std::shared_ptr<Net::cancellation_signal> Cancellation;
        std::shared_ptr<GateChannel> Done;
    };

    struct CancellationCallCompletion final
    {
        std::shared_ptr<CancellationCallState> State;
        std::shared_ptr<GateChannel> Done;

        auto operator()(std::exception_ptr Failure) const -> void
        {
            if (Failure)
            {
                State->Error = MakeExceptionInfo(Failure);
                State->Canceled = IsCancellationException(Failure);
                State->Completed = false;
            }
            (void)Done->try_send(boost::system::error_code{});
        }
    };

    auto RunCancellationCall(CancellationCallRequest Request) -> Net::awaitable<void>
    {
        try
        {
            const auto Addresses = co_await Request.ResolverOwner->AsyncResolve(
                Request.Domain);
            const auto Failure = Addresses ? Prism::Fault::Failure{} : Addresses.error();
            Request.State->Error = MakeErrorInfo(Failure);
            Request.State->Canceled = IsCancellationCode(Failure);
            Request.State->Completed = Addresses && Addresses->Size() == 1U;
        }
        catch (const std::system_error &Error)
        {
            Request.State->Error = MakeErrorInfo(Error.code());
            Request.State->Canceled = IsCancellationCode(Error.code());
            Request.State->Completed = false;
        }
        catch (...)
        {
            Request.State->Error = MakeExceptionInfo(std::current_exception());
            Request.State->Canceled = IsCancellationException(std::current_exception());
            Request.State->Completed = false;
        }
    }

    auto StartCancellationCall(CancellationCallRequest Request) -> void
    {
        try
        {
            Net::co_spawn(
                *Request.IoContext,
                RunCancellationCall(Request),
                Net::bind_cancellation_slot(
                    Request.Cancellation->slot(),
                    CancellationCallCompletion{Request.State, Request.Done}));
        }
        catch (...)
        {
            Request.State->Error = MakeExceptionInfo(std::current_exception());
            Request.State->Canceled = false;
            Request.State->Completed = false;
            (void)Request.Done->try_send(boost::system::error_code{});
        }
    }

    struct CancellationLeaderRequest final
    {
        const std::shared_ptr<Prism::Network::Dns::Resolver> &Resolver;
        const std::shared_ptr<GateChannel> &Done;
        bool &Completed;
    };

    auto RunCancellationLeader(CancellationLeaderRequest Request) -> Net::awaitable<void>
    {
        const auto Addresses = co_await Request.Resolver->AsyncResolve(
            "cancel.perf.example.com");
        Request.Completed = Addresses && Addresses->Size() == 1;
        (void)Request.Done->try_send(boost::system::error_code{});
    }

    struct CancellationScenarioRequest final
    {
        Net::io_context &IoContext;
        PerfDnsRuntime &Runtime;
        const std::shared_ptr<Prism::Network::Dns::Resolver> &Resolver;
        const std::shared_ptr<Net::cancellation_signal> &Cancellation;
        const std::shared_ptr<CancellationCallState> &WaiterState;
        const std::shared_ptr<GateChannel> &Release;
        const std::shared_ptr<GateChannel> &QuerySignal;
        bool &LeaderCompleted;
        bool &WaiterCanceled;
        bool &WaiterCompleted;
        bool &ScenarioOk;
    };

    auto RunCancellationScenario(CancellationScenarioRequest Request)
        -> Net::awaitable<void>
    {
        const auto LeaderDone = std::make_shared<GateChannel>(
            Request.IoContext.get_executor(), 1);
        const auto WaiterDone = std::make_shared<GateChannel>(
            Request.IoContext.get_executor(), 1);
        Net::co_spawn(
            Request.IoContext,
            RunCancellationLeader(CancellationLeaderRequest{
                Request.Resolver, LeaderDone, Request.LeaderCompleted}),
            Net::detached);
        StartCancellationCall(CancellationCallRequest{
            &Request.IoContext, Request.Resolver, Request.WaiterState,
            "cancel.perf.example.com", Request.Cancellation, WaiterDone});
        co_await Request.QuerySignal->async_receive(Net::use_awaitable);
        Request.Cancellation->emit(Net::cancellation_type::all);
        co_await WaiterDone->async_receive(Net::use_awaitable);
        Request.WaiterCanceled = Request.WaiterState->Canceled;
        Request.WaiterCompleted = Request.WaiterState->Completed;
        Net::post(Request.Runtime.IoContext(), [Release = Request.Release]
        { (void)Release->try_send(boost::system::error_code{}); });
        co_await LeaderDone->async_receive(Net::use_awaitable);
        Request.ScenarioOk = Request.LeaderCompleted && Request.WaiterCanceled &&
            !Request.WaiterCompleted && Request.Runtime.Server()->QueryCount() == 1;
    }

    [[nodiscard]] auto RunResolverCancellationPreflight() -> bool
    {
        Net::io_context IoContext;
        PerfDnsRuntime Runtime;
        const auto Release = std::make_shared<GateChannel>(Runtime.IoContext().get_executor(), 1);
        const auto QuerySignal = std::make_shared<GateChannel>(IoContext.get_executor(), 1);
        Runtime.Server()->HoldFirstResponse(Release);
        Runtime.Server()->ObserveQueries(IoContext, QuerySignal);
        if (!Runtime.Start()) return false;
        auto Resolver = std::make_shared<Prism::Network::Dns::Resolver>(
            IoContext.get_executor(), MakeResolverConfig(ResolverConfigRequest{*Runtime.Server(), false}));
        auto Cancellation = std::make_shared<Net::cancellation_signal>();
        bool LeaderCompleted = false;
        bool WaiterCanceled = false;
        bool WaiterCompleted = false;
        auto WaiterState = std::make_shared<CancellationCallState>();
        bool ScenarioOk = false;
        RunDnsCoroutine(IoContext, RunCancellationScenario(CancellationScenarioRequest{
            IoContext, Runtime, Resolver, Cancellation, WaiterState, Release, QuerySignal,
            LeaderCompleted, WaiterCanceled, WaiterCompleted, ScenarioOk}));
        std::printf(
            "dns-preflight follower-cancel upstream=%zu responses=%zu canceled=%s leader=%s "
            "waiter_error=%s/%d/%s result=%s\n",
            Runtime.Server()->QueryCount(), Runtime.Server()->ResponseCount(),
            WaiterCanceled ? "yes" : "no", LeaderCompleted ? "yes" : "no",
            WaiterState->Error.Category.c_str(), WaiterState->Error.Value, WaiterState->Error.Message.c_str(),
            ScenarioOk ? "pass" : "fail");
        return ScenarioOk;
    }

    struct LastWaiterCancellationState final
    {
        Net::io_context *IoContext{nullptr};
        Net::io_context *RuntimeIoContext{nullptr};
        std::shared_ptr<Prism::Network::Dns::Resolver> ResolverOwner;
        std::shared_ptr<GateChannel> Release;
        std::shared_ptr<GateChannel> QuerySignal;
        std::shared_ptr<GateChannel> ResponseSignal;
        std::shared_ptr<Net::cancellation_signal> LeaderCancellation;
        std::shared_ptr<Net::cancellation_signal> FollowerCancellation;
        std::shared_ptr<CancellationCallState> Leader;
        std::shared_ptr<CancellationCallState> Follower;
        bool ScenarioOk{false};
    };

    auto RunLastWaiterCancellation(
        std::shared_ptr<LastWaiterCancellationState> State) -> Net::awaitable<void>
    {
        const auto LeaderDone = std::make_shared<GateChannel>(State->IoContext->get_executor(), 1);
        const auto FollowerDone = std::make_shared<GateChannel>(State->IoContext->get_executor(), 1);
        StartCancellationCall(CancellationCallRequest{
            State->IoContext, State->ResolverOwner, State->Leader,
            "cancel-last.perf.example.com", State->LeaderCancellation, LeaderDone});
        StartCancellationCall(CancellationCallRequest{
            State->IoContext, State->ResolverOwner, State->Follower,
            "cancel-last.perf.example.com", State->FollowerCancellation, FollowerDone});
        try
        {
            co_await State->QuerySignal->async_receive(Net::use_awaitable);
            std::fprintf(stderr, "dns-last-cancel stage=query-observed\n");
            State->LeaderCancellation->emit(Net::cancellation_type::all);
            State->FollowerCancellation->emit(Net::cancellation_type::all);
            co_await LeaderDone->async_receive(Net::use_awaitable);
            std::fprintf(stderr, "dns-last-cancel stage=leader-retired\n");
            co_await FollowerDone->async_receive(Net::use_awaitable);
            std::fprintf(stderr, "dns-last-cancel stage=follower-retired\n");
            Net::post(*State->RuntimeIoContext, [Release = State->Release]
            { (void)Release->try_send(boost::system::error_code{}); });
            co_await State->ResponseSignal->async_receive(Net::use_awaitable);
            std::fprintf(stderr, "dns-last-cancel stage=response-observed\n");

            const auto Recovery = co_await State->ResolverOwner->AsyncResolve(
                "cancel-last.perf.example.com");
            State->ScenarioOk = State->Leader->Canceled && State->Follower->Canceled &&
                !State->Leader->Completed && !State->Follower->Completed &&
                Recovery && Recovery->Size() == 1U;
        }
        catch (...)
        {
            State->ScenarioOk = false;
        }
        State->ResolverOwner.reset();
    }

    [[nodiscard]] auto RunResolverLastWaiterCancellationPreflight() -> bool
    {
        Net::io_context IoContext;
        PerfDnsRuntime Runtime;
        const auto Release = std::make_shared<GateChannel>(Runtime.IoContext().get_executor(), 1);
        const auto QuerySignal = std::make_shared<GateChannel>(IoContext.get_executor(), 1);
        const auto ResponseSignal = std::make_shared<GateChannel>(IoContext.get_executor(), 1);
        Runtime.Server()->HoldFirstResponse(Release);
        Runtime.Server()->ObserveQueries(IoContext, QuerySignal);
        Runtime.Server()->ObserveResponses(IoContext, ResponseSignal);
        if (!Runtime.Start()) return false;

        auto State = std::make_shared<LastWaiterCancellationState>();
        State->IoContext = &IoContext;
        State->RuntimeIoContext = &Runtime.IoContext();
        State->ResolverOwner = std::make_shared<Prism::Network::Dns::Resolver>(
            IoContext.get_executor(), MakeResolverConfig(ResolverConfigRequest{*Runtime.Server(), true}));
        State->Release = Release;
        State->QuerySignal = QuerySignal;
        State->ResponseSignal = ResponseSignal;
        State->LeaderCancellation = std::make_shared<Net::cancellation_signal>();
        State->FollowerCancellation = std::make_shared<Net::cancellation_signal>();
        State->Leader = std::make_shared<CancellationCallState>();
        State->Follower = std::make_shared<CancellationCallState>();
        const auto DriverOk = RunDnsCoroutineNatural(
            IoContext, RunLastWaiterCancellation(State));
        const auto ScenarioOk = State->ScenarioOk;
        std::printf(
            "dns-preflight last-waiter-cancel contract=all_pending upstream=%zu responses=%zu "
            "leader={canceled:%s,completed:%s,error:%s/%d/%s} "
            "follower={canceled:%s,completed:%s,error:%s/%d/%s} result=%s\n",
            Runtime.Server()->QueryCount(), Runtime.Server()->ResponseCount(),
            State->Leader->Canceled ? "yes" : "no", State->Leader->Completed ? "yes" : "no",
            State->Leader->Error.Category.c_str(), State->Leader->Error.Value, State->Leader->Error.Message.c_str(),
            State->Follower->Canceled ? "yes" : "no", State->Follower->Completed ? "yes" : "no",
            State->Follower->Error.Category.c_str(), State->Follower->Error.Value, State->Follower->Error.Message.c_str(),
            DriverOk && ScenarioOk ? "pass" : "fail");
        return DriverOk && ScenarioOk;
    }

    struct CachePreflightRequest final
    {
        Net::io_context &IoContext;
        PerfDnsRuntime &Runtime;
        Prism::Network::Dns::Resolver &Resolver;
        bool &Result;
    };

    auto RunTtlCacheScenario(CachePreflightRequest Request) -> Net::awaitable<void>
    {
        const auto First = co_await Request.Resolver.AsyncResolve("ttl.perf.example.com");
        const auto Hit = co_await Request.Resolver.AsyncResolve("ttl.perf.example.com");
        Net::steady_timer Timer(Request.IoContext.get_executor());
        Timer.expires_after(std::chrono::milliseconds(1100));
        co_await Timer.async_wait(Net::use_awaitable);
        const auto Expired = co_await Request.Resolver.AsyncResolve("ttl.perf.example.com");
        Request.Result = First && Hit && Expired &&
            Request.Runtime.Server()->QueryCount() == 2;
    }

    auto RunEvictCacheScenario(CachePreflightRequest Request) -> Net::awaitable<void>
    {
        for (const auto Domain : {"evict-a.perf.example.com", "evict-b.perf.example.com",
                                  "evict-c.perf.example.com", "evict-a.perf.example.com"})
        {
            const auto Result = co_await Request.Resolver.AsyncResolve(Domain);
            if (!Result)
            {
                Request.Result = false;
                co_return;
            }
        }
        Request.Result = Request.Runtime.Server()->QueryCount() == 4;
    }

    auto RunNegativeCacheScenario(CachePreflightRequest Request) -> Net::awaitable<void>
    {
        const auto First = co_await Request.Resolver.AsyncResolve(
            "negative.perf.example.com");
        const auto Cached = co_await Request.Resolver.AsyncResolve(
            "negative.perf.example.com");
        Request.Result = !First && !Cached &&
            First.error().Code == Prism::Fault::Code::DnsFailed &&
            Cached.error().Code == Prism::Fault::Code::DnsFailed &&
            Request.Runtime.Server()->QueryCount() == 1;
    }

    [[nodiscard]] auto RunResolverCachePreflight() -> bool
    {
        bool TtlOk = false;
        bool EvictOk = false;
        bool NegativeOk = false;
        {
            Net::io_context IoContext;
            PerfDnsRuntime Runtime;
            if (!Runtime.Start()) return false;
            Prism::Network::Dns::Resolver Resolver(IoContext.get_executor(),
                MakeResolverConfig(ResolverConfigRequest{*Runtime.Server(), true, 8,
                                      std::chrono::seconds(1), std::chrono::seconds(1)}));
            RunDnsCoroutine(IoContext, RunTtlCacheScenario(
                CachePreflightRequest{IoContext, Runtime, Resolver, TtlOk}));
            std::printf("dns-preflight ttl upstream=%zu result=%s\n",
                        Runtime.Server()->QueryCount(), TtlOk ? "pass" : "fail");
        }
        {
            Net::io_context IoContext;
            PerfDnsRuntime Runtime;
            if (!Runtime.Start()) return false;
            Prism::Network::Dns::Resolver Resolver(IoContext.get_executor(),
                MakeResolverConfig(ResolverConfigRequest{*Runtime.Server(), true, 2,
                                      std::chrono::seconds(60), std::chrono::seconds(60)}));
            RunDnsCoroutine(IoContext, RunEvictCacheScenario(
                CachePreflightRequest{IoContext, Runtime, Resolver, EvictOk}));
            std::printf("dns-preflight evict upstream=%zu result=%s\n",
                        Runtime.Server()->QueryCount(), EvictOk ? "pass" : "fail");
        }
        {
            Net::io_context IoContext;
            PerfDnsRuntime Runtime;
            Runtime.Server()->SetEmptyAnswer(true);
            if (!Runtime.Start()) return false;
            Prism::Network::Dns::Resolver Resolver(
                IoContext.get_executor(), MakeResolverConfig(ResolverConfigRequest{*Runtime.Server(), true}));
            RunDnsCoroutine(IoContext, RunNegativeCacheScenario(
                CachePreflightRequest{IoContext, Runtime, Resolver, NegativeOk}));
            std::printf("dns-preflight negative upstream=%zu result=%s\n",
                        Runtime.Server()->QueryCount(), NegativeOk ? "pass" : "fail");
        }
        return TtlOk && EvictOk && NegativeOk;
    }

    [[nodiscard]] auto RunDnsPreflight() -> bool
    {
        const auto SingleFlightOk = RunSingleFlightPreflight(5, true);
        const auto CancellationOk = RunResolverCancellationPreflight();
        const auto CacheOk = RunResolverCachePreflight();
        return SingleFlightOk && CancellationOk && CacheOk;
    }

}

