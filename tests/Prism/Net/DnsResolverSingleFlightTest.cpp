/**
 * @file DnsResolverSingleFlightTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "DnsResolverTestSupport.hpp"

namespace
{
    struct ConcurrentSingleFlightRequest final
    {
        Resolver &ResolverOwner;
        std::vector<ResolveResult> &Results;
        std::size_t Index;
    };

    /**
     * @brief 执行一个并发 single-flight 查询并写入按索引分配的结果槽。
     * @param Request resolver、地址结果、错误结果和 waiter 索引。
     * @return 完成一次真实 burst.local 查询的异步操作。
     * @details resolver 和结果槽由测试在同步 io_context.run() 期间持有。
     */
    auto RunConcurrentSingleFlightQuery(ConcurrentSingleFlightRequest Request)
        -> Net::awaitable<void>
    {
        Request.Results[Request.Index] = co_await Request.ResolverOwner.AsyncResolve("burst.local");
    }

    struct ConcurrentSingleFlightScenarioRequest final
    {
        Net::io_context &IoContext;
        Resolver &ResolverOwner;
        std::vector<ResolveResult> &Results;
    };

    struct ConcurrentSingleFlightCompletion final
    {
        explicit ConcurrentSingleFlightCompletion(Net::any_io_executor Executor, const std::size_t Count)
            : Done(std::make_shared<GateChannel>(std::move(Executor), Count))
        {
        }

        std::shared_ptr<GateChannel> Done;
        std::exception_ptr Failure;
    };

    auto RecordConcurrentSingleFlightCompletion(
        const std::shared_ptr<ConcurrentSingleFlightCompletion> &Completion,
        std::exception_ptr Failure) -> void
    {
        if (Failure && !Completion->Failure)
        {
            Completion->Failure = Failure;
        }
        (void)Completion->Done->try_send(boost::system::error_code{});
    }

    /**
     * @brief 等待四个并发查询全部完成后再返回。
     * @param Request single-flight 场景的 IO、resolver 与结果槽。
     * @return 所有 query frame 和 completion callback 均结束后完成。
     */
    auto RunConcurrentSingleFlightScenario(ConcurrentSingleFlightScenarioRequest Request)
        -> Net::awaitable<void>
    {
        constexpr std::size_t QueryCount = 4;
        const auto Completion = std::make_shared<ConcurrentSingleFlightCompletion>(
            Request.IoContext.get_executor(), QueryCount);
        for (std::size_t Index = 0; Index < QueryCount; ++Index)
        {
            const auto Query = ConcurrentSingleFlightRequest{
                Request.ResolverOwner, Request.Results, Index};
            Net::co_spawn(
                Request.IoContext,
                RunConcurrentSingleFlightQuery(Query),
                [Completion](std::exception_ptr Failure)
                { RecordConcurrentSingleFlightCompletion(Completion, Failure); });
        }
        for (std::size_t Index = 0; Index < QueryCount; ++Index)
        {
            co_await Completion->Done->async_receive(Net::use_awaitable);
        }
        if (Completion->Failure)
        {
            std::rethrow_exception(Completion->Failure);
        }
    }

    struct CancellationScenarioRequest final
    {
        Net::io_context &IoContext;
        std::shared_ptr<MiniDnsServer> Server;
        std::shared_ptr<Resolver> ResolverOwner;
        std::shared_ptr<GateChannel> QuerySignal;
        std::shared_ptr<GateChannel> Release;
        std::shared_ptr<Net::cancellation_signal> Cancellation;
        std::shared_ptr<ResolverCancellationProbe> Probe;
        ResolveResult &Recovery;
        bool &FirstDone;
    };

    /**
     * @brief 验证取消 leader 后 follower/后续查询的资源与缓存状态。
     * @param Request 取消场景的真实 server、resolver、控制信号和结果槽。
     * @return 完成首个取消、响应释放及后续恢复查询的异步操作。
     * @details shared owner 持有网络资源到场景结束，结果引用由 RunCoro 的同步调用方持有。
     */
    auto RunCancellationScenario(CancellationScenarioRequest Request)
        -> Net::awaitable<void>
    {
        const auto Done = std::make_shared<GateChannel>(Request.IoContext.get_executor(), 1);
        Net::co_spawn(
            Request.IoContext,
            RunResolverCancellationProbe(Request.Probe),
            Net::bind_cancellation_slot(
                Request.Cancellation->slot(),
                ResolverCancellationCompletion{Request.Probe, Done}));
        co_await Request.QuerySignal->async_receive(Net::use_awaitable);
        std::fprintf(stderr, "dns-cancel stage=query-observed queries=%zu responses=%zu\n",
                     Request.Server->QueryCount(), Request.Server->ResponseCount());
        Request.Cancellation->emit(Net::cancellation_type::all);
        co_await Done->async_receive(Net::use_awaitable);
        Request.FirstDone = true;
        std::fprintf(stderr,
                     "dns-cancel stage=caller-retired error=%s/%d/%s completed=%s\n",
                     Request.Probe->Error.Native.category().name(), Request.Probe->Error.Native.value(),
                     Request.Probe->Error.Native.message().c_str(),
                     Request.Probe->Completed ? "yes" : "no");
        (void)Request.Release->try_send(boost::system::error_code{});
        std::fprintf(stderr, "dns-cancel stage=response-release queries=%zu responses=%zu\n",
                     Request.Server->QueryCount(), Request.Server->ResponseCount());
        Request.Recovery = co_await Request.ResolverOwner->AsyncResolve("cancel-next.local");
        std::fprintf(stderr,
                     "dns-cancel stage=recovery-complete failure=%d addresses=%zu "
                     "queries=%zu responses=%zu cache=%zu\n",
                     static_cast<int>(Request.Recovery ? Prism::Fault::Code::Success :
                         Request.Recovery.error().Code),
                     Request.Recovery ? Request.Recovery->Size() : 0U,
                     Request.Server->QueryCount(), Request.Server->ResponseCount(),
                     Request.ResolverOwner->Size());
    }
} // namespace

TEST(DnsResolver, NxDomainNegativeCachedNoRetry)
{
    // 1.3 端到端验证：NXDOMAIN 被负缓存；二次解析不再打上游
    Net::io_context ioc;
    auto server = std::make_shared<MiniDnsServer>(ioc, MiniDnsServer::Behavior::NxDomain);
    server->Start();

    Config cfg;
    cfg.Servers = {server->MakeConfig()};
    cfg.DisableIpv6 = true;
    Resolver r(ioc.get_executor(), cfg);

    ResolveFailure Failure;
    std::vector<Net::ip::address> addrs;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 CaptureResolveResult(co_await r.AsyncResolve("nx.local"), addrs, Failure);
             });
    EXPECT_EQ(Failure.Code, Prism::Fault::Code::DnsFailed);
    EXPECT_TRUE(addrs.empty());
    EXPECT_EQ(r.Size(), 1u); // 负缓存已入

    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 CaptureResolveResult(co_await r.AsyncResolve("nx.local"), addrs, Failure);
             });
    EXPECT_EQ(Failure.Code, Prism::Fault::Code::DnsFailed);
    EXPECT_EQ(server->QueryCount(), 1u); // 负缓存命中，不再打上游
    server->Close();
}

TEST(DnsResolver, CacheTtlUsesShortestAddressFamily)
{
    Net::io_context ioc;
    auto server = std::make_shared<MiniDnsServer>(ioc, MiniDnsServer::Behavior::MixedAnswer);
    server->Start();

    Config cfg;
    cfg.Servers = {server->MakeConfig()};
    Resolver r(ioc.get_executor(), cfg);

    ResolveFailure Failure;
    std::vector<Net::ip::address> addrs;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 CaptureResolveResult(co_await r.AsyncResolve("ttl.local"), addrs, Failure);
             });
    ASSERT_TRUE(Failure.Succeeded());
    ASSERT_EQ(addrs.size(), 2u);
    EXPECT_EQ(server->QueryCount(), 2u);

    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 CaptureResolveResult(co_await r.AsyncResolve("ttl.local"), addrs, Failure);
             });

    EXPECT_TRUE(Failure.Succeeded());
    EXPECT_EQ(server->QueryCount(), 4u);
    server->Close();
}

TEST(DnsResolver, ConcurrentSingleFlight)
{
    // 并发同域名解析：single-flight 使上游查询只发生一次（A 族 leader 唯一）
    Net::io_context ioc;
    auto server = std::make_shared<MiniDnsServer>(ioc, MiniDnsServer::Behavior::Answer);
    server->Start();

    Config cfg;
    cfg.Servers = {server->MakeConfig()};
    cfg.DisableIpv6 = true;
    Resolver r(ioc.get_executor(), cfg);

    constexpr std::size_t QueryCount = 4;
    std::vector<ResolveResult> results(QueryCount);
    const auto ScenarioRequest = ConcurrentSingleFlightScenarioRequest{ioc, r, results};
    const auto MakeScenario = [ScenarioRequest]() -> Net::awaitable<void>
    {
        return RunConcurrentSingleFlightScenario(ScenarioRequest);
    };
    RunCoro(ioc, MakeScenario);

    EXPECT_EQ(server->QueryCount(), 1u); // 4 个并发请求只打了一次上游
    for (std::size_t Index = 0; Index < QueryCount; ++Index)
    {
        ASSERT_TRUE(results[Index]);
        ASSERT_EQ(results[Index]->Size(), 1u);
        EXPECT_EQ((*results[Index])[0], Net::ip::make_address("1.2.3.4"));
    }
    server->Close();
}

TEST(DnsResolver, CanceledRequestDoesNotPoisonNextRequest)
{
    Net::io_context ioc;
    auto server = std::make_shared<MiniDnsServer>(ioc, MiniDnsServer::Behavior::Answer);
    server->Start();

    Config cfg;
    cfg.Servers = {server->MakeConfig()};
    cfg.DisableIpv6 = true;
    cfg.CacheEnabled = true;
    auto ResolverOwner = std::make_shared<Resolver>(ioc.get_executor(), cfg);
    auto QuerySignal = std::make_shared<GateChannel>(ioc.get_executor(), 1);
    auto Release = std::make_shared<GateChannel>(ioc.get_executor(), 1);
    server->ObserveQueries(ioc, QuerySignal);
    server->HoldFirstResponse(Release);

    auto Cancellation = std::make_shared<Net::cancellation_signal>();
    auto Probe = std::make_shared<ResolverCancellationProbe>();
    Probe->ResolverOwner = ResolverOwner.get();
    Probe->Domain = "cancel-next.local";
    ResolveResult Recovery;
    bool FirstDone = false;

    const auto ScenarioRequest = CancellationScenarioRequest{
        ioc, server, ResolverOwner, QuerySignal, Release, Cancellation, Probe,
        Recovery, FirstDone};
    const auto MakeScenario = [ScenarioRequest]() -> Net::awaitable<void>
    {
        return RunCancellationScenario(ScenarioRequest);
    };
    RunCoro(ioc, MakeScenario);

    ASSERT_TRUE(FirstDone);
    EXPECT_FALSE(Probe->Completed);
    EXPECT_EQ(Probe->Error.Code, Prism::Fault::Code::Canceled);
    EXPECT_TRUE(Probe->Error.Native == std::make_error_code(std::errc::operation_canceled) ||
                Probe->Error.Native.value() == static_cast<int>(boost::asio::error::operation_aborted));
    ASSERT_TRUE(Recovery);
    ASSERT_EQ(Recovery->Size(), 1U);
    EXPECT_EQ((*Recovery)[0], Net::ip::make_address("1.2.3.4"));
    // 取消请求没有缓存成功答案；独立的新请求应真实发出第二次查询。
    EXPECT_EQ(server->QueryCount(), 2U);
    EXPECT_EQ(server->ResponseCount(), 2U);
    server->Close();
}

TEST(DnsResolver, ServeStaleEndToEnd)
{
    // serve-stale 端到端：缓存过期后仍返回旧数据，且不打上游
    Net::io_context ioc;
    auto server = std::make_shared<MiniDnsServer>(ioc, MiniDnsServer::Behavior::Answer, 1);
    server->Start();

    Config cfg;
    cfg.Servers = {server->MakeConfig()};
    cfg.DisableIpv6 = true;
    cfg.CacheTtl = std::chrono::seconds(1);
    cfg.CachePolicy = StalePolicy::Serve;
    Resolver r(ioc.get_executor(), cfg);

    ResolveFailure Failure;
    std::vector<Net::ip::address> addrs;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 CaptureResolveResult(co_await r.AsyncResolve("stale.local"), addrs, Failure);
             });
    ASSERT_EQ(addrs.size(), 1u);

    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    std::vector<Net::ip::address> stale;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 CaptureResolveResult(co_await r.AsyncResolve("stale.local"), stale, Failure);
             });
    ASSERT_EQ(stale.size(), 1u);
    EXPECT_EQ(stale[0], addrs[0]);          // 过期后仍返回旧数据
    EXPECT_EQ(server->QueryCount(), 1u);    // 未再打上游
    server->Close();
}
