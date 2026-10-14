/**
 * @file DnsUpstreamSelectionTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "DnsUpstreamTestSupport.hpp"

namespace
{
    using QueryCompletionChannel =
        Net::experimental::channel<void(boost::system::error_code)>;

    struct SharedConcurrentOwnerScenario final
    {
        Net::io_context &IoContext;
        std::shared_ptr<std::shared_ptr<Upstream>> Holder;
        std::shared_ptr<FakeDnsServer> FirstServer;
        std::shared_ptr<FakeDnsServer> SecondServer;
        std::shared_ptr<QueryCompletionChannel> QueryCompleted;
        QueryResult *Result;
        std::exception_ptr *Failure;
    };

    auto RunSharedConcurrentOwnerScenario(SharedConcurrentOwnerScenario Scenario)
        -> Net::awaitable<void>
    {
        auto Client = *Scenario.Holder;
        auto Query = Client->Resolve("owner-release.example.com", QType::A);
        Client.reset();
        Net::co_spawn(
            Scenario.IoContext, std::move(Query),
            [Scenario](std::exception_ptr Error, QueryResult Value)
            {
                *Scenario.Failure = std::move(Error);
                *Scenario.Result = std::move(Value);
                (void)Scenario.QueryCompleted->try_send(boost::system::error_code{});
            });
        co_await Scenario.FirstServer->WaitForQuery();
        Scenario.Holder->reset();
        (void)co_await Scenario.QueryCompleted->async_receive(Net::use_awaitable);
        Scenario.FirstServer->Close();
        Scenario.SecondServer->Close();
        co_await Scenario.FirstServer->Drain();
        co_await Scenario.SecondServer->Drain();
    }
} // namespace

TEST(DnsUpstream, TestUdpQuerySuccess)
{
Net::io_context IoContext;
    auto DnsServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::Answer);
    DnsServer->Start();

    Upstream UpstreamOwner(IoContext.get_executor(), UpstreamOptions{.Servers = {DnsServer->MakeConfig()}});
    QueryResult Result;
    RunCoro(IoContext,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await UpstreamOwner.Resolve("example.com", QType::A);
                DnsServer->Close();
                co_await DnsServer->Drain();
            });

    EXPECT_TRUE(Result.Error.Succeeded());
    ASSERT_EQ(Result.Response.Ips.Size(), 1u);
    EXPECT_EQ(Result.Response.Ips[0], Net::ip::make_address_v4("1.2.3.4"));
    EXPECT_EQ(Result.ServerAddr, DnsServer->Addr());
    EXPECT_EQ(Result.Response.MinTtl, 60u);
}

TEST(DnsUpstream, TestTruncatedFallsBackToTcp)
{
Net::io_context IoContext;
    auto DnsServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::Truncate);
    DnsServer->Start();

    auto UpstreamOwner = std::make_shared<Upstream>(
        IoContext.get_executor(), UpstreamOptions{.Servers = {DnsServer->MakeConfig()}});
    QueryResult Result;
    RunCoro(IoContext,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await UpstreamOwner->Resolve("big.example.com", QType::A);
                UpstreamOwner.reset();
                DnsServer->Close();
                co_await DnsServer->Drain();
            });

    // UDP TC=1 → 自动改走 TCP 取得完整应答
    EXPECT_TRUE(Result.Error.Succeeded());
    ASSERT_EQ(Result.Response.Ips.Size(), 1u);
    EXPECT_EQ(Result.Response.Ips[0], Net::ip::make_address_v4("1.2.3.4"));
}

TEST(DnsUpstream, TestFallbackSkipsFailedServer)
{
Net::io_context IoContext;
    auto EmptyServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::EmptyAnswer);
    auto GoodServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::Answer);
    EmptyServer->Start();
    GoodServer->Start();

    Upstream UpstreamOwner(IoContext.get_executor(),
                UpstreamOptions{.Servers = {EmptyServer->MakeConfig(), GoodServer->MakeConfig()},
                                .QueryMode = Preview::Network::Dns::Mode::Fallback});
    QueryResult Result;
    RunCoro(IoContext,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await UpstreamOwner.Resolve("fallback.com", QType::A);
                EmptyServer->Close();
                GoodServer->Close();
                co_await EmptyServer->Drain();
                co_await GoodServer->Drain();
            });

    // 首个上游零应答视为失败 → 顺序尝试第二个
    EXPECT_TRUE(Result.Error.Succeeded());
    ASSERT_EQ(Result.Response.Ips.Size(), 1u);
    EXPECT_EQ(Result.ServerAddr, GoodServer->Addr());
}

TEST(DnsUpstream, TestFirstReturnsFirstSuccessfulServer)
{
Net::io_context IoContext;
    // 首个上游故意延迟：First 策略返回先完成的成功响应
    auto SlowServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::Answer,
                                                std::chrono::milliseconds(50));
    auto FastServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::Answer);
    SlowServer->Start();
    FastServer->Start();

    auto UpstreamOwner = std::make_shared<Upstream>(IoContext.get_executor(),
        UpstreamOptions{.Servers = {SlowServer->MakeConfig(), FastServer->MakeConfig()},
                        .QueryMode = Preview::Network::Dns::Mode::First});
    QueryResult Result;
    RunCoro(IoContext,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await UpstreamOwner->Resolve("first.com", QType::A);
                SlowServer->Close();
                FastServer->Close();
                co_await SlowServer->Drain();
                co_await FastServer->Drain();
            });

    EXPECT_TRUE(Result.Error.Succeeded());
    EXPECT_EQ(Result.ServerAddr, FastServer->Addr());
}

TEST(DnsUpstream, FirstReleasesOwnerAfterLosersAreCanceled)
{
Net::io_context IoContext;
    auto FastServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::Answer);
    auto SilentServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::Silent);
    FastServer->Start();
    SilentServer->Start();
    auto Owner = std::make_shared<Upstream>(IoContext.get_executor(),
        UpstreamOptions{.Servers = {FastServer->MakeConfig(), SilentServer->MakeConfig()},
                        .QueryMode = Preview::Network::Dns::Mode::First});
    const std::weak_ptr<Upstream> WeakOwner = Owner;
    QueryResult Result;

    RunCoro(IoContext,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Owner->Resolve("first-owner-release.example.com", QType::A);
                Owner.reset();
                FastServer->Close();
                SilentServer->Close();
                co_await FastServer->Drain();
                co_await SilentServer->Drain();
            });

    EXPECT_TRUE(Result.Error.Succeeded());
    EXPECT_TRUE(WeakOwner.expired());
}

TEST(DnsUpstream, CallerCancellationJoinsAllWorkersBeforeReturning)
{
Net::io_context IoContext;
    auto FirstServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::Silent);
    auto SecondServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::Silent);
    FirstServer->Start();
    SecondServer->Start();
    auto Owner = std::make_shared<Upstream>(IoContext.get_executor(),
        UpstreamOptions{.Servers = {FirstServer->MakeConfig(), SecondServer->MakeConfig()},
                        .QueryMode = Preview::Network::Dns::Mode::First});
    const std::weak_ptr<Upstream> WeakOwner = Owner;
    auto Cancellation = std::make_shared<Net::cancellation_signal>();
    std::exception_ptr Failure;
    bool Returned = false;
    bool CompletedNormally = false;
    bool OperationAborted = false;
    bool OwnerExpired = false;
    bool TriggerReturned = false;
    std::exception_ptr TriggerFailure;

    CancellationScenario Scenario{
        Owner, FirstServer, SecondServer, WeakOwner, &Failure, &OperationAborted, &OwnerExpired,
        &Returned, &CompletedNormally};
    Net::co_spawn(
        IoContext,
        RunCancellationScenario(std::move(Scenario)),
        Net::bind_cancellation_slot(
            Cancellation->slot(),
            [&](std::exception_ptr Error)
            {
                if (Error && !Failure)
                {
                    Failure = std::move(Error);
                }
                Returned = true;
            }));
    Owner.reset();

    Net::co_spawn(
        IoContext,
        RunCancelTrigger(CancellationTrigger{FirstServer, SecondServer, Cancellation}),
        [&](std::exception_ptr Error)
        {
            TriggerFailure = std::move(Error);
            TriggerReturned = true;
        });
    IoContext.run();

    ASSERT_TRUE(Returned);
    EXPECT_FALSE(CompletedNormally);
    ASSERT_TRUE(Failure);
    EXPECT_TRUE(OperationAborted);
    EXPECT_TRUE(OwnerExpired);
    EXPECT_TRUE(WeakOwner.expired());
    EXPECT_TRUE(TriggerReturned);
    EXPECT_FALSE(TriggerFailure);
}

TEST(DnsUpstream, TestFastestPicksLowerRtt)
{
Net::io_context IoContext;
    auto InstantServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::Answer);
    auto SluggishServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::Answer,
                                                    std::chrono::milliseconds(200));
    InstantServer->Start();
    SluggishServer->Start();

    auto UpstreamOwner = std::make_shared<Upstream>(IoContext.get_executor(),
        UpstreamOptions{.Servers = {SluggishServer->MakeConfig(), InstantServer->MakeConfig()},
                        .QueryMode = Preview::Network::Dns::Mode::Fastest});
    QueryResult Result;
    RunCoro(IoContext,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await UpstreamOwner->Resolve("fastest.com", QType::A);
                InstantServer->Close();
                SluggishServer->Close();
                co_await InstantServer->Drain();
                co_await SluggishServer->Drain();
            });

    // Fastest 等全部完成后选 RTT 最低者
    EXPECT_TRUE(Result.Error.Succeeded());
    EXPECT_EQ(Result.ServerAddr, InstantServer->Addr());
}

TEST(DnsUpstream, RejectsUnownedConcurrentUpstream)
{
Net::io_context IoContext;
    auto FirstServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::Answer);
    auto SecondServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::Answer);
    FirstServer->Start();
    SecondServer->Start();

    Upstream UpstreamOwner(IoContext.get_executor(),
                UpstreamOptions{.Servers = {FirstServer->MakeConfig(), SecondServer->MakeConfig()},
                                .QueryMode = Preview::Network::Dns::Mode::First});
    QueryResult Result;
    RunCoro(IoContext,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await UpstreamOwner.Resolve("unowned.example.com", QType::A);
                FirstServer->Close();
                SecondServer->Close();
                co_await FirstServer->Drain();
                co_await SecondServer->Drain();
            });

    EXPECT_EQ(Result.Error.Code, Preview::Fault::Code::NotSupported);
}

TEST(DnsUpstream, SharedConcurrentOwnerSurvivesCallerRelease)
{
Net::io_context IoContext;
    auto FirstServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::Answer,
                                                 std::chrono::milliseconds(30));
    auto SecondServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::Answer);
    FirstServer->Start();
    SecondServer->Start();

    auto Holder = std::make_shared<std::shared_ptr<Upstream>>(std::make_shared<Upstream>(
        IoContext.get_executor(),
        UpstreamOptions{.Servers = {FirstServer->MakeConfig(), SecondServer->MakeConfig()},
                        .QueryMode = Preview::Network::Dns::Mode::First}));
    QueryResult Result;
    std::exception_ptr Failure;
    auto QueryCompleted = std::make_shared<QueryCompletionChannel>(IoContext, 1);
    RunCoro(IoContext,
            RunSharedConcurrentOwnerScenario(SharedConcurrentOwnerScenario{
                IoContext, Holder, FirstServer, SecondServer, QueryCompleted, &Result, &Failure}));

    ASSERT_FALSE(Failure);
    EXPECT_TRUE(Result.Error.Succeeded());
    ASSERT_EQ(Result.Response.Ips.Size(), 1u);
    EXPECT_EQ(Result.Response.Ips[0], Net::ip::make_address_v4("1.2.3.4"));
}


TEST(DnsUpstream, AwaitableCompletesAfterFacadeReleaseBeforeScheduling)
{
    Net::io_context IoContext;
    auto Server = std::make_shared<FakeDnsServer>(
        IoContext, FakeDnsServer::Behavior::Answer);
    Server->Start();

    auto UpstreamOwner = std::make_shared<Upstream>(
        IoContext.get_executor(),
        UpstreamOptions{.Servers = {Server->MakeConfig()}});
    std::weak_ptr<Upstream> WeakOwner = UpstreamOwner;
    auto Query = UpstreamOwner->Resolve("deferred-owner.example.com", QType::A);
    UpstreamOwner.reset();

    QueryResult Result;
    std::exception_ptr Failure;
    RunCoro(IoContext,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await std::move(Query);
                Server->Close();
                co_await Server->Drain();
            });

    ASSERT_FALSE(Failure);
    EXPECT_TRUE(Result.Error.Succeeded());
    ASSERT_EQ(Result.Response.Ips.Size(), 1u);
    EXPECT_EQ(Result.Response.Ips[0], Net::ip::make_address_v4("1.2.3.4"));
    EXPECT_TRUE(WeakOwner.expired());
}
