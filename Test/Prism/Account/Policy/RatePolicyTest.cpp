/** @file RatePolicyTest.cpp
 * @brief 既有rate/并发/策略换代输入的共享账本合同迁移。
 */
#include "../Runtime/AccountTestSupport.hpp"
namespace
{
    struct StaleGenerationWorkerState final
    {
        std::shared_ptr<const PolicySnapshot> InitialPolicy;
        std::shared_ptr<const AccountBinding> Current;
        Prism::Account::CredentialIndexView View;
        std::barrier<>* Gate;
        std::atomic<std::uint32_t>* StaleAccepted;
        std::atomic<std::uint32_t>* StalePolicyAccepted;
        PolicyVersion InitialVersion;
    };
    auto RunStaleGenerationWorker(StaleGenerationWorkerState State) -> void
    {
        State.Gate->arrive_and_wait();
        auto Admission = Acquire(State.View, {.Credential = CredentialOf(State.Current), .Rate = RateRequest{0, 200, 1},
            .RequiredPolicyVersion = State.InitialVersion});
        if (Admission) { State.StaleAccepted->fetch_add(1, std::memory_order_relaxed); }
        if (ConsumeRate(*State.InitialPolicy->Rate(), RateRequest{0, 200, 1}))
        { State.StalePolicyAccepted->fetch_add(1, std::memory_order_relaxed); }
        State.Gate->arrive_and_wait();
    }
    struct RateRaceWorker final
    {
        std::vector<std::unique_ptr<RateLimiter>>* Limiters;
        std::barrier<>* Gate;
        RateRequest Request;
    };
    auto RunRateRace(RateRaceWorker State) -> void
    {
        for (auto& Limiter : *State.Limiters)
        {
            State.Gate->arrive_and_wait();
            (void)ConsumeRate(*Limiter, State.Request);
            State.Gate->arrive_and_wait();
        }
    }
    struct ByteQuotaWorker final
    {
        const Prism::Account::AccountLease* Lease;
        std::array<Prism::Account::ByteLease, 256U>* Tickets;
        std::atomic<std::uint32_t>* Successes;
        std::uint32_t Index;
    };
    auto RunByteQuotaWorker(ByteQuotaWorker State) -> void
    {
        for (std::uint32_t Attempt = 0; Attempt < 32; ++Attempt)
        {
            auto Reserved = State.Lease->ReserveBytes(1);
            if (Reserved)
            {
                (*State.Tickets)[State.Index * 32U + Attempt] = std::move(*Reserved);
                State.Successes->fetch_add(1, std::memory_order_relaxed);
            }
        }
    }
}
TEST(PrismAccountRate, StrictGlobalPolicyIsSharedAcrossWorkers)
{
    RateLimiter Limiter({.Policy = RatePolicy{StrictGlobalRatePolicy{2, 100}}});
    EXPECT_TRUE(ConsumeRate(Limiter, RateRequest{0, 10, 1}));
    EXPECT_TRUE(ConsumeRate(Limiter, RateRequest{1, 10, 1}));
    EXPECT_FALSE(ConsumeRate(Limiter, RateRequest{0, 10, 1}));
    EXPECT_TRUE(ConsumeRate(Limiter, RateRequest{0, 110, 1}));
}
TEST(PrismAccountRate, WorkerShardedPolicyReportsBoundedOvershoot)
{
    const WorkerShardedRatePolicy Policy{2, 3, 100};
    EXPECT_EQ(Policy.PerWorkerLimit(), 2U); EXPECT_EQ(Policy.MaxOvershoot(), 1U);
    RateLimiter Limiter({.Policy = RatePolicy{Policy}});
    EXPECT_TRUE(ConsumeRate(Limiter, RateRequest{0, 10, 1}));
    EXPECT_TRUE(ConsumeRate(Limiter, RateRequest{0, 10, 1}));
    EXPECT_TRUE(ConsumeRate(Limiter, RateRequest{1, 10, 1}));
    EXPECT_TRUE(ConsumeRate(Limiter, RateRequest{1, 10, 1}));
    EXPECT_FALSE(ConsumeRate(Limiter, RateRequest{0, 10, 1}));
    EXPECT_FALSE(ConsumeRate(Limiter, RateRequest{1, 10, 1}));
}
TEST(PrismAccountRate, RejectsZeroWorkerShardCount)
{
    RateLimiter Limiter({.Policy = RatePolicy{WorkerShardedRatePolicy{0, 3, 100}}});
    EXPECT_FALSE(ConsumeRate(Limiter, RateRequest{0, 10, 1}));
}
TEST(PrismAccountRecord, DirectConstructionKeepsPolicyGenerationConsistent)
{
    const auto Generation = PolicyVersion{77};
    const auto Record = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{117},
        .CredentialValue = Credential::Password("direct-generation-account")});
    AccountStore Directory(Prism::Account::StoreOptions{.InitialPolicyVersion = Generation});
    ASSERT_TRUE(Publish(Directory, Record));
    const auto Binding = Directory.FindById(Prism::AccountId{117});
    ASSERT_TRUE(Binding);
    EXPECT_EQ(Binding->Policy()->Version(), Generation);
    ASSERT_TRUE(Binding->Runtime());
    EXPECT_EQ(Binding->Runtime()->AccountId(), Prism::AccountId{117});
}
TEST(PrismAccountRate, ReconfigurationRebasesWindowAndRejectsConcurrentStaleGeneration)
{
    constexpr std::size_t StaleWorkers = 8;
    const auto Initial = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{118},
        .CredentialValue = Credential::Password("window-reconfiguration-account"), .Rate = StrictGlobalRatePolicy{1, 100}});
    AccountStore Directory;
    ASSERT_TRUE(Publish(Directory, Initial));
    const auto PublishedInitial = Directory.FindById(Prism::AccountId{118});
    ASSERT_TRUE(PublishedInitial);
    const auto InitialGeneration = PublishedInitial->Policy()->Version();
    const auto InitialPolicy = PublishedInitial->Policy();
    ASSERT_TRUE(InitialPolicy);
    const auto View = CompileView(Directory);
    auto Consumed = Acquire(View, {.Credential = CredentialOf(PublishedInitial), .Rate = RateRequest{0, 100, 1}});
    ASSERT_TRUE(Consumed); Consumed->Release();
    const auto Replacement = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{118},
        .CredentialValue = Credential::Password("window-reconfiguration-account"), .Rate = StrictGlobalRatePolicy{2, 1000}});
    ASSERT_TRUE(Publish(Directory, Replacement));
    const auto PublishedReplacement = Directory.FindById(Prism::AccountId{118});
    ASSERT_TRUE(PublishedReplacement);
    const auto ReplacementGeneration = PublishedReplacement->Policy()->Version();
    EXPECT_NE(ReplacementGeneration, InitialGeneration);
    EXPECT_EQ(PublishedReplacement->Runtime(), PublishedInitial->Runtime());
    ASSERT_TRUE(ConsumeRate(*PublishedReplacement->Policy()->Rate(), RateRequest{0, 200, 1}));
    std::atomic<std::uint32_t> StaleAccepted{0}, StalePolicyAccepted{0};
    std::barrier Gate(static_cast<std::ptrdiff_t>(StaleWorkers + 1));
    std::vector<std::thread> Threads;
    Threads.reserve(StaleWorkers);
    for (std::size_t Index = 0; Index < StaleWorkers; ++Index)
    {
        Threads.emplace_back(RunStaleGenerationWorker, StaleGenerationWorkerState{InitialPolicy,
            PublishedReplacement, View, &Gate, &StaleAccepted, &StalePolicyAccepted, InitialGeneration});
    }
    Gate.arrive_and_wait(); Gate.arrive_and_wait();
    for (auto& Thread : Threads) { Thread.join(); }
    EXPECT_EQ(StaleAccepted.load(std::memory_order_relaxed), 0U);
    // 新合同：新策略成功消费同一ledger，旧窗口视图同样记账，不能再双花一个单位。
    EXPECT_EQ(StalePolicyAccepted.load(std::memory_order_relaxed), 0U);
    EXPECT_FALSE(ConsumeRate(*PublishedReplacement->Policy()->Rate(), RateRequest{0, 200, 1}));
    EXPECT_FALSE(ConsumeRate(*PublishedReplacement->Policy()->Rate(), RateRequest{0, 200, 1}));
}
TEST(PrismAccountRate, ReconfigurationPreservesTimestampFloorAcrossWindowReset)
{
    RateLimiter Initial({.Policy = RatePolicy{StrictGlobalRatePolicy{2, 100}}});
    ASSERT_TRUE(ConsumeRate(Initial, RateRequest{0, 1000, 1}));
    const auto Reconfigured = Initial.Reconfigure(RatePolicy{StrictGlobalRatePolicy{2, 1000}});
    ASSERT_TRUE(Reconfigured);
    EXPECT_FALSE(ConsumeRate(**Reconfigured, RateRequest{0, 999, 1}));
    EXPECT_TRUE(ConsumeRate(**Reconfigured, RateRequest{0, 1000, 1}));
}
TEST(PrismAccountRate, RejectsDefaultAndOutOfOrderTimestamps)
{
    RateLimiter Limiter({.Policy = RatePolicy{StrictGlobalRatePolicy{3, 100}}});
    EXPECT_FALSE(ConsumeRate(Limiter, RateRequest{0, 0, 1}));
    EXPECT_TRUE(ConsumeRate(Limiter, RateRequest{0, 100, 1}));
    EXPECT_FALSE(ConsumeRate(Limiter, RateRequest{0, 99, 1}));
}
TEST(PrismAccountRate, RejectsLimitsBeyondPackedCounterWidth)
{
    RateLimiter Limiter({.Policy = RatePolicy{StrictGlobalRatePolicy{std::numeric_limits<std::uint64_t>::max(), 100}}});
    EXPECT_FALSE(ConsumeRate(Limiter, RateRequest{0, 1, 1}));
}
TEST(PrismAccountRate, RejectsWorkerShardCountBeyondBound)
{
    RateLimiter Limiter({.Policy = RatePolicy{WorkerShardedRatePolicy{10000, 0, 100}}});
    EXPECT_FALSE(ConsumeRate(Limiter, RateRequest{0, 1, 1}));
}
TEST(PrismAccountRate, ConcurrentNewerWindowCannotBeRewoundByStaleRequests)
{
    constexpr std::size_t Rounds = 512, StaleWorkers = 8;
    constexpr std::uint32_t Limit = static_cast<std::uint32_t>(StaleWorkers);
    std::vector<std::unique_ptr<RateLimiter>> Limiters;
    Limiters.reserve(Rounds);
    for (std::size_t Index = 0; Index < Rounds; ++Index)
    { Limiters.push_back(std::make_unique<RateLimiter>(RateLimiter::CreateRequest{.Policy = RatePolicy{StrictGlobalRatePolicy{Limit, 100}}})); }
    std::barrier Gate(static_cast<std::ptrdiff_t>(StaleWorkers + 2));
    std::vector<std::thread> Threads;
    Threads.reserve(StaleWorkers + 1);
    for (std::size_t Worker = 0; Worker < StaleWorkers; ++Worker)
    { Threads.emplace_back(RunRateRace, RateRaceWorker{&Limiters, &Gate, RateRequest{0, 100, 1}}); }
    Threads.emplace_back(RunRateRace, RateRaceWorker{&Limiters, &Gate, RateRequest{0, 200, Limit}});
    for (auto& Limiter : Limiters)
    {
        Gate.arrive_and_wait(); Gate.arrive_and_wait();
        EXPECT_FALSE(ConsumeRate(*Limiter, RateRequest{0, 200, 1}));
    }
    for (auto& Thread : Threads) { Thread.join(); }
}
TEST(PrismAccountQuota, ConcurrentReservationUsesSingleBoundedCASLedger)
{
    AccountStore Directory;
    const auto Record = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{1U},
        .CredentialValue = Credential::Password("quota-ledger"), .Quota = {.MaxBytes = 100}});
    ASSERT_TRUE(Publish(Directory, Record));
    auto Lease = Acquire(CompileView(Directory), {.Credential = CredentialOf(Record)});
    ASSERT_TRUE(Lease);
    const auto Binding = Lease->Binding();
    std::array<Prism::Account::ByteLease, 256U> Tickets;
    std::atomic<std::uint32_t> Successes{0};
    std::vector<std::thread> Threads;
    Threads.reserve(8);
    for (std::uint32_t Index = 0; Index < 8; ++Index)
    { Threads.emplace_back(RunByteQuotaWorker, ByteQuotaWorker{&*Lease, &Tickets, &Successes, Index}); }
    for (auto& Thread : Threads) { Thread.join(); }
    EXPECT_EQ(Successes.load(std::memory_order_relaxed), 100U);
    EXPECT_EQ(Binding->Runtime()->UsedBytes(), 100U);
    for (auto& Ticket : Tickets) { Ticket.Release(); }
    EXPECT_EQ(Binding->Runtime()->UsedBytes(), 0U);
}
