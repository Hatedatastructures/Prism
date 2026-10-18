/** @file AccountLeaseTest.cpp
 * @brief 既有根/child/字节额度及撤销场景的正式拥有型接口迁移。
 */
#include "AccountTestSupport.hpp"
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <cstddef>
#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <stdexcept>
#include <utility>

namespace
{
    namespace Net = boost::asio;
    using AccountRuntime = Prism::Account::AccountRuntime;
    using AccountRuntimeIdentity = Prism::Account::AccountRuntimeIdentity;
    using AccountLease = Prism::Account::AccountLease;
    using StreamLease = Prism::Account::StreamLease;
    using LeaseDrainOutcome = AccountRuntime::LeaseDrainOutcome;
    using LeaseDrainDeadline = AccountRuntime::LeaseDrainDeadline;
    using DrainWaiterSignal = Net::experimental::concurrent_channel<void(boost::system::error_code)>;

    /** @brief 独立等待协程的真实完成统计，不作为生产退休事实。 */
    struct DrainWaiterResults final
    {
        std::size_t Started{0U};
        std::size_t Completed{0U};
        std::size_t Succeeded{0U};
        std::optional<Prism::Fault::Failure> FirstFailure;
        std::exception_ptr Exception;
        std::shared_ptr<DrainWaiterSignal> StartedSignal;
    };

    /** @brief 同 executor 的两个等待者与真实 root/child lease owner。 */
    struct MultiWaiterDrainScenario final
    {
        std::shared_ptr<AccountRuntime> Runtime;
        AccountLease Root;
        StreamLease Child;
        LeaseDrainDeadline Limit;
        DrainWaiterResults Results;
        std::size_t StartedBeforeRetirement{0U};
        std::uint32_t ActiveAfterRootRelease{0U};
    };

    /** @brief 持有一次 deadline receipt，供完整 io_context.run 驱动。 */
    struct DrainProbe final
    {
        std::shared_ptr<AccountRuntime> Runtime;
        LeaseDrainDeadline Limit;
        std::optional<LeaseDrainOutcome> Outcome;
        std::exception_ptr Exception;
    };

    /** @brief 等待并记录一个实际 AccountRuntime receipt。 */
    auto WaitForLeaseDrain(const std::shared_ptr<AccountRuntime> Runtime,
                           const LeaseDrainDeadline Limit,
                           DrainWaiterResults &Results) -> Net::awaitable<void>
    {
        ++Results.Started;
        if (!Results.StartedSignal->try_send(boost::system::error_code{}))
        {
            Results.Exception = std::make_exception_ptr(
                std::runtime_error("lease drain waiter start receipt rejected"));
            co_return;
        }
        const auto Outcome = co_await Runtime->WaitForNoActiveConnections(Limit);
        ++Results.Completed;
        if (Outcome)
        {
            ++Results.Succeeded;
            co_return;
        }
        if (!Results.FirstFailure)
        {
            Results.FirstFailure = Outcome.error();
        }
    }

    /** @brief 先让两个等待者在 strand 上挂起，再关闭 root 并释放最后 child。 */
    auto RunMultiWaiterDrain(MultiWaiterDrainScenario &Scenario) -> Net::awaitable<void>
    {
        const auto Executor = co_await Net::this_coro::executor;
        Scenario.Results.StartedSignal = std::make_shared<DrainWaiterSignal>(Executor, 2U);
        Net::co_spawn(Executor,
            WaitForLeaseDrain(Scenario.Runtime, Scenario.Limit, Scenario.Results),
            [&Scenario](const std::exception_ptr Error)
            {
                if (Error) { Scenario.Results.Exception = Error; }
            });
        Net::co_spawn(Executor,
            WaitForLeaseDrain(Scenario.Runtime, Scenario.Limit, Scenario.Results),
            [&Scenario](const std::exception_ptr Error)
            {
                if (Error) { Scenario.Results.Exception = Error; }
            });
        co_await Scenario.Results.StartedSignal->async_receive(Net::use_awaitable);
        co_await Scenario.Results.StartedSignal->async_receive(Net::use_awaitable);
        Scenario.StartedBeforeRetirement = Scenario.Results.Started;
        Scenario.Root.Release();
        Scenario.ActiveAfterRootRelease = Scenario.Runtime->ActiveConnections();
        Scenario.Child.Release();
    }

    /** @brief 完整等待一个有界 receipt，不调用 stop、poll 或 run_for。 */
    auto RunDrainProbe(DrainProbe &Probe) -> Net::awaitable<void>
    {
        Probe.Outcome = co_await Probe.Runtime->WaitForNoActiveConnections(Probe.Limit);
    }
}

TEST(PrismAccountLease, MoveAndReleaseExactlyOnce)
{
    const auto Record = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{106},
        .CredentialValue = Credential::Password("lease-password"), .Quota = {.MaxConnections = 1}});
    AccountStore Directory;
    ASSERT_TRUE(Publish(Directory, Record));
    const auto Binding = Directory.FindById(Prism::AccountId{106});
    auto Result = Acquire(CompileView(Directory), {.Credential = CredentialOf(Record), .Rate = RateRequest{0, 1, 1}});
    ASSERT_TRUE(Result);
    static_assert(!std::is_copy_constructible_v<Prism::Account::AccountLease>);
    static_assert(!std::is_copy_assignable_v<Prism::Account::AccountLease>);
    auto Lease = std::move(*Result);
    EXPECT_FALSE(*Result);
    EXPECT_TRUE(Lease);
    EXPECT_EQ(Binding->Runtime()->ActiveConnections(), 1U);
    Lease.Release(); Lease.Release();
    EXPECT_FALSE(Lease);
    EXPECT_EQ(Binding->Runtime()->ActiveConnections(), 0U);
}
TEST(PrismAccountLease, StreamLeaseIsMoveOnlyAndBounded)
{
    const auto Record = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{107},
        .CredentialValue = Credential::Password("stream-password"), .Quota = {.MaxConnections = 1, .MaxStreams = 1}});
    AccountStore Directory;
    ASSERT_TRUE(Publish(Directory, Record));
    const auto Binding = Directory.FindById(Prism::AccountId{107});
    auto Result = Acquire(CompileView(Directory), {.Credential = CredentialOf(Record), .Rate = RateRequest{0, 1, 1}});
    ASSERT_TRUE(Result);
    auto Account = std::move(*Result);
    auto Stream = Account.TryAcquireStream();
    auto Rejected = Account.TryAcquireStream();
    static_assert(!std::is_copy_constructible_v<Prism::Account::StreamLease>);
    EXPECT_TRUE(Stream); EXPECT_FALSE(Rejected);
    ASSERT_TRUE(Stream);
    auto MovedStream = std::move(*Stream);
    EXPECT_FALSE(*Stream); EXPECT_TRUE(MovedStream);
    MovedStream.Release();
    EXPECT_EQ(Binding->Runtime()->ActiveStreams(), 0U);
}
TEST(PrismAccountQuota, EnforcesConnectionStreamAndByteBoundaries)
{
    const auto Record = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{108},
        .CredentialValue = Credential::Password("quota-password"), .Quota = {.MaxConnections = 1, .MaxStreams = 1, .MaxBytes = 5}});
    AccountStore Directory;
    ASSERT_TRUE(Publish(Directory, Record));
    const auto Binding = Directory.FindById(Prism::AccountId{108});
    const auto View = CompileView(Directory);
    auto First = Acquire(View, {.Credential = CredentialOf(Record), .Rate = RateRequest{0, 1, 1}});
    ASSERT_TRUE(First);
    auto Second = Acquire(View, {.Credential = CredentialOf(Record), .Rate = RateRequest{0, 1, 1}});
    EXPECT_FALSE(Second);
    auto Bytes = First->ReserveBytes(5);
    EXPECT_TRUE(Bytes); ASSERT_TRUE(Bytes);
    EXPECT_FALSE(First->ReserveBytes(1));
    ASSERT_TRUE(Bytes->Reduce(2));
    EXPECT_EQ(Binding->Runtime()->UsedBytes(), 3U);
    auto Extra = First->ReserveBytes(2);
    EXPECT_TRUE(Extra);
    EXPECT_FALSE(First->ReserveBytes(1));
}
TEST(PrismAccountDirectory, RevocationRejectsNewLeaseAndPreservesExistingRelease)
{
    const auto Record = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{109},
        .CredentialValue = Credential::Token("revocable-token"), .Quota = {.MaxConnections = 2}});
    AccountStore Directory;
    ASSERT_TRUE(Publish(Directory, Record));
    const auto Binding = Directory.FindById(Prism::AccountId{109});
    const auto View = CompileView(Directory);
    auto Existing = Acquire(View, {.Credential = CredentialOf(Record), .Rate = RateRequest{0, 1, 1}});
    ASSERT_TRUE(Existing);
    ASSERT_TRUE(Directory.Revoke(Prism::AccountId{109}));
    EXPECT_TRUE(Binding->Runtime()->IsRevoked());
    auto Rejected = Acquire(View, {.Credential = CredentialOf(Record), .Rate = RateRequest{0, 1, 1}});
    EXPECT_FALSE(Rejected);
    EXPECT_EQ(Binding->Runtime()->ActiveConnections(), 1U);
    Existing->Release();
    EXPECT_EQ(Binding->Runtime()->ActiveConnections(), 0U);
}
TEST(PrismAccountDirectory, RejectsInvalidInputsAtInsertionAndAcquire)
{
    AccountStore Directory;
    EXPECT_FALSE(Publish(Directory, AccountDefinition{}));
    const auto Result = Acquire(CompileView(Directory), {.Credential = CredentialView{}, .Rate = RateRequest{0, 1, 1}});
    ASSERT_FALSE(Result);
    EXPECT_EQ(Result.error().Code, Prism::Fault::Code::InvalidArgument);
    EXPECT_FALSE(FindCredentialAccount(Directory, CredentialView{}));
    EXPECT_FALSE(Directory.FindById(Prism::AccountId{}));
    EXPECT_FALSE(Directory.PrepareRemove(Prism::AccountId{}));
}
TEST(PrismAccountQuota, ReservationCannotOverrideRecordPolicy)
{
    const auto Record = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{111},
        .CredentialValue = Credential::Password("bound-quota-password"), .Quota = {.MaxBytes = 5}});
    AccountStore Directory;
    ASSERT_TRUE(Publish(Directory, Record));
    const auto Binding = Directory.FindById(Prism::AccountId{111});
    auto Lease = Acquire(CompileView(Directory), {.Credential = CredentialOf(Record)});
    ASSERT_TRUE(Lease);
    EXPECT_FALSE(Lease->ReserveBytes(6));
    auto Bytes = Lease->ReserveBytes(5);
    EXPECT_TRUE(Bytes);
    EXPECT_EQ(Binding->Runtime()->UsedBytes(), 5U);
}
TEST(PrismAccountDirectory, SameIdUpsertPreservesRuntimeAndRevocation)
{
    const auto Original = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{112},
        .CredentialValue = Credential::Password("reload-old-password"), .Quota = {.MaxConnections = 1}});
    AccountStore Directory;
    ASSERT_TRUE(Publish(Directory, Original));
    const auto PublishedOriginal = Directory.FindById(Prism::AccountId{112});
    const auto View = CompileView(Directory);
    auto Existing = Acquire(View, {.Credential = CredentialOf(Original), .Rate = RateRequest{0, 1, 1}});
    ASSERT_TRUE(Existing);
    const auto Replacement = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{112},
        .CredentialValue = Credential::Password("reload-new-password"), .Quota = {.MaxConnections = 1}});
    ASSERT_TRUE(Publish(Directory, Replacement));
    EXPECT_EQ(Directory.FindById(Prism::AccountId{112})->Runtime(), PublishedOriginal->Runtime());
    auto Busy = Acquire(View, {.Credential = CredentialOf(Replacement), .Rate = RateRequest{0, 1, 1}});
    EXPECT_FALSE(Busy);
    ASSERT_TRUE(Directory.Revoke(Prism::AccountId{112}));
    Existing->Release();
    auto Revoked = Acquire(View, {.Credential = CredentialOf(Replacement), .Rate = RateRequest{0, 1, 1}});
    EXPECT_FALSE(Revoked);
}
TEST(PrismAccountDirectory, SameIdUpsertPublishesPolicyGenerationWithSharedRuntime)
{
    const auto Original = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{115},
        .CredentialValue = Credential::Password("policy-generation-old"), .Quota = {.MaxBytes = 2}, .Rate = StrictGlobalRatePolicy{1, 100}});
    AccountStore Directory;
    ASSERT_TRUE(Publish(Directory, Original));
    const auto PublishedOriginal = Directory.FindById(Prism::AccountId{115});
    ASSERT_TRUE(PublishedOriginal);
    EXPECT_EQ(PublishedOriginal->Policy()->Version(), PolicyVersion{1});
    const auto View = CompileView(Directory);
    auto Existing = Acquire(View, {.Credential = CredentialOf(Original), .Rate = RateRequest{0, 100, 1}});
    ASSERT_TRUE(Existing);
    auto OriginalBytes = Existing->ReserveBytes(2);
    ASSERT_TRUE(OriginalBytes);
    const auto Replacement = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{115},
        .CredentialValue = Credential::Password("policy-generation-new"), .Quota = {.MaxBytes = 3}, .Rate = StrictGlobalRatePolicy{2, 100}});
    ASSERT_TRUE(Publish(Directory, Replacement));
    const auto PublishedReplacement = Directory.FindById(Prism::AccountId{115});
    ASSERT_TRUE(PublishedReplacement);
    EXPECT_EQ(PublishedReplacement->Policy()->Version(), PolicyVersion{2});
    EXPECT_EQ(PublishedReplacement->Runtime(), PublishedOriginal->Runtime());
    EXPECT_FALSE(Existing->ReserveBytes(1));
    auto NewFirst = Acquire(View, {.Credential = CredentialOf(Replacement), .Rate = RateRequest{0, 100, 1}});
    ASSERT_TRUE(NewFirst);
    auto NewBytes = NewFirst->ReserveBytes(1);
    EXPECT_TRUE(NewBytes);
    EXPECT_FALSE(NewFirst->ReserveBytes(1));
    auto NewSecond = Acquire(View, {.Credential = CredentialOf(Replacement), .Rate = RateRequest{0, 100, 1}});
    EXPECT_FALSE(NewSecond);
    ASSERT_TRUE(NewBytes);
    NewBytes->Release();
    NewFirst->Release(); Existing->Release();
}
TEST(PrismAccountLease, MoveAssignmentReleasesDestinationExactlyOnce)
{
    const auto FirstRecord = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{113},
        .CredentialValue = Credential::Password("move-assignment-first-password"), .Quota = {.MaxConnections = 1}});
    const auto SecondRecord = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{114},
        .CredentialValue = Credential::Password("move-assignment-second-password"), .Quota = {.MaxConnections = 1}});
    AccountStore Directory;
    ASSERT_TRUE(Publish(Directory, FirstRecord)); ASSERT_TRUE(Publish(Directory, SecondRecord));
    const auto FirstBinding = Directory.FindById(Prism::AccountId{113});
    const auto SecondBinding = Directory.FindById(Prism::AccountId{114});
    const auto View = CompileView(Directory);
    auto First = Acquire(View, {.Credential = CredentialOf(FirstRecord), .Rate = RateRequest{0, 1, 1}});
    auto Second = Acquire(View, {.Credential = CredentialOf(SecondRecord), .Rate = RateRequest{0, 1, 1}});
    ASSERT_TRUE(First); ASSERT_TRUE(Second);
    auto Destination = std::move(*First);
    auto Source = std::move(*Second);
    Destination = std::move(Source);
    EXPECT_EQ(FirstBinding->Runtime()->ActiveConnections(), 0U);
    EXPECT_EQ(SecondBinding->Runtime()->ActiveConnections(), 1U);
    EXPECT_FALSE(Source);
    Destination.Release(); Destination.Release();
    EXPECT_EQ(SecondBinding->Runtime()->ActiveConnections(), 0U);
}

TEST(PrismAccountLease, DrainWakesMultipleWaitersAfterFinalChildRelease)
{
    const auto Record = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{116},
        .CredentialValue = Credential::Password("lease-drain-multiple-waiters"),
        .Quota = {.MaxConnections = 1, .MaxStreams = 1}});
    AccountStore Directory;
    ASSERT_TRUE(Publish(Directory, Record));
    const auto Binding = Directory.FindById(Prism::AccountId{116});
    ASSERT_TRUE(Binding);
    auto RootResult = Acquire(CompileView(Directory),
        {.Credential = CredentialOf(Record), .Rate = RateRequest{0, 1, 1}});
    ASSERT_TRUE(RootResult);
    auto ChildResult = RootResult->TryAcquireStream();
    ASSERT_TRUE(ChildResult);
    ASSERT_TRUE(Directory.Revoke(Prism::AccountId{116}));

    // executor 的真实 io_context 必须比持有 channel 的场景更晚析构。
    Net::io_context Io;
    MultiWaiterDrainScenario Scenario{
        Binding->Runtime(), std::move(*RootResult), std::move(*ChildResult),
        std::chrono::steady_clock::now() + std::chrono::seconds(5)};
    const auto Executor = Net::make_strand(Io);
    std::exception_ptr DriverException;
    Net::co_spawn(Executor, RunMultiWaiterDrain(Scenario),
        [&DriverException](const std::exception_ptr Error) { DriverException = Error; });
    Io.run();

    EXPECT_FALSE(DriverException);
    EXPECT_EQ(Scenario.StartedBeforeRetirement, 2U);
    EXPECT_EQ(Scenario.ActiveAfterRootRelease, 1U);
    EXPECT_EQ(Scenario.Runtime->ActiveConnections(), 0U);
    EXPECT_EQ(Scenario.Results.Completed, 2U);
    EXPECT_EQ(Scenario.Results.Succeeded, 2U);
    EXPECT_FALSE(Scenario.Results.FirstFailure.has_value());
    EXPECT_FALSE(Scenario.Results.Exception);
}

TEST(PrismAccountLease, DeadlineFailureKeepsRetiredRuntimePinnedByLease)
{
    const auto Record = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{117},
        .CredentialValue = Credential::Password("lease-drain-deadline"),
        .Quota = {.MaxConnections = 1}});
    AccountStore Directory;
    ASSERT_TRUE(Publish(Directory, Record));
    auto Binding = Directory.FindById(Prism::AccountId{117});
    ASSERT_TRUE(Binding);
    AccountLease Lease;
    {
        const auto View = CompileView(Directory);
        auto LeaseResult = Acquire(View,
            {.Credential = CredentialOf(Record), .Rate = RateRequest{0, 1, 1}});
        ASSERT_TRUE(LeaseResult);
        Lease = std::move(*LeaseResult);
    }
    const auto RuntimeWeak = std::weak_ptr<AccountRuntime>(Binding->Runtime());
    ASSERT_TRUE(Directory.Revoke(Prism::AccountId{117}));
    auto Remove = Directory.PrepareRemove(Prism::AccountId{117});
    ASSERT_TRUE(Remove);
    ASSERT_TRUE(Directory.Commit(*Remove));
    Binding.reset();

    DrainProbe Probe{RuntimeWeak.lock(), LeaseDrainDeadline::min()};
    ASSERT_TRUE(Probe.Runtime);
    Net::io_context Io;
    const auto Executor = Net::make_strand(Io);
    Net::co_spawn(Executor, RunDrainProbe(Probe),
        [&Probe](const std::exception_ptr Error) { Probe.Exception = Error; });
    Io.run();

    EXPECT_FALSE(Probe.Exception);
    ASSERT_TRUE(Probe.Outcome.has_value());
    ASSERT_FALSE(Probe.Outcome->has_value());
    EXPECT_EQ(Probe.Outcome->error().Code, Prism::Fault::Code::Timeout);
    EXPECT_EQ(Probe.Outcome->error().Native,
        std::make_error_code(std::errc::timed_out));
    Probe.Runtime.reset();
    EXPECT_FALSE(RuntimeWeak.expired());
    Lease.Release();
    EXPECT_TRUE(RuntimeWeak.expired());
}

TEST(PrismAccountLease, RuntimeIdentityMatchesPinnedBindingRuntime)
{
    static_assert(!std::is_same_v<AccountRuntimeIdentity, PolicyVersion>);
    const auto Record = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{118},
        .CredentialValue = Credential::Password("lease-runtime-identity"),
        .Quota = {.MaxConnections = 1}});
    AccountStore Directory;
    ASSERT_TRUE(Publish(Directory, Record));
    const auto Binding = Directory.FindById(Prism::AccountId{118});
    ASSERT_TRUE(Binding);
    auto LeaseResult = Acquire(CompileView(Directory),
        {.Credential = CredentialOf(Record), .Rate = RateRequest{0, 1, 1}});
    ASSERT_TRUE(LeaseResult);
    EXPECT_TRUE(LeaseResult->RuntimeIdentity().IsValid());
    EXPECT_TRUE(LeaseResult->RuntimeIdentity() == Binding->Runtime()->RuntimeIdentity());

    const auto Replacement = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{118},
        .CredentialValue = Credential::Password("lease-runtime-identity-updated"),
        .Quota = {.MaxConnections = 1}});
    ASSERT_TRUE(Publish(Directory, Replacement));
    const auto Updated = Directory.FindById(Prism::AccountId{118});
    ASSERT_TRUE(Updated);
    EXPECT_TRUE(Updated->Runtime()->RuntimeIdentity() == LeaseResult->RuntimeIdentity());
}

TEST(PrismAccountDirectory, RemoveReaddGetsNewRuntimeIdentityAfterOldOwnerRetires)
{
    const auto Original = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{119},
        .CredentialValue = Credential::Password("lease-runtime-old"),
        .Quota = {.MaxConnections = 1}});
    AccountStore Directory;
    ASSERT_TRUE(Publish(Directory, Original));
    std::weak_ptr<AccountRuntime> OldRuntimeWeak;
    AccountRuntimeIdentity OldIdentity;
    {
        auto OldBinding = Directory.FindById(Prism::AccountId{119});
        ASSERT_TRUE(OldBinding);
        OldRuntimeWeak = OldBinding->Runtime();
        const auto View = CompileView(Directory);
        auto LeaseResult = Acquire(View,
            {.Credential = CredentialOf(Original), .Rate = RateRequest{0, 1, 1}});
        ASSERT_TRUE(LeaseResult);
        auto OldLease = std::move(*LeaseResult);
        OldIdentity = OldLease.RuntimeIdentity();

        ASSERT_TRUE(Directory.Revoke(Prism::AccountId{119}));
        auto FirstRemove = Directory.PrepareRemove(Prism::AccountId{119});
        ASSERT_TRUE(FirstRemove);
        ASSERT_TRUE(Directory.Commit(*FirstRemove));
        const auto SameIdReadd = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{119},
            .CredentialValue = Credential::Password("lease-runtime-same-owner"),
            .Quota = {.MaxConnections = 1}});
        ASSERT_TRUE(Publish(Directory, SameIdReadd));
        const auto ReaddedWhileOldOwnerLives = Directory.FindById(Prism::AccountId{119});
        ASSERT_TRUE(ReaddedWhileOldOwnerLives);
        EXPECT_TRUE(ReaddedWhileOldOwnerLives->Runtime() == OldBinding->Runtime());
        EXPECT_TRUE(ReaddedWhileOldOwnerLives->Runtime()->IsRevoked());
        EXPECT_TRUE(ReaddedWhileOldOwnerLives->Runtime()->RuntimeIdentity() == OldIdentity);

        auto SecondRemove = Directory.PrepareRemove(Prism::AccountId{119});
        ASSERT_TRUE(SecondRemove);
        ASSERT_TRUE(Directory.Commit(*SecondRemove));
        OldLease.Release();
    }
    EXPECT_TRUE(OldRuntimeWeak.expired());

    const auto Fresh = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{119},
        .CredentialValue = Credential::Password("lease-runtime-fresh-owner"),
        .Quota = {.MaxConnections = 1}});
    ASSERT_TRUE(Publish(Directory, Fresh));
    const auto FreshBinding = Directory.FindById(Prism::AccountId{119});
    ASSERT_TRUE(FreshBinding);
    EXPECT_TRUE(FreshBinding->Runtime()->IsRevoked());
    EXPECT_FALSE(FreshBinding->Runtime()->RuntimeIdentity() == OldIdentity);
}
