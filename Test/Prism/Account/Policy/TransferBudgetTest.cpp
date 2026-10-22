/** @file TransferBudgetTest.cpp @brief 内存账本下的账户信用发放与结算。 */
#include <Prism/Account/Binding.hpp>
#include <Prism/Account/Credential.hpp>
#include <Prism/Account/CredentialScope.hpp>
#include <Prism/Account/Detail/TransferRequestKey.hpp>
#include <Prism/Account/Detail/TransferSequence.hpp>
#include <Prism/Account/Materials.hpp>
#include <Prism/Account/Policy.hpp>
#include <Prism/Account/PolicyVersion.hpp>
#include <Prism/Account/Runtime.hpp>
#include <Prism/Account/RuntimeRegistry.hpp>
#include <Prism/Account/Store.hpp>
#include <Prism/Account/TransferBudget.hpp>
#include <Prism/Account/UsagePersistence.hpp>
#include <Prism/Contract/Account/PayloadBudget.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <exception>
#include <expected>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    using PayloadDirection = Prism::Contract::PayloadDirection;
    using PayloadRequest = Prism::Contract::PayloadRequest;
    using PolicySettings = Prism::Account::PolicySettings;
    using PolicySnapshot = Prism::Account::PolicySnapshot;
    using PolicySource = Prism::Account::PolicySource;
    using TransferBudget = Prism::Account::TransferBudget;
    using TransferBudgetOptions = Prism::Account::TransferBudgetOptions;
    using UsageCycle = Prism::Account::UsageCycle;
    using UsageCycleRequest = Prism::Account::UsageCycleRequest;
    using UsagePersistence = Prism::Account::UsagePersistence;
    using UsageReadRequest = Prism::Account::UsageReadRequest;
    using UsageReservation = Prism::Account::UsageReservation;
    using UsageReservationRequest = Prism::Account::UsageReservationRequest;
    using UsageSettlementRequest = Prism::Account::UsageSettlementRequest;
    using UsageAdjustmentRequest = Prism::Account::UsageAdjustmentRequest;
    using UsageSnapshot = Prism::Account::UsageSnapshot;

    class FixedPolicySource final : public PolicySource
    {
    public:
        explicit FixedPolicySource(std::shared_ptr<const PolicySnapshot> Policy)
            : Policy_(std::move(Policy))
        {
        }

        [[nodiscard]] auto Load(Prism::AccountId) const noexcept
            -> std::shared_ptr<const PolicySnapshot> override
        {
            return Policy_;
        }

    private:
        std::shared_ptr<const PolicySnapshot> Policy_;
    };

    class InMemoryUsageLedger final : public UsagePersistence
    {
    public:
        auto ResolveCycle(UsageCycleRequest) -> Net::awaitable<
            std::expected<UsageCycle, Fault::Failure>> override
        {
            ++ResolveCalls;
            co_return UsageCycle{1000, std::nullopt};
        }

        auto Read(UsageReadRequest Request) -> Net::awaitable<
            std::expected<UsageSnapshot, Fault::Failure>> override
        {
            AccountKey_ = std::move(Request.AccountKey);
            Cycle_ = Request.Cycle;
            Limit_ = Request.LimitBytes;
            co_return Snapshot();
        }

        auto Reserve(UsageReservationRequest Request) -> Net::awaitable<
            std::expected<UsageReservation, Fault::Failure>> override
        {
            ++ReserveCalls;
            AccountKey_ = Request.Usage.AccountKey;
            Cycle_ = Request.Usage.Cycle;
            Limit_ = Request.Usage.LimitBytes;
            LastRequest = Request;
            if (SettledRequestKeys_.contains(Request.RequestKey))
            {
                co_return std::unexpected(Fault::Failure{Fault::Code::ReplayDetected});
            }
            if (!Limit_)
            {
                co_return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
            }
            const auto Used = SettledBytes_ + ReservedBytes_;
            const auto Remaining = *Limit_ > Used ? *Limit_ - Used : 0U;
            const auto Granted = (std::min)(Request.Bytes,
                (std::min)(Request.OutstandingLimit, Remaining));
            if (Granted == 0U)
            {
                co_return std::unexpected(Fault::Failure{Fault::Code::Blocked});
            }
            ReservationId_ = "memory-reservation";
            ReservedBytes_ += Granted;
            co_return UsageReservation{ReservationId_, Request.RequestKey, AccountKey_,
                Cycle_, Granted, Revision_};
        }

        auto Settle(UsageSettlementRequest Request) -> Net::awaitable<
            std::expected<UsageSnapshot, Fault::Failure>> override
        {
            ++SettleCalls;
            LastSettlement = Request;
            if (Request.ReservationId != ReservationId_ ||
                Request.ConsumedBytes > ReservedBytes_)
            {
                co_return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
            }
            if (Request.Final)
            {
                if (LastRequest) { SettledRequestKeys_.insert(LastRequest->RequestKey); }
                SettledBytes_ += Request.ConsumedBytes;
                ReservedBytes_ = 0U;
                ReservationId_.clear();
                ++Revision_;
            }
            co_return Snapshot();
        }

        auto Adjust(UsageAdjustmentRequest) -> Net::awaitable<
            std::expected<UsageSnapshot, Fault::Failure>> override
        {
            co_return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
        }

        [[nodiscard]] auto Snapshot() const -> UsageSnapshot
        {
            UsageSnapshot Result;
            Result.AccountKey = AccountKey_;
            Result.Cycle = Cycle_;
            Result.Revision = Revision_;
            Result.LimitBytes = Limit_;
            Result.SettledBytes = SettledBytes_;
            Result.ReservedBytes = ReservedBytes_;
            if (Limit_)
            {
                const auto Used = SettledBytes_ + ReservedBytes_;
                Result.RemainingBytes = *Limit_ > Used ? *Limit_ - Used : 0U;
            }
            return Result;
        }

        std::uint32_t ResolveCalls{0U};
        std::uint32_t ReserveCalls{0U};
        std::uint32_t SettleCalls{0U};
        std::optional<UsageReservationRequest> LastRequest;
        std::optional<UsageSettlementRequest> LastSettlement;

    private:
        std::string AccountKey_;
        UsageCycle Cycle_{};
        std::optional<std::uint64_t> Limit_;
        std::string ReservationId_;
        std::uint64_t ReservedBytes_{0U};
        std::uint64_t SettledBytes_{0U};
        std::uint64_t Revision_{1U};
        std::set<std::string> SettledRequestKeys_;
    };

    struct TransferScenario final
    {
        std::shared_ptr<TransferBudget> Budget;
        std::shared_ptr<InMemoryUsageLedger> Ledger;
        std::optional<Fault::Failure> Failure;
        std::uint64_t FirstGrant{0U};
        std::uint64_t SecondGrant{0U};
        std::uint64_t MovedGrant{0U};
    };

    auto RunTransferScenario(TransferScenario& Scenario) -> Net::awaitable<void>
    {
        {
            auto First = co_await Scenario.Budget->Acquire(
                PayloadRequest{9U, PayloadDirection::Upload, false});
            if (!First)
            {
                Scenario.Failure = First.error();
                co_return;
            }
            Scenario.FirstGrant = First->Bytes();

            auto Second = co_await Scenario.Budget->Acquire(
                PayloadRequest{5U, PayloadDirection::Upload, false});
            if (!Second)
            {
                Scenario.Failure = Second.error();
                co_return;
            }
            Scenario.SecondGrant = Second->Bytes();

            auto Destination = std::move(*First);
            Destination = std::move(*Second);
            Scenario.MovedGrant = Destination.Bytes();
            Destination.Finish(8U);
        }

        const auto Flushed = co_await Scenario.Budget->Flush(true);
        if (!Flushed)
        {
            Scenario.Failure = Flushed.error();
        }
    }

    /** @brief 同时固定runtime registry与store，验证账户重绑时runtime回收。 */
    struct AccountTransferOwner final
    {
        std::shared_ptr<Prism::Account::AccountRuntimeRegistry> Registry;
        std::unique_ptr<Prism::Account::AccountStore> Store;
    };

    /** @brief 为持久预算用例创建有界流量策略。 */
    auto MakeTransferPolicySource() -> std::shared_ptr<FixedPolicySource>
    {
        PolicySettings Settings;
        Settings.Transfer.TrafficBytes = 100U;
        Settings.Transfer.UploadBytesPerSecond = 65535U;
        auto Policy = std::make_shared<PolicySnapshot>(PolicySnapshot::CreateRequest{
            Prism::Account::PolicyVersion{1U}, std::move(Settings), {}});
        return std::make_shared<FixedPolicySource>(std::move(Policy));
    }

    auto MakeTransferPolicySourceFromSettings(PolicySettings Settings)
        -> std::shared_ptr<FixedPolicySource>
    {
        auto Policy = std::make_shared<PolicySnapshot>(PolicySnapshot::CreateRequest{
            Prism::Account::PolicyVersion{1U}, std::move(Settings), {}});
        return std::make_shared<FixedPolicySource>(std::move(Policy));
    }

    /** @brief 连接测试账本并创建真实AccountStore owner。 */
    auto MakeTransferAccountOwner(const std::shared_ptr<FixedPolicySource>& Policies,
        const std::shared_ptr<InMemoryUsageLedger>& Ledger, std::string Incarnation)
        -> std::optional<AccountTransferOwner>
    {
        auto Registry = std::make_shared<Prism::Account::AccountRuntimeRegistry>();
        if (!Registry->AttachPolicySource(Policies) ||
            !Registry->AttachUsagePersistence(Ledger, std::move(Incarnation)))
        {
            return std::nullopt;
        }
        auto Store = std::make_unique<Prism::Account::AccountStore>(
            Prism::Account::StoreOptions{.RuntimeRegistry = Registry});
        return AccountTransferOwner{std::move(Registry), std::move(Store)};
    }

    /** @brief 以固定显示身份构造可重复绑定的账户。 */
    auto MakeTransferAccountDefinition(const Prism::AccountId Id)
        -> Prism::Account::AccountDefinition
    {
        std::vector<Prism::Account::CredentialMaterial> Credentials;
        Credentials.push_back({Prism::Account::CredentialScope{1U}, {},
            Prism::Account::Credential::Password("transfer-budget-account")});
        auto Materials = std::make_shared<const Prism::Account::AccountMaterials>(
            Prism::Account::AccountMaterials::CreateRequest{
                Id, "stable-transfer-account", std::move(Credentials)});
        return {std::move(Materials), Prism::Account::PolicySettings{}};
    }

    /** @brief 通过真实prepare/commit路径发布账户binding。 */
    auto BindTransferAccount(Prism::Account::AccountStore& Store,
        const Prism::Account::AccountDefinition& Definition)
        -> std::shared_ptr<const Prism::Account::AccountBinding>
    {
        auto Prepared = Store.PrepareUpsert(Definition);
        if (!Prepared || !Store.Commit(*Prepared)) { return {}; }
        return Store.FindById(Definition.Materials->AccountId());
    }

    /** @brief 在专属io_context中完整驱动一次异步流量场景。 */
    auto RunTransferScenarioNow(TransferScenario& Scenario) -> std::exception_ptr
    {
        Net::io_context Io;
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunTransferScenario(Scenario),
            [&Exception](std::exception_ptr Error) { Exception = Error; });
        Io.run();
        return Exception;
    }

    struct BudgetAcquireScenario final
    {
        std::shared_ptr<TransferBudget> Budget;
        PayloadRequest Request;
        std::optional<Fault::Failure> Failure;
        std::uint64_t Granted{0U};
    };

    auto RunBudgetAcquireScenario(BudgetAcquireScenario& Scenario) -> Net::awaitable<void>
    {
        auto Permit = co_await Scenario.Budget->Acquire(Scenario.Request);
        if (!Permit)
        {
            Scenario.Failure = Permit.error();
            co_return;
        }
        Scenario.Granted = Permit->Bytes();
        Permit->Finish(Scenario.Granted);
        const auto Flushed = co_await Scenario.Budget->Flush(true);
        if (!Flushed) { Scenario.Failure = Flushed.error(); }
    }

    auto RunBudgetAcquireScenarioNow(BudgetAcquireScenario& Scenario)
        -> std::exception_ptr
    {
        Net::io_context Io;
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunBudgetAcquireScenario(Scenario),
            [&Exception](std::exception_ptr Error) { Exception = Error; });
        Io.run();
        return Exception;
    }

    /** @brief 表示预算请求键中的进程 incarnation 与账户 key。 */
    struct RequestKeyIdentity final
    {
        std::string_view Incarnation;
        std::string_view AccountKey;
    };

    /** @brief 检查请求 key 是否含有按长度编码的进程与账户身份。 */
    auto HasRequestKeyIdentity(const std::string_view RequestKey,
        const RequestKeyIdentity Identity) -> bool
    {
        const auto Encoded = ":" + std::to_string(Identity.Incarnation.size()) + ":" +
            std::string(Identity.Incarnation) + ":" +
            std::to_string(Identity.AccountKey.size()) + ":" +
            std::string(Identity.AccountKey) + ":";
        return RequestKey.find(Encoded) != std::string_view::npos;
    }

} // namespace

TEST(PrismTransferBudget, AcquiresPersistsAndRefundsExactClampedPayloadUsage)
{
    PolicySettings Settings;
    Settings.Transfer.TrafficBytes = 100U;
    Settings.Transfer.UploadBytesPerSecond = 65535U;
    const auto Policy = std::make_shared<PolicySnapshot>(PolicySnapshot::CreateRequest{
        Prism::Account::PolicyVersion{1U}, std::move(Settings), {}});
    auto Policies = std::make_shared<FixedPolicySource>(Policy);
    auto Ledger = std::make_shared<InMemoryUsageLedger>();
    TransferBudgetOptions Options;
    Options.Id = Prism::AccountId{7101U};
    Options.AccountKey = "transfer-budget-memory";
    Options.Policies = std::move(Policies);
    Options.Persistence = Ledger;
    Options.Incarnation = "test-incarnation";
    TransferScenario Scenario{std::make_shared<TransferBudget>(std::move(Options)), Ledger};

    Net::io_context Io;
    std::exception_ptr Exception;
    Net::co_spawn(Io, RunTransferScenario(Scenario),
        [&Exception](std::exception_ptr Error) { Exception = Error; });
    Io.run();

    ASSERT_FALSE(Exception);
    ASSERT_FALSE(Scenario.Failure.has_value());
    EXPECT_EQ(Scenario.FirstGrant, 9U);
    EXPECT_EQ(Scenario.SecondGrant, 5U);
    EXPECT_EQ(Scenario.MovedGrant, 5U);
    ASSERT_EQ(Ledger->ResolveCalls, 1U);
    ASSERT_EQ(Ledger->ReserveCalls, 1U);
    ASSERT_EQ(Ledger->SettleCalls, 1U);
    ASSERT_TRUE(Ledger->LastSettlement.has_value());
    EXPECT_EQ(Ledger->LastSettlement->ConsumedBytes, 5U);
    EXPECT_TRUE(Ledger->LastSettlement->Final);
    EXPECT_EQ(Ledger->Snapshot().SettledBytes, 5U);
    EXPECT_EQ(Ledger->Snapshot().ReservedBytes, 0U);
    EXPECT_EQ(Ledger->Snapshot().RemainingBytes, 95U);
    EXPECT_TRUE(Scenario.Budget->AdmissionAllowed());
}

TEST(PrismTransferBudget, RecreatedBudgetUsesDistinctReservationRequestKey)
{
    constexpr Prism::AccountId Id{7102U};
    constexpr std::string_view Incarnation{"test-incarnation"};
    const auto Policies = MakeTransferPolicySource();
    const auto Ledger = std::make_shared<InMemoryUsageLedger>();
    auto Owner = MakeTransferAccountOwner(Policies, Ledger, std::string(Incarnation));
    ASSERT_TRUE(Owner.has_value());
    const auto Definition = MakeTransferAccountDefinition(Id);
    auto FirstBinding = BindTransferAccount(*Owner->Store, Definition);
    ASSERT_TRUE(FirstBinding);
    ASSERT_EQ(FirstBinding->Runtime()->StableKey(), "stable-transfer-account");
    auto FirstBudget = FirstBinding->Runtime()->Transfer();
    ASSERT_TRUE(FirstBudget);
    std::weak_ptr<Prism::Account::AccountRuntime> FirstRuntime = FirstBinding->Runtime();
    TransferScenario First{FirstBudget, Ledger};
    const auto FirstException = RunTransferScenarioNow(First);
    ASSERT_FALSE(FirstException);
    ASSERT_FALSE(First.Failure.has_value());
    ASSERT_TRUE(Ledger->LastRequest.has_value());
    const auto FirstRequestKey = Ledger->LastRequest->RequestKey;
    ASSERT_EQ(Ledger->ReserveCalls, 1U);
    EXPECT_EQ(Ledger->LastRequest->Usage.AccountKey, "stable-transfer-account");
    EXPECT_TRUE(FirstRequestKey.starts_with("budget:"));
    EXPECT_TRUE(HasRequestKeyIdentity(FirstRequestKey,
        RequestKeyIdentity{Incarnation, "stable-transfer-account"}));
    EXPECT_TRUE(FirstRequestKey.ends_with(":1"));

    auto Removed = Owner->Store->PrepareRemove(Id);
    ASSERT_TRUE(Removed);
    ASSERT_TRUE(Owner->Store->Commit(*Removed));
    EXPECT_FALSE(Owner->Store->FindById(Id));
    First.Budget.reset();
    FirstBudget.reset();
    FirstBinding.reset();
    EXPECT_TRUE(FirstRuntime.expired());

    auto SecondBinding = BindTransferAccount(*Owner->Store, Definition);
    ASSERT_TRUE(SecondBinding);
    EXPECT_EQ(SecondBinding->Runtime()->StableKey(), "stable-transfer-account");
    TransferScenario Second{SecondBinding->Runtime()->Transfer(), Ledger};
    ASSERT_TRUE(Second.Budget);
    const auto SecondException = RunTransferScenarioNow(Second);
    ASSERT_FALSE(SecondException);
    ASSERT_FALSE(Second.Failure.has_value());
    ASSERT_EQ(Ledger->ReserveCalls, 2U);
    ASSERT_TRUE(Ledger->LastRequest.has_value());
    EXPECT_EQ(Ledger->LastRequest->Usage.AccountKey, "stable-transfer-account");
    EXPECT_TRUE(Ledger->LastRequest->RequestKey.starts_with("budget:"));
    EXPECT_TRUE(HasRequestKeyIdentity(Ledger->LastRequest->RequestKey,
        RequestKeyIdentity{Incarnation, "stable-transfer-account"}));
    EXPECT_TRUE(Ledger->LastRequest->RequestKey.ends_with(":1"));
    EXPECT_NE(Ledger->LastRequest->RequestKey, FirstRequestKey);
}

TEST(PrismAccountIdentityContract, RejectedCommitPreservesPublishedRuntime)
{
    const auto Policies = MakeTransferPolicySource();
    const auto Ledger = std::make_shared<InMemoryUsageLedger>();
    auto Registry = std::make_shared<Prism::Account::AccountRuntimeRegistry>();
    ASSERT_TRUE(Registry->AttachPolicySource(Policies));
    ASSERT_TRUE(Registry->AttachUsagePersistence(Ledger, "failed-prepare"));
    Prism::Account::AccountStore Store(Prism::Account::StoreOptions{
        .RuntimeRegistry = Registry, .RevokeRuntimesOnSeal = false});
    const auto Published = MakeTransferAccountDefinition(Prism::AccountId{7106U});
    ASSERT_TRUE(BindTransferAccount(Store, Published));
    const auto Runtime = Store.FindById(Prism::AccountId{7106U})->Runtime();
    const auto OriginalKey = Runtime->StableKey();
    const auto OriginalTransfer = Runtime->Transfer();

    std::vector<Prism::Account::CredentialMaterial> Credentials;
    Credentials.push_back({Prism::Account::CredentialScope{1U}, {},
        Prism::Account::Credential::Password("failed-prepare-credential")});
    auto Materials = std::make_shared<const Prism::Account::AccountMaterials>(
        Prism::Account::AccountMaterials::CreateRequest{
            Prism::AccountId{7106U}, "different-stable-key", std::move(Credentials)});
    auto Prepared = Store.PrepareUpsert(Prism::Account::AccountDefinition{
        std::move(Materials), {}});
    ASSERT_TRUE(Prepared);
    const auto Rejected = Store.Commit(*Prepared);
    ASSERT_FALSE(Rejected);
    EXPECT_EQ(Rejected.error().Code, Fault::Code::InvalidArgument);
    EXPECT_EQ(Runtime->StableKey(), OriginalKey);
    EXPECT_EQ(Runtime->Transfer(), OriginalTransfer);
    EXPECT_EQ(Store.FindById(Prism::AccountId{7106U})->Runtime(), Runtime);
}

TEST(PrismTransferBudget, IndependentRuntimeRegistriesUseDistinctRequestNamespaces)
{
    constexpr Prism::AccountId Id{7103U};
    constexpr std::string_view Incarnation{"test-incarnation"};
    const auto Policies = MakeTransferPolicySource();
    const auto Ledger = std::make_shared<InMemoryUsageLedger>();
    auto FirstOwner = MakeTransferAccountOwner(Policies, Ledger, std::string(Incarnation));
    auto SecondOwner = MakeTransferAccountOwner(Policies, Ledger, std::string(Incarnation));
    ASSERT_TRUE(FirstOwner.has_value());
    ASSERT_TRUE(SecondOwner.has_value());
    const auto Definition = MakeTransferAccountDefinition(Id);
    const auto FirstBinding = BindTransferAccount(*FirstOwner->Store, Definition);
    const auto SecondBinding = BindTransferAccount(*SecondOwner->Store, Definition);
    ASSERT_TRUE(FirstBinding);
    ASSERT_TRUE(SecondBinding);
    EXPECT_NE(FirstBinding->Runtime(), SecondBinding->Runtime());
    EXPECT_EQ(FirstBinding->Runtime()->StableKey(), SecondBinding->Runtime()->StableKey());

    TransferScenario First{FirstBinding->Runtime()->Transfer(), Ledger};
    ASSERT_TRUE(First.Budget);
    ASSERT_FALSE(RunTransferScenarioNow(First));
    ASSERT_FALSE(First.Failure.has_value());
    ASSERT_TRUE(Ledger->LastRequest.has_value());
    const auto FirstRequestKey = Ledger->LastRequest->RequestKey;
    EXPECT_EQ(Ledger->LastRequest->Usage.AccountKey, "stable-transfer-account");
    EXPECT_TRUE(HasRequestKeyIdentity(FirstRequestKey,
        RequestKeyIdentity{Incarnation, "stable-transfer-account"}));
    EXPECT_TRUE(FirstRequestKey.ends_with(":1"));

    TransferScenario Second{SecondBinding->Runtime()->Transfer(), Ledger};
    ASSERT_TRUE(Second.Budget);
    ASSERT_FALSE(RunTransferScenarioNow(Second));
    ASSERT_FALSE(Second.Failure.has_value());
    ASSERT_TRUE(Ledger->LastRequest.has_value());
    EXPECT_EQ(Ledger->LastRequest->Usage.AccountKey, "stable-transfer-account");
    EXPECT_NE(Ledger->LastRequest->RequestKey, FirstRequestKey);
    EXPECT_TRUE(Ledger->LastRequest->RequestKey.starts_with("budget:"));
    EXPECT_TRUE(HasRequestKeyIdentity(Ledger->LastRequest->RequestKey,
        RequestKeyIdentity{Incarnation, "stable-transfer-account"}));
    EXPECT_TRUE(Ledger->LastRequest->RequestKey.ends_with(":1"));
}

TEST(PrismAccountIdentityContract, PersistenceCannotAdoptRuntimeWithoutStableKey)
{
    const auto Policies = MakeTransferPolicySource();
    const auto Ledger = std::make_shared<InMemoryUsageLedger>();
    auto Registry = std::make_shared<Prism::Account::AccountRuntimeRegistry>();
    ASSERT_TRUE(Registry->AttachPolicySource(Policies));
    const auto Runtime = Registry->FindOrCreate(Prism::AccountId{7104U}, 1U);
    ASSERT_TRUE(Runtime);
    EXPECT_TRUE((*Runtime)->StableKey().empty());

    const auto Attached = Registry->AttachUsagePersistence(Ledger, "identity-contract");
    ASSERT_FALSE(Attached);
    EXPECT_EQ(Attached.error().Code, Fault::Code::InvalidArgument);
    EXPECT_FALSE((*Runtime)->Transfer());

    Prism::Account::AccountStore Store(Prism::Account::StoreOptions{
        .RuntimeRegistry = Registry, .RevokeRuntimesOnSeal = false});
    std::vector<Prism::Account::CredentialMaterial> Credentials;
    Credentials.push_back({Prism::Account::CredentialScope{1U}, {},
        Prism::Account::Credential::Password("identity-contract-retry")});
    auto Materials = std::make_shared<const Prism::Account::AccountMaterials>(
        Prism::Account::AccountMaterials::CreateRequest{
            Prism::AccountId{7104U}, "identity-contract", std::move(Credentials)});
    auto Prepared = Store.PrepareUpsert(
        Prism::Account::AccountDefinition{std::move(Materials), {}});
    ASSERT_TRUE(Prepared);
    ASSERT_TRUE(Store.Commit(*Prepared));
    ASSERT_TRUE(Registry->AttachUsagePersistence(Ledger, "identity-contract"));
    EXPECT_TRUE((*Runtime)->Transfer());
}

TEST(PrismAccountIdentityContract, PersistenceRejectsBindingWithoutStableKey)
{
    const auto Policies = MakeTransferPolicySource();
    const auto Ledger = std::make_shared<InMemoryUsageLedger>();
    auto Registry = std::make_shared<Prism::Account::AccountRuntimeRegistry>();
    ASSERT_TRUE(Registry->AttachPolicySource(Policies));
    ASSERT_TRUE(Registry->AttachUsagePersistence(Ledger, "identity-contract"));
    Prism::Account::AccountStore Store(Prism::Account::StoreOptions{
        .RuntimeRegistry = Registry, .RevokeRuntimesOnSeal = false});
    std::vector<Prism::Account::CredentialMaterial> Credentials;
    Credentials.push_back({Prism::Account::CredentialScope{1U}, {},
        Prism::Account::Credential::Password("empty-display-identity")});
    auto Materials = std::make_shared<const Prism::Account::AccountMaterials>(
        Prism::Account::AccountMaterials::CreateRequest{
            Prism::AccountId{7105U}, {}, std::move(Credentials)});

    const auto Prepared = Store.PrepareUpsert(
        Prism::Account::AccountDefinition{std::move(Materials), {}});
    ASSERT_FALSE(Prepared);
    EXPECT_EQ(Prepared.error().Code, Fault::Code::InvalidArgument);
    EXPECT_FALSE(Store.FindById(Prism::AccountId{7105U}));
}

TEST(PrismTransferBudget, RequestSequenceSaturatesWithoutReusingKeys)
{
    std::atomic<std::uint64_t> Sequence{std::numeric_limits<std::uint64_t>::max() - 1U};
    const auto Last = Prism::Account::Detail::TryTakeRequestSequence(Sequence);

    ASSERT_TRUE(Last.has_value());
    EXPECT_EQ(*Last, std::numeric_limits<std::uint64_t>::max() - 1U);
    EXPECT_EQ(Sequence.load(std::memory_order_relaxed), std::numeric_limits<std::uint64_t>::max());
    EXPECT_FALSE(Prism::Account::Detail::TryTakeRequestSequence(Sequence).has_value());
    EXPECT_EQ(Sequence.load(std::memory_order_relaxed), std::numeric_limits<std::uint64_t>::max());
    EXPECT_FALSE(Prism::Account::Detail::TryTakeRequestSequence(Sequence).has_value());
}

TEST(PrismTransferBudget, RequestKeyLengthPrefixesSeparateIdentityComponents)
{
    const auto First = Prism::Account::Detail::MakeTransferRequestKey({
        .Namespace = 1U, .Incarnation = "x", .AccountKey = "y:z", .Sequence = 1U});
    const auto Second = Prism::Account::Detail::MakeTransferRequestKey({
        .Namespace = 1U, .Incarnation = "x:y", .AccountKey = "z", .Sequence = 1U});

    ASSERT_TRUE(First.has_value());
    ASSERT_TRUE(Second.has_value());
    EXPECT_NE(*First, *Second);
}

TEST(PrismTransferBudget, NullTrafficQuotaBypassesPersistenceWhileFiniteQuotaClampsGrant)
{
    auto FiniteLedger = std::make_shared<InMemoryUsageLedger>();
    PolicySettings FiniteSettings;
    FiniteSettings.Transfer.TrafficBytes = 5U;
    auto FinitePolicies = MakeTransferPolicySourceFromSettings(std::move(FiniteSettings));
    TransferBudgetOptions FiniteOptions;
    FiniteOptions.Id = Prism::AccountId{7104U};
    FiniteOptions.AccountKey = "finite-transfer-quota";
    FiniteOptions.Policies = std::move(FinitePolicies);
    FiniteOptions.Persistence = FiniteLedger;
    FiniteOptions.Incarnation = "finite-quota-test";
    BudgetAcquireScenario Finite{std::make_shared<TransferBudget>(std::move(FiniteOptions)),
        PayloadRequest{9U, PayloadDirection::Upload, false}};

    ASSERT_FALSE(RunBudgetAcquireScenarioNow(Finite));
    ASSERT_FALSE(Finite.Failure.has_value());
    EXPECT_EQ(Finite.Granted, 5U);
    EXPECT_EQ(FiniteLedger->ResolveCalls, 1U);
    EXPECT_EQ(FiniteLedger->ReserveCalls, 1U);
    EXPECT_EQ(FiniteLedger->SettleCalls, 1U);
    EXPECT_EQ(FiniteLedger->Snapshot().SettledBytes, 5U);
    EXPECT_EQ(FiniteLedger->Snapshot().RemainingBytes, 0U);
    EXPECT_FALSE(Finite.Budget->AdmissionAllowed());

    auto UnlimitedLedger = std::make_shared<InMemoryUsageLedger>();
    PolicySettings UnlimitedSettings;
    UnlimitedSettings.Transfer.TrafficBytes = std::nullopt;
    auto UnlimitedPolicies = MakeTransferPolicySourceFromSettings(std::move(UnlimitedSettings));
    TransferBudgetOptions UnlimitedOptions;
    UnlimitedOptions.Id = Prism::AccountId{7105U};
    UnlimitedOptions.AccountKey = "unlimited-transfer-quota";
    UnlimitedOptions.Policies = std::move(UnlimitedPolicies);
    UnlimitedOptions.Persistence = UnlimitedLedger;
    UnlimitedOptions.Incarnation = "unlimited-quota-test";
    BudgetAcquireScenario Unlimited{std::make_shared<TransferBudget>(std::move(UnlimitedOptions)),
        PayloadRequest{9U, PayloadDirection::Upload, false}};

    ASSERT_FALSE(RunBudgetAcquireScenarioNow(Unlimited));
    ASSERT_FALSE(Unlimited.Failure.has_value());
    EXPECT_EQ(Unlimited.Granted, 9U);
    EXPECT_EQ(UnlimitedLedger->ResolveCalls, 0U);
    EXPECT_EQ(UnlimitedLedger->ReserveCalls, 0U);
    EXPECT_EQ(UnlimitedLedger->SettleCalls, 0U);
    EXPECT_TRUE(Unlimited.Budget->AdmissionAllowed());
}

TEST(PrismTransferBudget, NullUploadRateReturnsWholeRequestWhileFiniteRateReturnsBurst)
{
    constexpr std::uint64_t RequestBytes{1024U * 1024U};

    auto FiniteLedger = std::make_shared<InMemoryUsageLedger>();
    PolicySettings FiniteSettings;
    FiniteSettings.Transfer.TrafficBytes = std::nullopt;
    FiniteSettings.Transfer.UploadBytesPerSecond = 1U;
    auto FinitePolicies = MakeTransferPolicySourceFromSettings(std::move(FiniteSettings));
    TransferBudgetOptions FiniteOptions;
    FiniteOptions.Id = Prism::AccountId{7106U};
    FiniteOptions.AccountKey = "finite-transfer-rate";
    FiniteOptions.Policies = std::move(FinitePolicies);
    FiniteOptions.Persistence = FiniteLedger;
    FiniteOptions.Incarnation = "finite-rate-test";
    BudgetAcquireScenario Finite{std::make_shared<TransferBudget>(std::move(FiniteOptions)),
        PayloadRequest{RequestBytes, PayloadDirection::Upload, false}};

    ASSERT_FALSE(RunBudgetAcquireScenarioNow(Finite));
    ASSERT_FALSE(Finite.Failure.has_value());
    EXPECT_EQ(Finite.Granted, 65'535U);
    EXPECT_GT(Finite.Granted, 0U);
    EXPECT_LT(Finite.Granted, RequestBytes);
    EXPECT_EQ(FiniteLedger->ResolveCalls, 0U);
    EXPECT_EQ(FiniteLedger->ReserveCalls, 0U);
    EXPECT_EQ(FiniteLedger->SettleCalls, 0U);

    auto UnlimitedLedger = std::make_shared<InMemoryUsageLedger>();
    PolicySettings UnlimitedSettings;
    UnlimitedSettings.Transfer.TrafficBytes = std::nullopt;
    UnlimitedSettings.Transfer.UploadBytesPerSecond = std::nullopt;
    auto UnlimitedPolicies = MakeTransferPolicySourceFromSettings(std::move(UnlimitedSettings));
    TransferBudgetOptions UnlimitedOptions;
    UnlimitedOptions.Id = Prism::AccountId{7107U};
    UnlimitedOptions.AccountKey = "unlimited-transfer-rate";
    UnlimitedOptions.Policies = std::move(UnlimitedPolicies);
    UnlimitedOptions.Persistence = UnlimitedLedger;
    UnlimitedOptions.Incarnation = "unlimited-rate-test";
    BudgetAcquireScenario Unlimited{std::make_shared<TransferBudget>(std::move(UnlimitedOptions)),
        PayloadRequest{RequestBytes, PayloadDirection::Upload, false}};

    ASSERT_FALSE(RunBudgetAcquireScenarioNow(Unlimited));
    ASSERT_FALSE(Unlimited.Failure.has_value());
    EXPECT_EQ(Unlimited.Granted, RequestBytes);
    EXPECT_EQ(UnlimitedLedger->ResolveCalls, 0U);
    EXPECT_EQ(UnlimitedLedger->ReserveCalls, 0U);
    EXPECT_EQ(UnlimitedLedger->SettleCalls, 0U);
}
