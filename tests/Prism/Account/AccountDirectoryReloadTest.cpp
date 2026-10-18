/** @file AccountDirectoryReloadTest.cpp
 * @brief 原并发策略发布场景，读取一个完整Binding且使用其冻结quota。
 */
#include "AccountTestSupport.hpp"
#include <Prism/Application/Account/IdentityRegistry.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Runtime/GenerationPublication.hpp>
#include <TestSupport/Prism/AccountAdmissionAuthority.hpp>
namespace
{
    constexpr std::size_t Reloads = 256, Readers = 2, ReadsPerReader = 1024;
    struct ReloadWriterState final
    {
        AccountStore* Directory;
        std::barrier<>* Gate;
        std::atomic<std::uint32_t>* UpsertFailures;
    };
    struct ReloadReaderState final
    {
        Prism::Account::CredentialIndexView View;
        std::barrier<>* Gate;
        std::atomic<std::uint32_t>* GenerationMismatches;
        std::atomic<std::uint32_t>* MaxByteMismatches;
    };
    auto RunReloadWriter(ReloadWriterState State) -> void
    {
        State.Gate->arrive_and_wait();
        for (std::size_t Index = 0; Index < Reloads; ++Index)
        {
            const auto Replacement = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{116},
                .CredentialValue = Credential::Password("concurrent-policy-account"),
                .Quota = {.MaxBytes = (Index % 2U) + 1U}, .Rate = Prism::Account::UnlimitedRatePolicy{}});
            if (!Publish(*State.Directory, Replacement)) { State.UpsertFailures->fetch_add(1, std::memory_order_relaxed); }
        }
    }
    auto RunReloadReader(ReloadReaderState State) -> void
    {
        State.Gate->arrive_and_wait();
        for (std::size_t Index = 0; Index < ReadsPerReader; ++Index)
        {
            auto Result = Acquire(State.View, {.Credential = CredentialView::Password("concurrent-policy-account"),
                .Rate = RateRequest{0, 1, 1}});
            if (!Result) { continue; }
            auto Reserved = Result->ReserveBytes(2);
            if (Result->Binding()->Policy()->Version() != Result->PolicyVersion())
            { State.GenerationMismatches->fetch_add(1, std::memory_order_relaxed); }
            if (Reserved && Result->Binding()->Policy()->Quota().MaxBytes == 1)
            { State.MaxByteMismatches->fetch_add(1, std::memory_order_relaxed); }
            if (Reserved) { Reserved->Release(); }
            Result->Release();
        }
    }

    class AccountReloadGeneration final : public Prism::Foundation::GenerationLifetime
    {
    public:
        explicit AccountReloadGeneration(const std::uint64_t Value) noexcept : Id_(Value) {}

        [[nodiscard]] auto Id() const noexcept -> Prism::GenerationId override { return Id_; }

    private:
        Prism::GenerationId Id_;
    };

    [[nodiscard]] auto MakeAccountReloadGeneration(const std::uint64_t Id)
        -> std::shared_ptr<const Prism::Foundation::GenerationLifetime>
    {
        return std::make_shared<const AccountReloadGeneration>(Id);
    }

    [[nodiscard]] auto PublishAccountGeneration(
        Prism::Runtime::GenerationPublication &Publisher,
        const std::uint64_t Generation,
        std::vector<Prism::AccountId> Accounts) -> bool
    {
        auto Prepared = Publisher.Prepare(Publisher.Current(),
            MakeAccountReloadGeneration(Generation), std::move(Accounts));
        return Prepared && static_cast<bool>(Publisher.Publish(*Prepared));
    }

    [[nodiscard]] auto MakeAccountRuntimeRegistry(
        const std::shared_ptr<Prism::Runtime::GenerationPublication> &Publisher)
        -> std::shared_ptr<Prism::Account::AccountRuntimeRegistry>
    {
        auto Registry = std::make_shared<Prism::Account::AccountRuntimeRegistry>();
        if (!Registry->AttachAdmissionAuthority(Publisher)) { return {}; }
        return Registry;
    }

    [[nodiscard]] auto MakePublicationBoundStore(
        const std::shared_ptr<Prism::Account::AccountRuntimeRegistry> &RuntimeRegistry)
        -> std::unique_ptr<AccountStore>
    {
        return std::make_unique<AccountStore>(Prism::Account::StoreOptions{
            .WorkerCount = 1U,
            .RuntimeRegistry = RuntimeRegistry,
            .RevokeRuntimesOnSeal = false});
    }

    [[nodiscard]] auto InstallAccount(
        AccountStore &Store,
        const AccountDefinition &Definition) -> bool
    {
        auto Prepared = Store.PrepareUpsert(Definition);
        return Prepared && static_cast<bool>(Store.Commit(*Prepared));
    }
}
TEST(PrismAccountDirectory, InitialUpsertKeepsPolicyGenerationFloorAndAuthenticates)
{
    VerifyInitialPolicyGeneration(PolicyVersion{2}, Prism::AccountId{202});
    VerifyInitialPolicyGeneration(PolicyVersion{7}, Prism::AccountId{207});
}
TEST(PrismAccountAuthenticator, CallbackReturnsMoveOnlyLease)
{
    const auto Record = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{110},
        .CredentialValue = Credential::Password("callback-password"), .Quota = {.MaxConnections = 1}});
    auto Directory = std::make_shared<AccountStore>();
    ASSERT_TRUE(Publish(*Directory, Record));
    Prism::DirectoryAuthenticator AuthenticatorObject(CompileView(*Directory));
    auto Result = AuthenticatorObject.Authenticate({.Credential = CredentialOf(Record), .Rate = RateRequest{0, 1, 1}});
    ASSERT_TRUE(Result);
    EXPECT_EQ(Result->AccountId().Value(), 110U);
    EXPECT_TRUE(*Result);
    Result->Release();
}
TEST(PrismAccountDirectory, ConcurrentReloadPublishesMatchingPolicyGenerations)
{
    const auto Initial = MakeDefinition(AccountInput{.AccountId = Prism::AccountId{116},
        .CredentialValue = Credential::Password("concurrent-policy-account"), .Quota = {.MaxBytes = 1},
        .Rate = Prism::Account::UnlimitedRatePolicy{}});
    AccountStore Directory;
    ASSERT_TRUE(Publish(Directory, Initial));
    const auto View = CompileView(Directory);
    std::atomic<std::uint32_t> UpsertFailures{0}, GenerationMismatches{0}, MaxByteMismatches{0};
    std::barrier Gate(static_cast<std::ptrdiff_t>(Readers + 2));
    std::vector<std::thread> Threads;
    Threads.reserve(Readers + 1);
    Threads.emplace_back(RunReloadWriter, ReloadWriterState{&Directory, &Gate, &UpsertFailures});
    for (std::size_t Reader = 0; Reader < Readers; ++Reader)
    { Threads.emplace_back(RunReloadReader, ReloadReaderState{View, &Gate, &GenerationMismatches, &MaxByteMismatches}); }
    Gate.arrive_and_wait();
    for (auto& Thread : Threads) { Thread.join(); }
    EXPECT_EQ(UpsertFailures.load(std::memory_order_relaxed), 0U);
    EXPECT_EQ(GenerationMismatches.load(std::memory_order_relaxed), 0U);
    EXPECT_EQ(MaxByteMismatches.load(std::memory_order_relaxed), 0U);
}

TEST(PrismAccountDirectory, RuntimeIdentityCountersAndPolicyVersionContinueAcrossStores)
{
    const auto RuntimeRegistry = std::make_shared<Prism::Account::AccountRuntimeRegistry>();
    const auto StoreOptions = Prism::Account::StoreOptions{
        .WorkerCount = 1U,
        .RuntimeRegistry = RuntimeRegistry,
        .RevokeRuntimesOnSeal = false};
    const auto Id = Prism::AccountId{311U};
    const auto Initial = MakeDefinition(AccountInput{
        .AccountId = Id,
        .CredentialValue = Credential::Password("runtime-continuity-old"),
        .Quota = {.MaxConnections = 2U}});
    const auto Replacement = MakeDefinition(AccountInput{
        .AccountId = Id,
        .CredentialValue = Credential::Password("runtime-continuity-new"),
        .Quota = {.MaxConnections = 1U}});

    Prism::Account::AccountStore OldStore(StoreOptions);
    ASSERT_TRUE(Publish(OldStore, Initial));
    const auto OldBinding = OldStore.FindById(Id);
    ASSERT_TRUE(OldBinding);
    auto OldAdmission = Acquire(CompileView(OldStore), {
        .Credential = CredentialOf(Initial),
        .Rate = RateRequest{0, 1, 1}});
    ASSERT_TRUE(OldAdmission);
    EXPECT_EQ(OldBinding->Runtime()->ActiveConnections(), 1U);

    Prism::Account::AccountStore NewStore(StoreOptions);
    const std::array ReplacementSet{Replacement};
    auto Prepared = NewStore.PrepareReplacement(ReplacementSet);
    ASSERT_TRUE(Prepared);
    ASSERT_TRUE(NewStore.Commit(*Prepared));
    const auto NewBinding = NewStore.FindById(Id);
    ASSERT_TRUE(NewBinding);
    EXPECT_EQ(NewBinding->Runtime(), OldBinding->Runtime());
    EXPECT_EQ(NewBinding->Runtime()->RuntimeIdentity(), OldBinding->Runtime()->RuntimeIdentity());
    EXPECT_GT(NewBinding->Policy()->Version().Value(), OldBinding->Policy()->Version().Value());

    const auto NewView = CompileView(NewStore);
    auto RejectedWhileOldLeaseActive = Acquire(NewView, {
        .Credential = CredentialOf(Replacement),
        .Rate = RateRequest{0, 1, 1}});
    EXPECT_FALSE(RejectedWhileOldLeaseActive);
    ASSERT_FALSE(RejectedWhileOldLeaseActive);
    EXPECT_EQ(RejectedWhileOldLeaseActive.error().Native,
        Prism::Account::MakeFailure(Prism::Account::FailureReason::ConnectionQuota).Native);
    EXPECT_EQ(NewBinding->Runtime()->ActiveConnections(), 1U);
    OldAdmission->Release();
    EXPECT_EQ(NewBinding->Runtime()->ActiveConnections(), 0U);
    auto NewAdmission = Acquire(NewView, {
        .Credential = CredentialOf(Replacement),
        .Rate = RateRequest{0, 1, 1}});
    ASSERT_TRUE(NewAdmission);
    EXPECT_EQ(NewBinding->Runtime()->ActiveConnections(), 1U);
    NewAdmission->Release();
    EXPECT_EQ(NewBinding->Runtime()->ActiveConnections(), 0U);
}

TEST(PrismAccountDirectory, ExplicitRevocationSurvivesStoreReplacementAfterRuntimeRetirement)
{
    const auto RuntimeRegistry = std::make_shared<Prism::Account::AccountRuntimeRegistry>();
    const auto StoreOptions = Prism::Account::StoreOptions{
        .WorkerCount = 1U,
        .RuntimeRegistry = RuntimeRegistry,
        .RevokeRuntimesOnSeal = false};
    const auto Id = Prism::AccountId{312U};
    const auto Definition = MakeDefinition(AccountInput{
        .AccountId = Id,
        .CredentialValue = Credential::Password("runtime-revocation"),
        .Quota = {.MaxConnections = 1U}});
    std::weak_ptr<Prism::Account::AccountRuntime> RetiredRuntime;
    {
        Prism::Account::AccountStore OldStore(StoreOptions);
        ASSERT_TRUE(Publish(OldStore, Definition));
        const auto Binding = OldStore.FindById(Id);
        ASSERT_TRUE(Binding);
        RetiredRuntime = Binding->Runtime();
        ASSERT_TRUE(OldStore.Revoke(Id));
        EXPECT_TRUE(Binding->Runtime()->IsRevoked());
    }
    EXPECT_TRUE(RetiredRuntime.expired());

    Prism::Account::AccountStore NewStore(StoreOptions);
    const std::array ReplacementSet{Definition};
    auto Prepared = NewStore.PrepareReplacement(ReplacementSet);
    ASSERT_TRUE(Prepared);
    ASSERT_TRUE(NewStore.Commit(*Prepared));
    const auto NewBinding = NewStore.FindById(Id);
    ASSERT_TRUE(NewBinding);
    EXPECT_TRUE(NewBinding->Runtime()->IsRevoked());

    const auto Authentication = Acquire(CompileView(NewStore), {
        .Credential = CredentialOf(Definition),
        .Rate = RateRequest{0, 1, 1}});
    EXPECT_FALSE(Authentication);
    ASSERT_FALSE(Authentication);
    EXPECT_EQ(Authentication.error().Native,
        Prism::Account::MakeFailure(Prism::Account::FailureReason::Revoked).Native);
}

TEST(PrismAccountIdentityRegistry, AbandonedStagedNamesDoNotConsumeCommittedCapacity)
{
    const auto Registry = std::make_shared<Prism::Application::AccountIdentityRegistry>();
    Prism::AccountId AbandonedId;
    {
        auto Preparation = Registry->BeginPreparation();
        ASSERT_TRUE(Preparation);
        const auto Identity = (*Preparation)->Account("candidate-only-principal");
        ASSERT_TRUE(Identity);
        AbandonedId = *Identity;
        ASSERT_TRUE((*Preparation)->Scope("candidate-only-protocol"));
        ASSERT_TRUE((*Preparation)->StageCommit());
        EXPECT_EQ(Registry->AccountCount(), 0U);
        EXPECT_EQ(Registry->ScopeCount(), 0U);
    }
    EXPECT_EQ(Registry->AccountCount(), 0U);
    EXPECT_EQ(Registry->ScopeCount(), 0U);

    auto Preparation = Registry->BeginPreparation();
    ASSERT_TRUE(Preparation);
    const auto Identity = (*Preparation)->Account("candidate-only-principal");
    ASSERT_TRUE(Identity);
    EXPECT_EQ(Identity->Value(), AbandonedId.Value());
    ASSERT_TRUE((*Preparation)->Scope("candidate-only-protocol"));
    ASSERT_TRUE((*Preparation)->StageCommit());
    EXPECT_EQ(Registry->AccountCount(), 0U);
    EXPECT_EQ(Registry->ScopeCount(), 0U);
    ASSERT_TRUE((*Preparation)->Commit());
    EXPECT_EQ(Registry->AccountCount(), 1U);
    EXPECT_EQ(Registry->ScopeCount(), 1U);
}

TEST(PrismAccountIdentityRegistry, StagedIdentityRollbackDoesNotRevokeLiveRuntime)
{
    const auto Registry = std::make_shared<Prism::Application::AccountIdentityRegistry>();
    const auto RuntimeRegistry = Registry->RuntimeRegistry();
    const auto Authority = Prism::Testing::AccountAdmissionAuthorityForCurrentCase();
    ASSERT_TRUE(RuntimeRegistry->AttachAdmissionAuthority(Authority));
    Prism::AccountId Id;
    {
        auto Preparation = Registry->BeginPreparation();
        ASSERT_TRUE(Preparation);
        const auto Identity = (*Preparation)->Account("rollback-principal");
        ASSERT_TRUE(Identity);
        Id = *Identity;
        auto Runtime = RuntimeRegistry->FindOrCreate(Id, 1U);
        ASSERT_TRUE(Runtime);
        ASSERT_TRUE((*Preparation)->StageCommit());
        EXPECT_FALSE((*Runtime)->IsRevoked());
    }
    const auto RuntimeValue = RuntimeRegistry->FindOrCreate(Id, 1U);
    ASSERT_TRUE(RuntimeValue);
    EXPECT_FALSE((*RuntimeValue)->IsRevoked());
    EXPECT_TRUE(RuntimeRegistry->Revoke(Id));
    EXPECT_TRUE((*RuntimeValue)->IsRevoked());
}

TEST(PrismAccountIdentityRegistry, CommittedIdentityPreservesManualRuntimeTombstone)
{
    const auto Registry = std::make_shared<Prism::Application::AccountIdentityRegistry>();
    const auto RuntimeRegistry = Registry->RuntimeRegistry();
    const auto Authority = Prism::Testing::AccountAdmissionAuthorityForCurrentCase();
    ASSERT_TRUE(RuntimeRegistry->AttachAdmissionAuthority(Authority));
    auto Preparation = Registry->BeginPreparation();
    ASSERT_TRUE(Preparation);
    const auto Identity = (*Preparation)->Account("committed-removal-principal");
    ASSERT_TRUE(Identity);
    const auto RuntimeValue = RuntimeRegistry->FindOrCreate(*Identity, 1U);
    ASSERT_TRUE(RuntimeValue);
    ASSERT_TRUE((*Preparation)->StageCommit());
    EXPECT_FALSE((*RuntimeValue)->IsRevoked());

    ASSERT_TRUE(RuntimeRegistry->Revoke(*Identity));
    EXPECT_TRUE((*RuntimeValue)->IsRevoked());
    ASSERT_TRUE((*Preparation)->Commit());
    EXPECT_TRUE((*RuntimeValue)->IsRevoked());
    const auto Replacement = RuntimeRegistry->FindOrCreate(*Identity, 1U);
    ASSERT_TRUE(Replacement);
    EXPECT_TRUE((*Replacement)->IsRevoked());
}

TEST(PrismAccountDirectory, StagedGenerationRemovalKeepsOldRootAndChildAdmission)
{
    const auto Id = Prism::AccountId{321U};
    auto Publisher = std::make_shared<Prism::Runtime::GenerationPublication>();
    ASSERT_TRUE(PublishAccountGeneration(*Publisher, 1U, {Id}));
    const auto RuntimeRegistry = MakeAccountRuntimeRegistry(Publisher);
    ASSERT_TRUE(RuntimeRegistry);
    auto Store = MakePublicationBoundStore(RuntimeRegistry);
    const auto Definition = MakeDefinition(AccountInput{
        .AccountId = Id,
        .CredentialValue = Credential::Password("staged-removal-root-child"),
        .Quota = {.MaxConnections = 2U, .MaxStreams = 2U}});
    ASSERT_TRUE(InstallAccount(*Store, Definition));
    const auto View = CompileView(*Store);
    auto Root = Acquire(View, {
        .Credential = CredentialOf(Definition),
        .Rate = RateRequest{0, 1, 1}});
    ASSERT_TRUE(Root);
    auto Child = Root->TryAcquireStream();
    ASSERT_TRUE(Child);
    const auto OldBinding = Root->Binding();
    ASSERT_TRUE(OldBinding);

    const auto BeforePreparation = Publisher->Load();
    auto Removal = Publisher->Prepare(Publisher->Current(),
        MakeAccountReloadGeneration(2U), {});
    ASSERT_TRUE(Removal);
    EXPECT_EQ(Publisher->Load(), BeforePreparation);
    EXPECT_TRUE(Publisher->Load()->IsAdmitted(Id));
    EXPECT_EQ(Root->Binding(), OldBinding);
    EXPECT_EQ(Child->Binding(), OldBinding);

    auto ConcurrentRoot = Acquire(View, {
        .Credential = CredentialOf(Definition),
        .Rate = RateRequest{0, 1, 1}});
    ASSERT_TRUE(ConcurrentRoot);
    auto ConcurrentChild = ConcurrentRoot->TryAcquireStream();
    ASSERT_TRUE(ConcurrentChild);
    EXPECT_EQ(OldBinding->Runtime()->ActiveConnections(), 2U);
    EXPECT_EQ(OldBinding->Runtime()->ActiveStreams(), 2U);
    ConcurrentChild->Release();
    ConcurrentRoot->Release();
    Child->Release();
    Root->Release();
    EXPECT_EQ(OldBinding->Runtime()->ActiveConnections(), 0U);
    EXPECT_EQ(OldBinding->Runtime()->ActiveStreams(), 0U);
}

TEST(PrismAccountDirectory, PublishedRemovalRevokesNewRootAndChildAdmissionButKeepsOldLeases)
{
    const auto Id = Prism::AccountId{322U};
    auto Publisher = std::make_shared<Prism::Runtime::GenerationPublication>();
    ASSERT_TRUE(PublishAccountGeneration(*Publisher, 1U, {Id}));
    const auto RuntimeRegistry = MakeAccountRuntimeRegistry(Publisher);
    ASSERT_TRUE(RuntimeRegistry);
    auto Store = MakePublicationBoundStore(RuntimeRegistry);
    const auto Definition = MakeDefinition(AccountInput{
        .AccountId = Id,
        .CredentialValue = Credential::Password("published-removal-root-child"),
        .Quota = {.MaxConnections = 2U, .MaxStreams = 2U}});
    ASSERT_TRUE(InstallAccount(*Store, Definition));
    const auto View = CompileView(*Store);
    auto Root = Acquire(View, {
        .Credential = CredentialOf(Definition),
        .Rate = RateRequest{0, 1, 1}});
    ASSERT_TRUE(Root);
    auto Child = Root->TryAcquireStream();
    ASSERT_TRUE(Child);
    const auto OldBinding = Root->Binding();
    ASSERT_TRUE(OldBinding);

    ASSERT_TRUE(PublishAccountGeneration(*Publisher, 2U, {}));
    EXPECT_TRUE(Publisher->Load()->IsRevoked(Id));
    EXPECT_EQ(Publisher->Current()->Id(), Prism::GenerationId{2U});
    EXPECT_EQ(Root->Binding(), OldBinding);
    EXPECT_EQ(Child->Binding(), OldBinding);
    auto ExistingChildBytes = Child->ReserveBytes(1U);
    ASSERT_TRUE(ExistingChildBytes);

    auto RejectedRoot = Acquire(View, {
        .Credential = CredentialOf(Definition),
        .Rate = RateRequest{0, 1, 1}});
    ASSERT_FALSE(RejectedRoot);
    EXPECT_EQ(RejectedRoot.error().Native,
        Prism::Account::MakeFailure(Prism::Account::FailureReason::Revoked).Native);
    auto RejectedChild = Root->TryAcquireStream();
    ASSERT_FALSE(RejectedChild);
    EXPECT_EQ(RejectedChild.error().Native,
        Prism::Account::MakeFailure(Prism::Account::FailureReason::Revoked).Native);
    EXPECT_EQ(OldBinding->Runtime()->ActiveConnections(), 1U);
    EXPECT_EQ(OldBinding->Runtime()->ActiveStreams(), 1U);

    ExistingChildBytes->Release();
    Child->Release();
    Root->Release();
    EXPECT_EQ(OldBinding->Runtime()->ActiveConnections(), 0U);
    EXPECT_EQ(OldBinding->Runtime()->ActiveStreams(), 0U);
}

TEST(PrismAccountDirectory, ManualRevokeTombstoneSurvivesGenerationAndStoreReplacement)
{
    const auto Id = Prism::AccountId{323U};
    auto Publisher = std::make_shared<Prism::Runtime::GenerationPublication>();
    ASSERT_TRUE(PublishAccountGeneration(*Publisher, 1U, {Id}));
    const auto RuntimeRegistry = MakeAccountRuntimeRegistry(Publisher);
    ASSERT_TRUE(RuntimeRegistry);
    auto OldStore = MakePublicationBoundStore(RuntimeRegistry);
    const auto Definition = MakeDefinition(AccountInput{
        .AccountId = Id,
        .CredentialValue = Credential::Password("manual-revoke-reload"),
        .Quota = {.MaxConnections = 2U, .MaxStreams = 2U}});
    ASSERT_TRUE(InstallAccount(*OldStore, Definition));
    const auto OldView = CompileView(*OldStore);
    auto Root = Acquire(OldView, {
        .Credential = CredentialOf(Definition),
        .Rate = RateRequest{0, 1, 1}});
    ASSERT_TRUE(Root);
    auto Child = Root->TryAcquireStream();
    ASSERT_TRUE(Child);
    const auto OldBinding = Root->Binding();
    ASSERT_TRUE(OldBinding);

    ASSERT_TRUE(RuntimeRegistry->Revoke(Id));
    EXPECT_TRUE(Publisher->Load()->IsRevoked(Id));
    ASSERT_TRUE(PublishAccountGeneration(*Publisher, 2U, {Id}));
    EXPECT_TRUE(Publisher->Load()->IsMember(Id));
    EXPECT_TRUE(Publisher->Load()->IsRevoked(Id));

    auto ReplacementStore = MakePublicationBoundStore(RuntimeRegistry);
    ASSERT_TRUE(InstallAccount(*ReplacementStore, Definition));
    const auto ReplacementBinding = ReplacementStore->FindById(Id);
    ASSERT_TRUE(ReplacementBinding);
    EXPECT_EQ(ReplacementBinding->Runtime(), OldBinding->Runtime());
    const auto ReplacementView = CompileView(*ReplacementStore);
    auto RejectedRoot = Acquire(ReplacementView, {
        .Credential = CredentialOf(Definition),
        .Rate = RateRequest{0, 1, 1}});
    ASSERT_FALSE(RejectedRoot);
    EXPECT_EQ(RejectedRoot.error().Native,
        Prism::Account::MakeFailure(Prism::Account::FailureReason::Revoked).Native);
    auto RejectedChild = Root->TryAcquireStream();
    ASSERT_FALSE(RejectedChild);
    EXPECT_EQ(RejectedChild.error().Native,
        Prism::Account::MakeFailure(Prism::Account::FailureReason::Revoked).Native);
    EXPECT_EQ(Root->Binding(), OldBinding);
    EXPECT_EQ(Child->Binding(), OldBinding);
    EXPECT_EQ(OldBinding->Runtime()->ActiveConnections(), 1U);
    EXPECT_EQ(OldBinding->Runtime()->ActiveStreams(), 1U);

    Child->Release();
    Root->Release();
    EXPECT_EQ(OldBinding->Runtime()->ActiveConnections(), 0U);
    EXPECT_EQ(OldBinding->Runtime()->ActiveStreams(), 0U);
}
