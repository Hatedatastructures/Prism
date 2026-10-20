/** @file AccountTestSupport.hpp
 * @brief 账户模块既有场景的真实冷材料/发布/编译view夹具，不伪造运行账本。
 */
#pragma once
#include <gtest/gtest.h>
#include <Prism/Account/Account.hpp>
#include <Prism/Contract/Account/AdmissionAuthority.hpp>
#include <algorithm>
#include <array>
#include <atomic>
#include <barrier>
#include <cstdint>
#include <expected>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <type_traits>
#include <utility>
namespace
{
    using Prism::Account::AccountStore;
    using Prism::Account::AccountDefinition;
    using Prism::Account::AccountBinding;
    using Prism::Account::AccountMaterials;
    using Prism::Account::PolicyVersion;
    using Prism::Account::PolicySnapshot;
    using Prism::Account::Credential;
    using Prism::Account::CredentialKind;
    using Prism::Account::CredentialView;
    using Prism::Account::RateLimiter;
    using Prism::Account::RatePolicy;
    using Prism::Account::RateRequest;
    using Prism::Account::StrictGlobalRatePolicy;
    using Prism::Account::WorkerShardedRatePolicy;
    constexpr Prism::Account::CredentialScope TestScope{1U};

    /** @brief 只隔离账户账本用例的显式 authority；运行时集成覆盖使用真实 Publication。 */
    class TestAccountAdmissionAuthority final
        : public Prism::Contract::AccountAdmissionAuthority,
          public Prism::Contract::AccountAdmissionLeaseOwner,
          public std::enable_shared_from_this<TestAccountAdmissionAuthority>
    {
        using Snapshot = Prism::Contract::AccountAdmissionSnapshot;
        using SnapshotPin = Prism::Contract::AccountAdmissionAuthority::SnapshotPin;
        using Result = std::expected<void, Prism::Fault::Failure>;

    public:
        TestAccountAdmissionAuthority()
            : State_(std::make_shared<const Snapshot>(std::vector<Prism::AccountId>{},
                  std::vector<Prism::AccountId>{}, false))
        {
        }

        [[nodiscard]] auto Load() const noexcept -> SnapshotPin override
        {
            return State_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto BeginAdmission(const Prism::AccountId Id) noexcept
            -> std::expected<Prism::Contract::AccountAdmissionPermit,
                Prism::Fault::Failure> override
        {
            if (!Id || !TryBeginReader())
            {
                return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::WouldBlock});
            }
            const auto SnapshotValue = Load();
            if (SnapshotValue->IsRevoked(Id))
            {
                ReleaseAccountAdmission();
                return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::Forbidden});
            }
            try
            {
                return Prism::Contract::AccountAdmissionPermit{
                    std::static_pointer_cast<Prism::Contract::AccountAdmissionLeaseOwner>(
                        shared_from_this())};
            }
            catch (...)
            {
                ReleaseAccountAdmission();
                return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::ResourceUnavailable});
            }
        }

        [[nodiscard]] auto RevokeAccounts(
            const std::span<const Prism::AccountId> Ids) noexcept -> Result override
        {
            if (!TryBeginWriter())
            {
                return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::WouldBlock});
            }
            auto ResultValue = RevokeWhileExclusive(Ids);
            EndWriter();
            return ResultValue;
        }

        [[nodiscard]] auto CloseAllAccounts() noexcept -> Result override
        {
            return {};
        }

        auto ReleaseAccountAdmission() noexcept -> void override
        {
            Gate_.fetch_sub(1U, std::memory_order_release);
        }

    private:
        [[nodiscard]] auto TryBeginReader() noexcept -> bool
        {
            auto Current = Gate_.load(std::memory_order_acquire);
            while ((Current & WriterBit) == 0U && Current != WriterBit - 1U)
            {
                if (Gate_.compare_exchange_weak(Current, Current + 1U,
                        std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    return true;
                }
            }
            return false;
        }

        [[nodiscard]] auto TryBeginWriter() noexcept -> bool
        {
            std::uint64_t Expected = 0U;
            return Gate_.compare_exchange_strong(Expected, WriterBit,
                std::memory_order_acq_rel, std::memory_order_acquire);
        }

        auto EndWriter() noexcept -> void
        {
            Gate_.store(0U, std::memory_order_release);
        }

        [[nodiscard]] auto RevokeWhileExclusive(
            const std::span<const Prism::AccountId> Ids) noexcept -> Result
        {
            try
            {
                const auto Current = State_.load(std::memory_order_acquire);
                auto Revoked = Current->Revoked;
                for (const auto Id : Ids)
                {
                    if (!Id)
                    {
                        return std::unexpected(Prism::Fault::Failure{
                            Prism::Fault::Code::InvalidArgument});
                    }
                    Revoked.push_back(Id);
                }
                std::sort(Revoked.begin(), Revoked.end());
                Revoked.erase(std::unique(Revoked.begin(), Revoked.end()), Revoked.end());
                if (Revoked.size() > Snapshot::MaxRevocations)
                {
                    return std::unexpected(Prism::Fault::Failure{
                        Prism::Fault::Code::ResourceUnavailable});
                }
                State_.store(std::make_shared<const Snapshot>(Current->Members,
                    std::move(Revoked), false), std::memory_order_release);
                return {};
            }
            catch (...)
            {
                return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::ResourceUnavailable});
            }
        }

        inline static constexpr std::uint64_t WriterBit{std::uint64_t{1U} << 63U};
        std::atomic<std::uint64_t> Gate_{0U};
        std::atomic<std::shared_ptr<const Snapshot>> State_;
    };

    /** @brief 每个GoogleTest case拥有独立fake authority，避免跨用例共享撤销墓碑。 */
    inline auto TestAuthorityForCase()
        -> std::shared_ptr<TestAccountAdmissionAuthority>
    {
        static const testing::TestInfo* Previous{};
        static std::shared_ptr<TestAccountAdmissionAuthority> Authority;
        const auto* Current = testing::UnitTest::GetInstance()->current_test_info();
        if (!Authority || Current != Previous)
        {
            Authority = std::make_shared<TestAccountAdmissionAuthority>();
            Previous = Current;
        }
        return Authority;
    }

    auto AttachTestAuthority(AccountStore& Store) -> void
    {
        const auto Attached = Store.RuntimeRegistry()->AttachAdmissionAuthority(
            TestAuthorityForCase());
        if (!Attached)
        {
            throw std::runtime_error("test account authority attachment failed");
        }
    }
    /** @brief 原单账户场景的冷输入；不创建runtime或第二份成功事实。 */
    struct AccountInput final
    {
        Prism::AccountId AccountId;
        Credential CredentialValue;
        Prism::Account::QuotaPolicy Quota{};
        RatePolicy Rate{};
    };
    auto MakeDefinition(AccountInput Input) -> AccountDefinition
    {
        std::vector<Prism::Account::CredentialMaterial> Credentials;
        Credentials.push_back({TestScope, {}, std::move(Input.CredentialValue)});
        auto Materials = std::make_shared<const AccountMaterials>(AccountMaterials::CreateRequest{
            Input.AccountId, "test-account-" + std::to_string(Input.AccountId.Value()),
            std::move(Credentials)});
        return {std::move(Materials), {Input.Quota, Input.Rate}};
    }
    [[nodiscard]] auto IsBusy(const Prism::Fault::Failure Failure) noexcept -> bool
    {
        return Failure.Code == Prism::Fault::Code::ResourceUnavailable &&
            Failure.Native == Prism::Account::MakeFailure(Prism::Account::FailureReason::Busy).Native;
    }
    /** @brief 只重试新合同的瞬时竞争，不重试quota/撤销/冲突，不改变原输入数量。 */
    auto Publish(AccountStore& Store, const AccountDefinition& Definition) -> std::expected<void, Prism::Fault::Failure>
    {
        AttachTestAuthority(Store);
        for (;;)
        {
            auto Prepared = Store.PrepareUpsert(Definition);
            if (!Prepared)
            {
                if (IsBusy(Prepared.error())) { std::this_thread::yield(); continue; }
                return std::unexpected(Prepared.error());
            }
            for (;;)
            {
                const auto Result = Store.Commit(*Prepared);
                if (Result || !IsBusy(Result.error())) { return Result; }
                std::this_thread::yield();
            }
        }
    }
    auto CompileView(AccountStore& Store) -> Prism::Account::CredentialIndexView
    {
        for (;;)
        {
            auto Result = Store.CompileScope(TestScope);
            if (Result) { return std::move(*Result); }
            if (!IsBusy(Result.error())) { throw std::runtime_error("fixture scope compile failed"); }
            std::this_thread::yield();
        }
    }
    auto CredentialOf(const AccountDefinition& Definition) -> CredentialView
    { return Definition.Materials->Credentials().front().Credential.View(); }
    auto CredentialOf(const std::shared_ptr<const AccountBinding>& Binding) -> CredentialView
    { return Binding->Materials()->Credentials().front().Credential.View(); }
    auto FindCredentialAccount(AccountStore& Store, const CredentialView Credential) -> std::shared_ptr<const AccountBinding>
    {
        const auto View = CompileView(Store);
        std::shared_ptr<const AccountBinding> Found;
        const auto Read = View.ForEachCredential(Credential.Kind(), [&Found, Credential](const auto& Binding, const auto& Material)
            { if (Material.Credential.Matches(Credential)) { Found = Binding; } });
        EXPECT_TRUE(Read.has_value());
        return Found;
    }
    auto Acquire(const Prism::Account::CredentialIndexView& View, Prism::Account::AcquireRequest Request)
        -> Prism::AuthenticationResult
    {
        for (;;)
        {
            auto Result = View.TryAcquire(Request);
            if (Result || !IsBusy(Result.error())) { return Result; }
            std::this_thread::yield();
        }
    }
    auto ConsumeRate(const RateLimiter& Rate, const RateRequest Request) -> bool
    {
        for (;;)
        {
            const auto Result = Rate.TryConsume(Request);
            if (Result) { return true; }
            if (!IsBusy(Result.error())) { return false; }
            std::this_thread::yield();
        }
    }
    auto VerifyInitialPolicyGeneration(const PolicyVersion Version, const Prism::AccountId Id) -> void
    {
        auto Directory = std::make_shared<AccountStore>(Prism::Account::StoreOptions{.InitialPolicyVersion = Version});
        auto Original = MakeDefinition(AccountInput{.AccountId = Id,
            .CredentialValue = Credential::Password("generation-floor-" + std::to_string(Version.Value())),
            .Quota = {.MaxConnections = 1}});
        ASSERT_TRUE(Publish(*Directory, Original));
        const auto Published = Directory->FindById(Id);
        ASSERT_TRUE(Published);
        EXPECT_EQ(Published->Policy()->Version(), Version);
        ASSERT_TRUE(Published->Runtime());
        EXPECT_EQ(Published->Runtime()->AccountId(), Id);
        ASSERT_TRUE(Published->Policy()->Rate());
        Prism::DirectoryAuthenticator Authenticator(CompileView(*Directory));
        auto Authentication = Authenticator.Authenticate({.Credential = CredentialOf(Published)});
        ASSERT_TRUE(Authentication);
        EXPECT_EQ(Published->Runtime()->ActiveConnections(), 1U);
        const auto Replacement = MakeDefinition(AccountInput{.AccountId = Id,
            .CredentialValue = Credential::Password("generation-floor-replacement-" + std::to_string(Version.Value())),
            .Quota = {.MaxConnections = 1}});
        ASSERT_TRUE(Publish(*Directory, Replacement));
        const auto Next = Directory->FindById(Id);
        ASSERT_TRUE(Next);
        EXPECT_EQ(Next->Policy()->Version(), PolicyVersion{Version.Value() + 1U});
        EXPECT_EQ(Next->Runtime(), Published->Runtime());
        auto Busy = Authenticator.Authenticate({.Credential = CredentialOf(Next)});
        EXPECT_FALSE(Busy);
        ASSERT_FALSE(Busy);
        EXPECT_EQ(Busy.error().Native, Prism::Account::MakeFailure(Prism::Account::FailureReason::ConnectionQuota).Native);
        EXPECT_EQ(Next->Runtime()->ActiveConnections(), 1U);
        Authentication->Release();
        EXPECT_EQ(Next->Runtime()->ActiveConnections(), 0U);
        auto Accepted = Authenticator.Authenticate({.Credential = CredentialOf(Next)});
        ASSERT_TRUE(Accepted);
        EXPECT_EQ(Next->Runtime()->ActiveConnections(), 1U);
        Accepted->Release();
        EXPECT_EQ(Next->Runtime()->ActiveConnections(), 0U);
    }
    auto InspectMatch(const Prism::Authenticator& Auth, const CredentialView Credential) -> bool
    {
        const auto Result = Auth.InspectCredential(Credential);
        EXPECT_TRUE(Result.has_value());
        if (!Result) { return false; }
        return *Result;
    }
    /** @brief 核对既有无效材料场景的正式失败值，保留原输入与断言。 */
    auto VerifyInvalidCredential(const Prism::Authenticator& Auth, const CredentialView CredentialValue) -> void
    {
        const auto Result = Auth.Authenticate(Prism::AuthenticationRequest{
            .AccountId = {}, .Identity = {}, .Credential = CredentialValue, .Rate = {}});
        EXPECT_FALSE(Result.has_value());
        ASSERT_FALSE(Result);
        EXPECT_EQ(Result.error().Native, Prism::Account::MakeFailure(Prism::Account::FailureReason::InvalidCredential).Native);
    }
}
