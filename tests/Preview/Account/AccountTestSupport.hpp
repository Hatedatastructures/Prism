/** @file AccountTestSupport.hpp
 * @brief 账户模块既有场景的真实冷材料/发布/编译view夹具，不伪造运行账本。
 */
#pragma once
#include <gtest/gtest.h>
#include <Preview/Account/Account.hpp>
#include <Preview/Contract/Account/AdmissionAuthority.hpp>
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
    using Preview::Account::AccountStore;
    using Preview::Account::AccountDefinition;
    using Preview::Account::AccountBinding;
    using Preview::Account::AccountMaterials;
    using Preview::Account::PolicyVersion;
    using Preview::Account::PolicySnapshot;
    using Preview::Account::Credential;
    using Preview::Account::CredentialKind;
    using Preview::Account::CredentialView;
    using Preview::Account::RateLimiter;
    using Preview::Account::RatePolicy;
    using Preview::Account::RateRequest;
    using Preview::Account::StrictGlobalRatePolicy;
    using Preview::Account::WorkerShardedRatePolicy;
    constexpr Preview::Account::CredentialScope TestScope{1U};

    /** @brief 只隔离账户账本用例的显式 authority；运行时集成覆盖使用真实 Publication。 */
    class TestAccountAdmissionAuthority final
        : public Preview::Contract::AccountAdmissionAuthority,
          public Preview::Contract::AccountAdmissionLeaseOwner,
          public std::enable_shared_from_this<TestAccountAdmissionAuthority>
    {
        using Snapshot = Preview::Contract::AccountAdmissionSnapshot;
        using SnapshotPin = Preview::Contract::AccountAdmissionAuthority::SnapshotPin;
        using Result = std::expected<void, Preview::Fault::Failure>;

    public:
        TestAccountAdmissionAuthority()
            : State_(std::make_shared<const Snapshot>(std::vector<Preview::AccountId>{},
                  std::vector<Preview::AccountId>{}, false))
        {
        }

        [[nodiscard]] auto Load() const noexcept -> SnapshotPin override
        {
            return State_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto BeginAdmission(const Preview::AccountId Id) noexcept
            -> std::expected<Preview::Contract::AccountAdmissionPermit,
                Preview::Fault::Failure> override
        {
            if (!Id || !TryBeginReader())
            {
                return std::unexpected(Preview::Fault::Failure{
                    Preview::Fault::Code::WouldBlock});
            }
            const auto SnapshotValue = Load();
            if (SnapshotValue->IsRevoked(Id))
            {
                ReleaseAccountAdmission();
                return std::unexpected(Preview::Fault::Failure{
                    Preview::Fault::Code::Forbidden});
            }
            try
            {
                return Preview::Contract::AccountAdmissionPermit{
                    std::static_pointer_cast<Preview::Contract::AccountAdmissionLeaseOwner>(
                        shared_from_this())};
            }
            catch (...)
            {
                ReleaseAccountAdmission();
                return std::unexpected(Preview::Fault::Failure{
                    Preview::Fault::Code::ResourceUnavailable});
            }
        }

        [[nodiscard]] auto RevokeAccounts(
            const std::span<const Preview::AccountId> Ids) noexcept -> Result override
        {
            if (!TryBeginWriter())
            {
                return std::unexpected(Preview::Fault::Failure{
                    Preview::Fault::Code::WouldBlock});
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
            const std::span<const Preview::AccountId> Ids) noexcept -> Result
        {
            try
            {
                const auto Current = State_.load(std::memory_order_acquire);
                auto Revoked = Current->Revoked;
                for (const auto Id : Ids)
                {
                    if (!Id)
                    {
                        return std::unexpected(Preview::Fault::Failure{
                            Preview::Fault::Code::InvalidArgument});
                    }
                    Revoked.push_back(Id);
                }
                std::sort(Revoked.begin(), Revoked.end());
                Revoked.erase(std::unique(Revoked.begin(), Revoked.end()), Revoked.end());
                if (Revoked.size() > Snapshot::MaxRevocations)
                {
                    return std::unexpected(Preview::Fault::Failure{
                        Preview::Fault::Code::ResourceUnavailable});
                }
                State_.store(std::make_shared<const Snapshot>(Current->Members,
                    std::move(Revoked), false), std::memory_order_release);
                return {};
            }
            catch (...)
            {
                return std::unexpected(Preview::Fault::Failure{
                    Preview::Fault::Code::ResourceUnavailable});
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
        Preview::AccountId AccountId;
        Credential CredentialValue;
        Preview::Account::QuotaPolicy Quota{};
        RatePolicy Rate{};
    };
    auto MakeDefinition(AccountInput Input) -> AccountDefinition
    {
        std::vector<Preview::Account::CredentialMaterial> Credentials;
        Credentials.push_back({TestScope, {}, std::move(Input.CredentialValue)});
        auto Materials = std::make_shared<const AccountMaterials>(AccountMaterials::CreateRequest{
            Input.AccountId, {}, std::move(Credentials)});
        return {std::move(Materials), {Input.Quota, Input.Rate}};
    }
    [[nodiscard]] auto IsBusy(const Preview::Fault::Failure Failure) noexcept -> bool
    {
        return Failure.Code == Preview::Fault::Code::ResourceUnavailable &&
            Failure.Native == Preview::Account::MakeFailure(Preview::Account::FailureReason::Busy).Native;
    }
    /** @brief 只重试新合同的瞬时竞争，不重试quota/撤销/冲突，不改变原输入数量。 */
    auto Publish(AccountStore& Store, const AccountDefinition& Definition) -> std::expected<void, Preview::Fault::Failure>
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
    auto CompileView(AccountStore& Store) -> Preview::Account::CredentialIndexView
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
    auto Acquire(const Preview::Account::CredentialIndexView& View, Preview::Account::AcquireRequest Request)
        -> Preview::AuthenticationResult
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
    auto VerifyInitialPolicyGeneration(const PolicyVersion Version, const Preview::AccountId Id) -> void
    {
        auto Directory = std::make_shared<AccountStore>(Preview::Account::StoreOptions{.InitialPolicyVersion = Version});
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
        Preview::DirectoryAuthenticator Authenticator(CompileView(*Directory));
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
        EXPECT_EQ(Busy.error().Native, Preview::Account::MakeFailure(Preview::Account::FailureReason::ConnectionQuota).Native);
        EXPECT_EQ(Next->Runtime()->ActiveConnections(), 1U);
        Authentication->Release();
        EXPECT_EQ(Next->Runtime()->ActiveConnections(), 0U);
        auto Accepted = Authenticator.Authenticate({.Credential = CredentialOf(Next)});
        ASSERT_TRUE(Accepted);
        EXPECT_EQ(Next->Runtime()->ActiveConnections(), 1U);
        Accepted->Release();
        EXPECT_EQ(Next->Runtime()->ActiveConnections(), 0U);
    }
    auto InspectMatch(const Preview::Authenticator& Auth, const CredentialView Credential) -> bool
    {
        const auto Result = Auth.InspectCredential(Credential);
        EXPECT_TRUE(Result.has_value());
        if (!Result) { return false; }
        return *Result;
    }
    /** @brief 核对既有无效材料场景的正式失败值，保留原输入与断言。 */
    auto VerifyInvalidCredential(const Preview::Authenticator& Auth, const CredentialView CredentialValue) -> void
    {
        const auto Result = Auth.Authenticate(Preview::AuthenticationRequest{
            .AccountId = {}, .Identity = {}, .Credential = CredentialValue, .Rate = {}});
        EXPECT_FALSE(Result.has_value());
        ASSERT_FALSE(Result);
        EXPECT_EQ(Result.error().Native, Preview::Account::MakeFailure(Preview::Account::FailureReason::InvalidCredential).Native);
    }
}
