/** @file Store.hpp
 * @brief process 唯一账户store，冷准备/单次提交完整Binding与全部credential索引。
 */
#pragma once
#include <Prism/Account/Failure.hpp>
#include <Prism/Account/Index.hpp>
#include <Prism/Account/RuntimeRegistry.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <map>
#include <memory>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace Prism::Account
{
    struct StoreOptions final
    {
        std::size_t MaxAccounts{4096U};
        std::size_t RootLeaseSlots{4096U};
        std::size_t MaximumCredentialBytes{64U * 1024U};
        std::uint32_t WorkerCount{
            WorkerShardedRatePolicy::MaxWorkerCount}; ///< Application冷装配传实际worker数。
        Prism::Account::PolicyVersion InitialPolicyVersion{1U};
        std::shared_ptr<AccountRuntimeRegistry> RuntimeRegistry;
        bool RevokeRuntimesOnSeal{true};
    };
    /** @brief 一个账户的完整冷配置，材料不包含第二账本。 */
    struct AccountDefinition final
    {
        std::shared_ptr<const AccountMaterials> Materials;
        PolicySettings Policy;
    };
    class AccountStore;
    /** @brief prepared token pins Base/Next直到commit或放弃，未commit不发布认证材料。 */
    class PreparedAccountUpdate final
    {
    public:
        PreparedAccountUpdate() = default;
        PreparedAccountUpdate(const PreparedAccountUpdate&) = delete;
        auto operator=(const PreparedAccountUpdate&) -> PreparedAccountUpdate& = delete;
        PreparedAccountUpdate(PreparedAccountUpdate&&) noexcept = default;
        auto operator=(PreparedAccountUpdate&&) noexcept -> PreparedAccountUpdate& = default;

    private:
        friend class AccountStore;
        std::shared_ptr<Detail::AccountStoreState> Owner_;
        std::shared_ptr<const Detail::AccountSnapshot> Base_;
        std::shared_ptr<const Detail::AccountSnapshot> Next_;
    };
    /**
     * @brief 同AccountId只有一个运行账本，全部scope共享该store而非建协议目录。
     * @details Prepare/CompileScope/Commit是冷、非协程控制操作，允许材料/index分配。
     *          Commit单次发布同一个Snapshot：Binding同时拥有材料、policy和runtime。
     *          Revoke只封止账户准入，不关闭协议I/O；CloseSessions仍归管理命令/真实owner。
     */
    class AccountStore final
    {
        using Failure = Fault::Failure;
        using Code = Fault::Code;
        class Mutation final
        {
        public:
            explicit Mutation(std::atomic_flag& Gate) noexcept : Gate_(Gate)
            {
                Acquired_ = !Gate_.test_and_set(std::memory_order_acquire);
            }
            ~Mutation()
            {
                if (Acquired_)
                {
                    Gate_.clear(std::memory_order_release);
                    Gate_.notify_all();
                }
            }
            [[nodiscard]] auto Acquired() const noexcept -> bool
            {
                return Acquired_;
            }

        private:
            std::atomic_flag& Gate_;
            bool Acquired_{false};
        };

    public:
        explicit AccountStore(StoreOptions Options = {})
            : Options_(Options), RuntimeRegistry_(Options.RuntimeRegistry)
        {
            if (Options.MaxAccounts == 0U || Options.MaxAccounts > 4096U || Options.RootLeaseSlots == 0U ||
                Options.RootLeaseSlots > 65536U || Options.MaximumCredentialBytes == 0U ||
                Options.MaximumCredentialBytes > 1024U * 1024U || Options.WorkerCount == 0U ||
                Options.WorkerCount > WorkerShardedRatePolicy::MaxWorkerCount ||
                !Options.InitialPolicyVersion)
            {
                throw std::invalid_argument("invalid account store options");
            }
            if (!RuntimeRegistry_)
            {
                RuntimeRegistry_ = std::make_shared<AccountRuntimeRegistry>(Options.InitialPolicyVersion);
            }
            State_ = std::make_shared<Detail::AccountStoreState>(
                std::make_shared<Detail::LeasePool>(Options.RootLeaseSlots), Options.MaximumCredentialBytes);
        }
        AccountStore(const AccountStore&) = delete;
        auto operator=(const AccountStore&) -> AccountStore& = delete;
        ~AccountStore()
        {
            Seal();
        }
        /** @brief 控制owner与Commit串行封止新认证，不替代I/O关闭；view保活state而不能绕过封止。 */
        auto Seal() noexcept -> void
        {
            State_->Accepting.store(false, std::memory_order_release);
            if (Options_.RevokeRuntimesOnSeal)
            {
                const auto Revoked = RuntimeRegistry_->RevokeAll();
                static_cast<void>(Revoked);
            }
        }
        [[nodiscard]] auto RuntimeRegistry() const noexcept -> const std::shared_ptr<AccountRuntimeRegistry>&
        {
            return RuntimeRegistry_;
        }
        /** @brief 冷注册数值scope并冻结ordinal，热不再查scope名称。 */
        [[nodiscard]] auto CompileScope(const CredentialScope Scope)
            -> std::expected<CredentialIndexView, Failure>
        {
            Mutation Guard(Mutation_);
            if (!Guard.Acquired())
            {
                return std::unexpected(MakeFailure(FailureReason::Busy));
            }
            if (!State_->Accepting.load(std::memory_order_acquire))
            {
                return std::unexpected(Failure{Code::Canceled});
            }
            const auto Ordinal = EnsureScope(Scope);
            if (!Ordinal)
            {
                return std::unexpected(Ordinal.error());
            }
            return CredentialIndexView(State_, *Ordinal);
        }
        /** @brief 准备单账户替换，完整材料集替换该AccountId的全部scope。 */
        [[nodiscard]] auto PrepareUpsert(AccountDefinition Definition)
            -> std::expected<PreparedAccountUpdate, Failure>
        {
            Mutation Guard(Mutation_);
            if (!Guard.Acquired())
            {
                return std::unexpected(MakeFailure(FailureReason::Busy));
            }
            if (!State_->Accepting.load(std::memory_order_acquire))
            {
                return std::unexpected(Failure{Code::Canceled});
            }
            const auto Base = State_->Snapshot.load(std::memory_order_acquire);
            auto Next = std::make_shared<Detail::AccountSnapshot>(*Base);
            const auto Built = BuildBinding(std::move(Definition), Base);
            if (!Built)
            {
                return std::unexpected(Built.error());
            }
            bool Replaced = false;
            for (auto& Binding : Next->Bindings)
            {
                if (Binding->AccountId() == (*Built)->AccountId())
                {
                    Binding = *Built;
                    Replaced = true;
                    break;
                }
            }
            if (!Replaced)
            {
                if (Next->Bindings.size() == Options_.MaxAccounts)
                {
                    return std::unexpected(MakeFailure(FailureReason::Accounts));
                }
                Next->Bindings.push_back(*Built);
            }
            return FinishPrepared(Base, std::move(Next));
        }
        /** @brief Reload完整账户集合准备，失败不部分发布；旧lease继续pin旧Binding。 */
        [[nodiscard]] auto PrepareReplacement(const std::span<const AccountDefinition> Definitions)
            -> std::expected<PreparedAccountUpdate, Failure>
        {
            Mutation Guard(Mutation_);
            if (!Guard.Acquired())
            {
                return std::unexpected(MakeFailure(FailureReason::Busy));
            }
            if (!State_->Accepting.load(std::memory_order_acquire))
            {
                return std::unexpected(Failure{Code::Canceled});
            }
            if (Definitions.size() > Options_.MaxAccounts)
            {
                return std::unexpected(MakeFailure(FailureReason::Accounts));
            }
            const auto Base = State_->Snapshot.load(std::memory_order_acquire);
            auto Next = std::make_shared<Detail::AccountSnapshot>();
            Next->Bindings.reserve(Definitions.size());
            for (const auto& Definition : Definitions)
            {
                auto Built = BuildBinding(Definition, Base);
                if (!Built)
                {
                    return std::unexpected(Built.error());
                }
                if (std::any_of(Next->Bindings.begin(), Next->Bindings.end(), [&Built](const auto& Binding)
                        { return Binding->AccountId() == (*Built)->AccountId(); }))
                {
                    return std::unexpected(Failure{Code::InvalidArgument});
                }
                Next->Bindings.push_back(std::move(*Built));
            }
            return FinishPrepared(Base, std::move(Next));
        }
        [[nodiscard]] auto PrepareRemove(const Prism::AccountId Id)
            -> std::expected<PreparedAccountUpdate, Failure>
        {
            Mutation Guard(Mutation_);
            if (!Guard.Acquired())
            {
                return std::unexpected(MakeFailure(FailureReason::Busy));
            }
            if (!State_->Accepting.load(std::memory_order_acquire))
            {
                return std::unexpected(Failure{Code::Canceled});
            }
            const auto Base = State_->Snapshot.load(std::memory_order_acquire);
            auto Next = std::make_shared<Detail::AccountSnapshot>(*Base);
            const auto It = std::find_if(Next->Bindings.begin(), Next->Bindings.end(),
                [Id](const auto& Binding) { return Binding->AccountId() == Id; });
            if (!Id || It == Next->Bindings.end())
            {
                return std::unexpected(Failure{Code::AuthFailed});
            }
            Next->Bindings.erase(It);
            return FinishPrepared(Base, std::move(Next));
        }
        /** @brief 只提交本store冷准备的认证索引；generation成员与撤销在Publication CAS中提交。 */
        [[nodiscard]] auto Commit(PreparedAccountUpdate& Update) -> std::expected<void, Failure>
        {
            Mutation Guard(Mutation_);
            if (!Guard.Acquired())
            {
                return std::unexpected(MakeFailure(FailureReason::Busy));
            }
            if (!State_->Accepting.load(std::memory_order_acquire))
            {
                return std::unexpected(Failure{Code::Canceled});
            }
            if (Update.Owner_ != State_ || !Update.Next_ ||
                State_->Snapshot.load(std::memory_order_acquire) != Update.Base_)
            {
                return std::unexpected(Failure{Code::Blocked});
            }
            State_->Snapshot.store(std::move(Update.Next_), std::memory_order_release);
            Update.Owner_.reset();
            Update.Base_.reset();
            return {};
        }
        [[nodiscard]] auto FindById(const Prism::AccountId Id) const noexcept
            -> std::shared_ptr<const AccountBinding>
        {
            const auto Snapshot = State_->Snapshot.load(std::memory_order_acquire);
            const auto Found = std::lower_bound(Snapshot->Bindings.begin(), Snapshot->Bindings.end(), Id,
                [](const auto& Binding, const auto Key) { return Binding->AccountId() < Key; });
            if (Found != Snapshot->Bindings.end() && (*Found)->AccountId() == Id)
            {
                return *Found;
            }
            return {};
        }
        [[nodiscard]] auto Revoke(const Prism::AccountId Id) const noexcept -> std::expected<void, Failure>
        {
            const auto Binding = FindById(Id);
            if (!Binding)
            {
                return std::unexpected(Failure{Code::AuthFailed});
            }
            return RuntimeRegistry_->Revoke(Id);
        }
        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return State_->Snapshot.load(std::memory_order_acquire)->Bindings.size();
        }
        /** @brief 返回此冻结 store 当前完整成员；只用于 generation publication 的冷 prepare。 */
        [[nodiscard]] auto AccountIds() const -> std::vector<Prism::AccountId>
        {
            const auto Snapshot = State_->Snapshot.load(std::memory_order_acquire);
            std::vector<Prism::AccountId> Ids;
            Ids.reserve(Snapshot->Bindings.size());
            for (const auto& Binding : Snapshot->Bindings)
            {
                Ids.push_back(Binding->AccountId());
            }
            return Ids;
        }
        template <typename Function>
        auto ForEach(Function&& Visitor) const -> void
        {
            const auto Snapshot = State_->Snapshot.load(std::memory_order_acquire);
            for (const auto& Binding : Snapshot->Bindings)
            {
                Visitor(Binding);
            }
        }

    private:
        [[nodiscard]] auto EnsureScope(const CredentialScope Scope) -> std::expected<std::size_t, Failure>
        {
            if (!Scope)
            {
                return std::unexpected(Failure{Code::InvalidArgument});
            }
            for (std::size_t Index = 0U; Index < Scopes_.size(); ++Index)
            {
                if (Scopes_[Index] == Scope)
                {
                    return Index;
                }
            }
            if (Scopes_.size() == 64U)
            {
                return std::unexpected(MakeFailure(FailureReason::Scopes));
            }
            Scopes_.push_back(Scope);
            return Scopes_.size() - 1U;
        }
        [[nodiscard]] auto RuntimeFor(const Prism::AccountId Id)
            -> std::expected<std::shared_ptr<AccountRuntime>, Failure>
        {
            return RuntimeRegistry_->FindOrCreate(Id, Options_.WorkerCount);
        }
        [[nodiscard]] auto BuildBinding(AccountDefinition Definition,
            const std::shared_ptr<const Detail::AccountSnapshot>& Base)
            -> std::expected<std::shared_ptr<const AccountBinding>, Failure>
        {
            if (!Definition.Materials || !Definition.Materials->AccountId())
            {
                return std::unexpected(Failure{Code::InvalidArgument});
            }
            for (const auto& Entry : Definition.Materials->Credentials())
            {
                if (Entry.Credential.View().Size() > Options_.MaximumCredentialBytes ||
                    Entry.Identity.size() > Options_.MaximumCredentialBytes)
                {
                    return std::unexpected(Failure{Code::OversizedMsg});
                }
                const auto Scope = EnsureScope(Entry.Scope);
                if (!Scope)
                {
                    return std::unexpected(Scope.error());
                }
            }
            auto Runtime = RuntimeFor(Definition.Materials->AccountId());
            if (!Runtime)
            {
                return std::unexpected(Runtime.error());
            }
            if (!(*Runtime)->BindStableKey(Definition.Materials->DisplayIdentity()))
                return std::unexpected(Failure{Code::InvalidArgument});
            RuntimeRegistry_->InstallTransfer(*Runtime);
            std::shared_ptr<const RateLimiter> Previous;
            for (const auto& Binding : Base->Bindings)
            {
                if (Binding->AccountId() == Definition.Materials->AccountId())
                {
                    Previous = Binding->Policy()->Rate();
                    break;
                }
            }
            auto Rate = std::make_shared<const RateLimiter>(RateLimiter::CreateRequest{Definition.Policy.Rate,
                (*Runtime)->RateLedger(), std::move(Previous)});
            if (Rate->Failure().Failed())
            {
                return std::unexpected(Rate->Failure());
            }
            const auto Version = RuntimeRegistry_->AllocatePolicyVersion();
            if (!Version)
            {
                return std::unexpected(Version.error());
            }
            auto Policy = std::make_shared<const PolicySnapshot>(
                PolicySnapshot::CreateRequest{*Version, std::move(Definition.Policy), std::move(Rate)});
            return std::shared_ptr<const AccountBinding>(new AccountBinding(AccountBinding::CreateRequest{
                std::move(Definition.Materials), std::move(Policy), std::move(*Runtime)}));
        }
        [[nodiscard]] auto FinishPrepared(const std::shared_ptr<const Detail::AccountSnapshot>& Base,
            std::shared_ptr<Detail::AccountSnapshot> Next) -> std::expected<PreparedAccountUpdate, Failure>
        {
            std::sort(Next->Bindings.begin(), Next->Bindings.end(),
                [](const auto& Left, const auto& Right) { return Left->AccountId() < Right->AccountId(); });
            std::array<std::shared_ptr<Detail::CredentialIndex>, 64U> Indexes;
            for (std::size_t Scope = 0U; Scope < Scopes_.size(); ++Scope)
            {
                Indexes[Scope] = std::make_shared<Detail::CredentialIndex>();
            }
            for (const auto& Binding : Next->Bindings)
            {
                const auto& Materials = Binding->Materials()->Credentials();
                for (std::size_t Index = 0U; Index < Materials.size(); ++Index)
                {
                    const auto Scope = EnsureScope(Materials[Index].Scope);
                    if (!Scope)
                    {
                        return std::unexpected(Scope.error());
                    }
                    const auto Digest = Detail::DigestCredential(Materials[Index].Credential.View());
                    if (!Digest)
                    {
                        return std::unexpected(Digest.error());
                    }
                    auto& Entries = Indexes[*Scope]->Entries;
                    for (const auto& Existing : Entries)
                    {
                        const auto& Other =
                            Existing.Binding->Materials()->Credentials()[Existing.MaterialIndex];
                        if (Existing.Kind == Materials[Index].Credential.Kind() &&
                            Existing.Digest == *Digest &&
                            (Other.Identity.empty() || Materials[Index].Identity.empty() ||
                                Other.Identity == Materials[Index].Identity) &&
                            Other.Credential.Matches(Materials[Index].Credential.View()))
                        {
                            return std::unexpected(Failure{Code::InvalidArgument});
                        }
                    }
                    Entries.push_back({*Digest, Materials[Index].Credential.Kind(), Binding, Index});
                }
            }
            for (std::size_t Scope = 0U; Scope < Scopes_.size(); ++Scope)
            {
                auto& Entries = Indexes[Scope]->Entries;
                std::sort(Entries.begin(), Entries.end(), Detail::CredentialKeyLess);
                Next->Indexes[Scope] = std::move(Indexes[Scope]);
            }
            PreparedAccountUpdate Result;
            Result.Owner_ = State_;
            Result.Base_ = Base;
            Result.Next_ = std::move(Next);
            return Result;
        }
        const StoreOptions Options_;
        std::shared_ptr<AccountRuntimeRegistry> RuntimeRegistry_;
        std::shared_ptr<Detail::AccountStoreState> State_;
        std::atomic_flag Mutation_ = ATOMIC_FLAG_INIT;
        std::vector<CredentialScope> Scopes_;
    };
} // namespace Prism::Account
