/** @file Store.cpp
 * @brief 账户快照与预编译凭据索引的拥有者实现。
 */
#include <Prism/Account/Store.hpp>
#include <Prism/Account/Detail/LeasePool.hpp>
#include <Prism/Account/RuntimeRegistry.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace Prism::Account
{
            AccountStore::Mutation::Mutation(std::atomic_flag& Gate) noexcept : Gate_(Gate)
            {
                Acquired_ = !Gate_.test_and_set(std::memory_order_acquire);
            }

            AccountStore::Mutation::~Mutation()
            {
                if (Acquired_)
                {
                    Gate_.clear(std::memory_order_release);
                    Gate_.notify_all();
                }
            }

            auto AccountStore::Mutation::Acquired() const noexcept -> bool
            {
                return Acquired_;
            }

        AccountStore::AccountStore(StoreOptions Options)
            : Options_(std::move(Options)), RuntimeRegistry_(Options_.RuntimeRegistry)
        {
            if (Options_.MaxAccounts == 0U || Options_.MaxAccounts > 4096U ||
                Options_.RootLeaseSlots == 0U || Options_.RootLeaseSlots > 65536U ||
                Options_.MaximumCredentialBytes == 0U ||
                Options_.MaximumCredentialBytes > 1024U * 1024U ||
                Options_.WorkerCount == 0U ||
                Options_.WorkerCount > WorkerShardedRatePolicy::MaxWorkerCount ||
                !Options_.InitialPolicyVersion)
            {
                throw std::invalid_argument("invalid account store options");
            }
            if (!RuntimeRegistry_)
            {
                RuntimeRegistry_ =
                    std::make_shared<AccountRuntimeRegistry>(Options_.InitialPolicyVersion);
            }
            State_ = std::make_shared<Detail::AccountStoreState>(
                std::make_shared<Detail::LeasePool>(Options_.RootLeaseSlots),
                Options_.MaximumCredentialBytes);
        }

        AccountStore::~AccountStore()
        {
            Seal();
        }

        auto AccountStore::Seal() noexcept -> void
        {
            State_->Accepting.store(false, std::memory_order_release);
            if (Options_.RevokeRuntimesOnSeal)
            {
                const auto Revoked = RuntimeRegistry_->RevokeAll();
                static_cast<void>(Revoked);
            }
        }

        auto AccountStore::RuntimeRegistry() const noexcept -> const std::shared_ptr<AccountRuntimeRegistry>&
        {
            return RuntimeRegistry_;
        }

        auto AccountStore::CompileScope(const CredentialScope Scope)
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

        auto AccountStore::PrepareUpsert(AccountDefinition Definition)
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

        auto AccountStore::PrepareReplacement(const std::span<const AccountDefinition> Definitions)
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

        auto AccountStore::PrepareRemove(const Prism::AccountId Id)
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

        auto AccountStore::Commit(PreparedAccountUpdate& Update) -> std::expected<void, Failure>
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
            auto RuntimeTransaction =
                PrepareRuntimeTransactionUnlocked(RuntimeRegistry_, Update);
            if (!RuntimeTransaction)
            {
                return std::unexpected(RuntimeTransaction.error());
            }
            const auto Published = (*RuntimeTransaction)->Publish();
            if (!Published)
            {
                return std::unexpected(Published.error());
            }
            const auto Committed = CommitSnapshotLocked(Update);
            if (Committed)
            {
                (*RuntimeTransaction)->Finalize();
            }
            return Committed;
        }

        auto AccountStore::PrepareRuntimeTransaction(PreparedAccountUpdate &Update)
            -> std::expected<
                std::shared_ptr<AccountRuntimeRegistry::RuntimeBindingTransaction>, Failure>
        {
            Mutation Guard(Mutation_);
            if (!Guard.Acquired())
            {
                return std::unexpected(MakeFailure(FailureReason::Busy));
            }
            return PrepareRuntimeTransactionUnlocked(RuntimeRegistry_, Update);
        }

        auto AccountStore::PrepareRuntimeTransactionUnlocked(
            const std::shared_ptr<AccountRuntimeRegistry> &RuntimeRegistry,
            PreparedAccountUpdate &Update)
            -> std::expected<
                std::shared_ptr<AccountRuntimeRegistry::RuntimeBindingTransaction>, Failure>
        {
            if (!RuntimeRegistry || !Update.Next_)
            {
                return std::unexpected(Failure{Code::InvalidArgument});
            }
            std::vector<AccountRuntimeRegistry::RuntimeBindingRequest> Bindings;
            try
            {
                std::vector<Prism::AccountId> AccountIds;
                AccountIds.reserve(Update.Next_->Bindings.size());
                Bindings.reserve(
                    Update.Next_->Bindings.size() + Update.Base_->Bindings.size());
                for (const auto &Binding : Update.Next_->Bindings)
                {
                    AccountIds.push_back(Binding->AccountId());
                    Bindings.push_back({
                        Binding->Runtime(),
                        std::string(Binding->Materials()->DisplayIdentity())});
                }
                for (const auto &Binding : Update.Base_->Bindings)
                {
                    if (std::find(AccountIds.begin(), AccountIds.end(),
                            Binding->AccountId()) != AccountIds.end())
                    {
                        continue;
                    }
                    const auto Duplicate = std::find_if(
                        Bindings.begin(), Bindings.end(),
                        [&Binding](const auto &Request)
                        {
                            return Request.Runtime == Binding->Runtime();
                        });
                    if (Duplicate == Bindings.end())
                    {
                        Bindings.push_back({
                            Binding->Runtime(),
                            std::string(Binding->Materials()->DisplayIdentity())});
                    }
                }
            }
            catch (...)
            {
                return std::unexpected(Failure{Code::ResourceUnavailable});
            }
            auto Prepared = RuntimeRegistry->PrepareRuntimeBindings(Bindings);
            if (!Prepared)
            {
                return std::unexpected(Prepared.error());
            }
            Update.RuntimeTransaction_ = std::move(*Prepared);
            return Update.RuntimeTransaction_;
        }

        auto AccountStore::CommitSnapshot(PreparedAccountUpdate &Update)
            -> std::expected<void, Failure>
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
            return CommitSnapshotLocked(Update);
        }

        auto AccountStore::CommitSnapshotLocked(PreparedAccountUpdate &Update)
            -> std::expected<void, Failure>
        {
            State_->Snapshot.store(std::move(Update.Next_), std::memory_order_release);
            Update.Owner_.reset();
            Update.Base_.reset();
            return {};
        }

        auto PreparedAccountUpdate::DetachRuntimeTransaction() noexcept
            -> std::shared_ptr<AccountRuntimeRegistry::RuntimeBindingTransaction>
        {
            return std::move(RuntimeTransaction_);
        }

        auto AccountStore::FindById(const Prism::AccountId Id) const noexcept
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

        auto AccountStore::Revoke(const Prism::AccountId Id) const noexcept -> std::expected<void, Failure>
        {
            const auto Binding = FindById(Id);
            if (!Binding)
            {
                return std::unexpected(Failure{Code::AuthFailed});
            }
            return RuntimeRegistry_->Revoke(Id);
        }

        auto AccountStore::Size() const noexcept -> std::size_t
        {
            return State_->Snapshot.load(std::memory_order_acquire)->Bindings.size();
        }

        auto AccountStore::AccountIds() const -> std::vector<Prism::AccountId>
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

        auto AccountStore::EnsureScope(const CredentialScope Scope) -> std::expected<std::size_t, Failure>
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

        auto AccountStore::BuildBinding(AccountDefinition Definition,
            const std::shared_ptr<const Detail::AccountSnapshot>& Base)
            -> std::expected<std::shared_ptr<const AccountBinding>, Failure>
        {
            if (!Definition.Materials || !Definition.Materials->AccountId())
            {
                return std::unexpected(Failure{Code::InvalidArgument});
            }
            if (Definition.Materials->DisplayIdentity().empty())
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
            auto Runtime = RuntimeRegistry_->ResolveForPreparation(
                Definition.Materials->AccountId(),
                Definition.Materials->DisplayIdentity(),
                Options_.WorkerCount);
            if (!Runtime)
            {
                return std::unexpected(Runtime.error());
            }
            std::shared_ptr<const RateLimiter> Previous;
            for (const auto& Binding : Base->Bindings)
            {
                if (Binding->AccountId() == Definition.Materials->AccountId())
                {
                    if (Binding->Runtime() == *Runtime)
                    {
                        Previous = Binding->Policy()->Rate();
                    }
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

        auto AccountStore::FinishPrepared(const std::shared_ptr<const Detail::AccountSnapshot>& Base,
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
}
