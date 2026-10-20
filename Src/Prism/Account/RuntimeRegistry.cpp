/** @file RuntimeRegistry.cpp
 * @brief 账户运行时登记、撤销与持久化实现。
 */
#include <Prism/Account/RuntimeRegistry.hpp>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <expected>
#include <limits>
#include <map>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace Prism::Account
{
            AccountRuntimeRegistry::Mutation::Mutation(std::atomic_flag &Gate) noexcept : Gate_(Gate)
            {
                Acquired_ = !Gate_.test_and_set(std::memory_order_acquire);
            }

            AccountRuntimeRegistry::Mutation::~Mutation()
            {
                if (Acquired_)
                {
                    Gate_.clear(std::memory_order_release);
                    Gate_.notify_all();
                }
            }

            auto AccountRuntimeRegistry::Mutation::Acquired() const noexcept -> bool { return Acquired_; }

        AccountRuntimeRegistry::RuntimeBindingTransaction::~RuntimeBindingTransaction()
        {
            Rollback();
        }

        auto AccountRuntimeRegistry::RuntimeBindingTransaction::Publish() noexcept
            -> std::expected<void, Failure>
        {
            if (!Owner_ || Applied_ || RolledBack_)
            {
                return std::unexpected(Failure{Code::InvalidArgument});
            }
            Mutation Guard(Owner_->Mutation_);
            if (!Guard.Acquired())
            {
                return std::unexpected(MakeFailure(FailureReason::Busy));
            }
            if (Owner_->Closed_)
            {
                return std::unexpected(Failure{Code::Canceled});
            }
            try
            {
                Owner_->ApplyRuntimeBindings(*this);
            }
            catch (...)
            {
                Owner_->RestoreRuntimeBindingsLocked(*this);
                return std::unexpected(Failure{Code::ResourceUnavailable});
            }
            Applied_ = true;
            return {};
        }

        auto AccountRuntimeRegistry::RuntimeBindingTransaction::Finalize() noexcept -> void
        {
            if (!Applied_ || Finalized_)
            {
                return;
            }
            Finalized_ = true;
            Changes_.clear();
            Owner_.reset();
        }

        auto AccountRuntimeRegistry::RuntimeBindingTransaction::Rollback() noexcept -> void
        {
            if (!Owner_ || Finalized_ || RolledBack_)
            {
                return;
            }
            if (Applied_)
            {
                for (;;)
                {
                    Owner_->Mutation_.wait(true, std::memory_order_acquire);
                    Mutation Guard(Owner_->Mutation_);
                    if (!Guard.Acquired())
                    {
                        continue;
                    }
                    Owner_->RestoreRuntimeBindingsLocked(*this);
                    break;
                }
            }
            RolledBack_ = true;
            Changes_.clear();
            Owner_.reset();
        }

        AccountRuntimeRegistry::RuntimeBindingTransaction::RuntimeBindingTransaction(
            std::shared_ptr<AccountRuntimeRegistry> Owner,
            std::vector<Change> Changes)
            : Owner_(std::move(Owner)),
              Changes_(std::move(Changes))
        {
        }

        AccountRuntimeRegistry::AccountRuntimeRegistry(const PolicyVersion InitialVersion)
            : NextPolicyVersion_(InitialVersion.Value())
        {
            if (!InitialVersion)
            {
                throw std::invalid_argument("invalid initial account policy version");
            }
        }

        auto AccountRuntimeRegistry::AttachPolicySource(std::shared_ptr<PolicySource> Source)
            -> std::expected<void, Failure>
        {
            if (!Source || PolicySource_) return std::unexpected(Failure{Code::InvalidArgument});
            Mutation Guard(Mutation_);
            if (!Guard.Acquired()) return std::unexpected(MakeFailure(FailureReason::Busy));
            PolicySource_ = std::move(Source);
            for (const auto& Entry : Runtimes_)
                if (const auto Runtime = Entry.second.lock()) Runtime->AttachPolicySource(PolicySource_);
            return {};
        }

        auto AccountRuntimeRegistry::AttachUsagePersistence(std::shared_ptr<UsagePersistence> Persistence,
            std::string Incarnation) -> std::expected<void, Failure>
        {
            if (!Persistence || Incarnation.empty())
                return std::unexpected(Failure{Code::InvalidArgument});
            Mutation Guard(Mutation_);
            if (!Guard.Acquired()) return std::unexpected(MakeFailure(FailureReason::Busy));
            if (!PolicySource_ || Persistence_)
                return std::unexpected(Failure{Code::InvalidArgument});
            std::vector<std::pair<std::shared_ptr<AccountRuntime>,
                std::shared_ptr<TransferBudget>>> Prepared;
            try
            {
                Prepared.reserve(Runtimes_.size());
                for (const auto& Entry : Runtimes_)
                {
                    const auto Runtime = Entry.second.lock();
                    if (!Runtime || Runtime->Transfer()) continue;
                    const auto StableKey = Runtime->StableKey();
                    if (StableKey.empty())
                        return std::unexpected(Failure{Code::InvalidArgument});
                    Prepared.emplace_back(Runtime,
                        std::make_shared<TransferBudget>(TransferBudgetOptions{
                            Runtime->AccountId(), StableKey,
                            PolicySource_, Persistence, Incarnation}));
                }
            }
            catch (...)
            {
                return std::unexpected(Failure{Code::ResourceUnavailable});
            }
            Persistence_ = std::move(Persistence);
            Incarnation_ = std::move(Incarnation);
            for (auto& [Runtime, Transfer] : Prepared)
                Runtime->AttachTransfer(std::move(Transfer));
            return {};
        }

        auto AccountRuntimeRegistry::FlushUsage(const bool Final)
            -> Net::awaitable<std::expected<void, Failure>>
        {
            std::vector<std::pair<std::shared_ptr<AccountRuntime>, std::shared_ptr<TransferBudget>>> Owners;
            {
                Mutation Guard(Mutation_);
                if (!Guard.Acquired()) co_return std::unexpected(MakeFailure(FailureReason::Busy));
                try
                {
                    Owners.reserve(Runtimes_.size());
                    for (const auto& Entry : Runtimes_)
                    {
                        if (const auto Runtime = Entry.second.lock())
                            Owners.emplace_back(Runtime, Runtime->Transfer());
                    }
                }
                catch (...)
                {
                    co_return std::unexpected(Failure{Code::ResourceUnavailable});
                }
            }
            for (const auto& [Runtime, Transfer] : Owners)
            {
                if (!Transfer) continue;
                if (!Final)
                {
                    const auto Read = co_await Transfer->Read();
                    if (!Read) co_return std::unexpected(Read.error());
                }
                else
                {
                    const auto Flushed = co_await Transfer->Flush(true);
                    if (!Flushed) co_return std::unexpected(Flushed.error());
                }
            }
            co_return std::expected<void, Failure>{};
        }

        auto AccountRuntimeRegistry::AttachAdmissionAuthority(
            const std::shared_ptr<Prism::Contract::AccountAdmissionAuthority> &Authority)
            -> std::expected<void, Failure>
        {
            if (!Authority)
            {
                return std::unexpected(Failure{Code::InvalidArgument});
            }
            Mutation Guard(Mutation_);
            if (!Guard.Acquired())
            {
                return std::unexpected(MakeFailure(FailureReason::Busy));
            }
            if (Closed_)
            {
                return std::unexpected(Failure{Code::Canceled});
            }
            if (const auto Existing = Authority_.lock(); Existing && Existing != Authority)
            {
                return std::unexpected(Failure{Code::InvalidArgument});
            }
            Authority_ = Authority;
            for (const auto &Entry : Runtimes_)
            {
                if (const auto Runtime = Entry.second.lock())
                {
                    Runtime->AttachAuthority(Authority_);
                }
            }
            return {};
        }

        auto AccountRuntimeRegistry::FindOrCreate(
            const Prism::AccountId Id,
            const std::uint32_t WorkerCount)
            -> std::expected<std::shared_ptr<AccountRuntime>, Failure>
        {
            if (!Id || WorkerCount == 0U || WorkerCount > WorkerShardedRatePolicy::MaxWorkerCount)
            {
                return std::unexpected(Failure{Code::InvalidArgument});
            }
            Mutation Guard(Mutation_);
            if (!Guard.Acquired())
            {
                return std::unexpected(MakeFailure(FailureReason::Busy));
            }
            if (Closed_)
            {
                return std::unexpected(Failure{Code::Canceled});
            }
            if (const auto It = Runtimes_.find(Id); It != Runtimes_.end())
            {
                if (auto Runtime = It->second.lock())
                {
                    return Runtime;
                }
                Runtimes_.erase(It);
            }
            std::erase_if(Runtimes_, [](const auto &Entry) { return Entry.second.expired(); });
            if (Runtimes_.size() == MaxRuntimeRecords)
            {
                return std::unexpected(MakeFailure(FailureReason::Accounts));
            }
            try
            {
                auto Runtime = std::make_shared<AccountRuntime>(Id, WorkerCount);
                Runtime->AttachAuthority(Authority_);
                Runtime->AttachPolicySource(PolicySource_);
                Runtimes_.emplace(Id, Runtime);
                return Runtime;
            }
            catch (...)
            {
                return std::unexpected(Failure{Code::ResourceUnavailable});
            }
        }

        auto AccountRuntimeRegistry::Revoke(const Prism::AccountId Id) noexcept
            -> std::expected<void, Failure>
        {
            return RevokeMany(std::span<const Prism::AccountId>(&Id, 1U));
        }

        auto AccountRuntimeRegistry::RevokeMany(
            const std::span<const Prism::AccountId> Ids) noexcept
            -> std::expected<void, Failure>
        {
            Mutation Guard(Mutation_);
            if (!Guard.Acquired())
            {
                return std::unexpected(MakeFailure(FailureReason::Busy));
            }
            if (Closed_)
            {
                return std::unexpected(Failure{Code::Canceled});
            }
            const auto Authority = Authority_.lock();
            if (!Authority)
            {
                return std::unexpected(Failure{Code::ResourceUnavailable});
            }
            return Authority->RevokeAccounts(Ids);
        }

        auto AccountRuntimeRegistry::RevokeAll() noexcept -> std::expected<void, Failure>
        {
            Mutation Guard(Mutation_);
            if (!Guard.Acquired())
            {
                return std::unexpected(MakeFailure(FailureReason::Busy));
            }
            if (Closed_)
            {
                return {};
            }
            const auto Authority = Authority_.lock();
            if (!Authority)
            {
                return std::unexpected(Failure{Code::ResourceUnavailable});
            }
            const auto Closed = Authority->CloseAllAccounts();
            if (Closed)
            {
                Closed_ = true;
            }
            return Closed;
        }

        auto AccountRuntimeRegistry::AllocatePolicyVersion() noexcept -> std::expected<PolicyVersion, Failure>
        {
            auto Current = NextPolicyVersion_.load(std::memory_order_relaxed);
            for (;;)
            {
                if (Current == 0U || Current == std::numeric_limits<std::uint64_t>::max())
                {
                    return std::unexpected(MakeFailure(FailureReason::VersionExhausted));
                }
                if (NextPolicyVersion_.compare_exchange_weak(
                        Current, Current + 1U, std::memory_order_relaxed,
                        std::memory_order_relaxed))
                {
                    return PolicyVersion{Current};
                }
            }
        }

        auto AccountRuntimeRegistry::IsRevoked(const Prism::AccountId Id) const noexcept -> bool
        {
            const auto Authority = Authority_.lock();
            if (!Authority)
            {
                return true;
            }
            const auto Snapshot = Authority->Load();
            return !Snapshot || Snapshot->IsRevoked(Id);
        }

        auto AccountRuntimeRegistry::PrepareRuntimeBindings(
            const std::span<const RuntimeBindingRequest> Bindings)
            -> std::expected<std::shared_ptr<RuntimeBindingTransaction>, Failure>
        {
            Mutation Guard(Mutation_);
            if (!Guard.Acquired())
            {
                return std::unexpected(MakeFailure(FailureReason::Busy));
            }
            if (Closed_)
            {
                return std::unexpected(Failure{Code::Canceled});
            }
            std::vector<RuntimeBindingTransaction::Change> Changes;
            try
            {
                Changes.reserve(Bindings.size());
                for (const auto& Binding : Bindings)
                {
                    if (!Binding.Runtime || Binding.StableKey.empty())
                        return std::unexpected(Failure{Code::InvalidArgument});
                    const auto Duplicate = std::find_if(
                        Changes.begin(), Changes.end(),
                        [&Binding](const auto &Change)
                        {
                            return Change.Runtime->AccountId() ==
                                Binding.Runtime->AccountId();
                        });
                    if (Duplicate != Changes.end())
                    {
                        return std::unexpected(Failure{Code::InvalidArgument});
                    }
                    const auto Existing = Runtimes_.find(Binding.Runtime->AccountId());
                    bool WasRegistered = false;
                    std::weak_ptr<AccountRuntime> PreviousRuntime;
                    std::string RegisteredKey;
                    if (Existing != Runtimes_.end())
                    {
                        if (const auto Registered = Existing->second.lock())
                        {
                            PreviousRuntime = Registered;
                            if (Registered == Binding.Runtime)
                            {
                                WasRegistered = true;
                                RegisteredKey = Registered->StableKey();
                            }
                            else if (!Registered->StableKey().empty())
                            {
                                return std::unexpected(Failure{Code::InvalidArgument});
                            }
                        }
                    }
                    const auto ExistingKey = Binding.Runtime->StableKey();
                    auto ExistingTransfer = Binding.Runtime->Transfer();
                    if (!RegisteredKey.empty() && RegisteredKey != Binding.StableKey)
                        return std::unexpected(Failure{Code::InvalidArgument});
                    if (!ExistingKey.empty() && ExistingKey != Binding.StableKey)
                        return std::unexpected(Failure{Code::InvalidArgument});
                    auto Transfer = ExistingTransfer;
                    if (Transfer && Transfer->AccountKey() != Binding.StableKey)
                        return std::unexpected(Failure{Code::InvalidArgument});
                    if (!Transfer && Persistence_ && PolicySource_)
                    {
                        Transfer = std::make_shared<TransferBudget>(TransferBudgetOptions{
                            Binding.Runtime->AccountId(), Binding.StableKey,
                            PolicySource_, Persistence_, Incarnation_});
                    }
                    Changes.push_back({
                        Binding.Runtime,
                        std::string(Binding.StableKey),
                        std::move(Transfer),
                        ExistingKey,
                        std::move(ExistingTransfer),
                        std::move(PreviousRuntime),
                        WasRegistered});
                }
            }
            catch (...)
            {
                return std::unexpected(Failure{Code::ResourceUnavailable});
            }
            std::shared_ptr<RuntimeBindingTransaction> Transaction;
            try
            {
                Transaction = std::shared_ptr<RuntimeBindingTransaction>(
                    new RuntimeBindingTransaction(
                        shared_from_this(), std::move(Changes)));
            }
            catch (...)
            {
                return std::unexpected(Failure{Code::ResourceUnavailable});
            }
            return Transaction;
        }

        auto AccountRuntimeRegistry::ApplyRuntimeBindings(
            RuntimeBindingTransaction &Transaction) -> void
        {
            auto Next = Runtimes_;
            std::erase_if(Next,
                [](const auto &Entry) { return Entry.second.expired(); });
            for (const auto &Change : Transaction.Changes_)
            {
                if (!Change.WasRegistered)
                {
                    Next.insert_or_assign(Change.Runtime->AccountId(), Change.Runtime);
                }
            }
            if (Next.size() > MaxRuntimeRecords)
            {
                throw std::length_error("runtime registry capacity");
            }
            for (auto &Change : Transaction.Changes_)
            {
                auto Transfer = Change.Transfer ? std::move(Change.Transfer)
                                               : Change.Runtime->Transfer();
                if (!Transfer && Persistence_ && PolicySource_)
                {
                    Transfer = std::make_shared<TransferBudget>(TransferBudgetOptions{
                        Change.Runtime->AccountId(), Change.StableKey,
                        PolicySource_, Persistence_, Incarnation_});
                }
                Change.Runtime->ApplyStableKeyAndTransfer(
                    std::move(Change.StableKey), std::move(Transfer));
                if (!Change.WasRegistered)
                {
                    Change.Runtime->AttachAuthority(Authority_);
                    Change.Runtime->AttachPolicySource(PolicySource_);
                }
            }
            Runtimes_.swap(Next);
            // 保持 owner 以支持 generation CAS 失败后的恢复；成功提交由 Finalize 释放。
        }

        auto AccountRuntimeRegistry::RestoreRuntimeBindingsLocked(
            RuntimeBindingTransaction &Transaction) noexcept -> void
        {
            for (auto It = Transaction.Changes_.rbegin();
                It != Transaction.Changes_.rend(); ++It)
            {
                try
                {
                    if (It->Runtime->StableKey() != It->PreviousStableKey ||
                        It->Runtime->Transfer() != It->PreviousTransfer)
                    {
                        It->Runtime->ApplyStableKeyAndTransfer(
                            std::string(It->PreviousStableKey),
                            It->PreviousTransfer);
                    }
                    if (!It->WasRegistered)
                    {
                        const auto Entry = Runtimes_.find(It->Runtime->AccountId());
                        if (Entry != Runtimes_.end() &&
                            Entry->second.lock() == It->Runtime)
                        {
                            if (const auto Previous = It->PreviousRuntime.lock())
                            {
                                Entry->second = Previous;
                            }
                            else
                            {
                                Runtimes_.erase(Entry);
                            }
                        }
                    }
                }
                catch (...)
                {
                }
            }
        }

        auto AccountRuntimeRegistry::ResolveForPreparation(
            const Prism::AccountId Id,
            const std::string_view StableKey,
            const std::uint32_t WorkerCount)
            -> std::expected<std::shared_ptr<AccountRuntime>, Failure>
        {
            if (!Id || StableKey.empty() || WorkerCount == 0U ||
                WorkerCount > WorkerShardedRatePolicy::MaxWorkerCount)
            {
                return std::unexpected(Failure{Code::InvalidArgument});
            }
            Mutation Guard(Mutation_);
            if (!Guard.Acquired()) return std::unexpected(MakeFailure(FailureReason::Busy));
            if (Closed_) return std::unexpected(Failure{Code::Canceled});
            if (const auto Existing = Runtimes_.find(Id); Existing != Runtimes_.end())
            {
                if (const auto Runtime = Existing->second.lock())
                {
                    const auto RegisteredKey = Runtime->StableKey();
                    if (RegisteredKey.empty() || RegisteredKey == StableKey)
                    {
                        return Runtime;
                    }
                }
            }
            try
            {
                auto Candidate = std::make_shared<AccountRuntime>(Id, WorkerCount);
                Candidate->AttachAuthority(Authority_);
                Candidate->AttachPolicySource(PolicySource_);
                return Candidate;
            }
            catch (...)
            {
                return std::unexpected(Failure{Code::ResourceUnavailable});
            }
        }
}
