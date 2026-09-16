/**
 * @file Directory.hpp
 * @brief 账户凭据目录与无锁租约获取
 * @details 目录以原子快照保存账户记录；读路径不加锁，写路径复制快照并
 *          CAS 发布。旧记录由已有租约继续持有，撤销只影响后续获取。
 */
#pragma once

#include "Lease.hpp"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace Preview::Account
{

    enum class AcquireFailure : std::uint8_t
    {
        None = 0,
        NotFound,
        Revoked,
        ConnectionQuota,
        RateLimited,
        InvalidCredential,
    };

    class AccountDirectory final
    {
    public:
        struct AcquireRequest
        {
            CredentialView Credential;
            RateRequest Rate{};
        };

        struct AcquireResult
        {
            SharedAccountRecord Record;
            AccountLease Lease;
            AcquireFailure Failure{AcquireFailure::None};

            [[nodiscard]] explicit operator bool() const noexcept
            {
                return static_cast<bool>(Lease);
            }
        };

        AccountDirectory() : Records_(std::make_shared<const Records>())
        {
        }

        [[nodiscard]] auto Upsert(SharedAccountRecord Record) -> bool
        {
            if (!Record || !Record->IsValid())
            {
                return false;
            }

            auto Current = Records_.load(std::memory_order_acquire);
            while (true)
            {
                auto Next = std::make_shared<Records>(*Current);
                bool Replaced = false;
                SharedAccountRuntimeState RuntimeToUpdate;
                AccountRuntimeState::PolicyUpdate PendingPolicy;
                for (const auto &Existing : *Next)
                {
                    if (Existing->AccountId() != Record->AccountId() &&
                        Existing->Credential().Kind() == Record->Credential().Kind() &&
                        Credential::ConstantTimeEqual(Existing->Credential(), Record->Credential()))
                    {
                        return false;
                    }
                }
                for (auto &Existing : *Next)
                {
                    if (Existing->AccountId() == Record->AccountId())
                    {
                        RuntimeToUpdate = Existing->Runtime();
                        const auto Generation = NextPolicyGeneration();
                        auto Rebound = Record->WithRuntime(RuntimeToUpdate, Generation);
                        PendingPolicy = AccountRuntimeState::PolicyUpdate{
                            Generation, Record->Rate(), Record->Quota().MaxBytes};
                        Existing = std::move(Rebound);
                        Replaced = true;
                        break;
                    }
                }
                if (!Replaced)
                {
                    RuntimeToUpdate = Record->Runtime();
                    const auto Generation = NextPolicyGeneration();
                    auto Published = Record->WithRuntime(RuntimeToUpdate, Generation);
                    PendingPolicy = AccountRuntimeState::PolicyUpdate{
                        Generation, Record->Rate(), Record->Quota().MaxBytes};
                    Next->push_back(std::move(Published));
                }

                auto PreparedPolicy = RuntimeToUpdate->PreparePolicy(PendingPolicy);
                std::shared_ptr<const Records> Published = std::move(Next);
                if (Records_.compare_exchange_weak(Current, Published, std::memory_order_release,
                                                   std::memory_order_acquire))
                {
                    RuntimeToUpdate->PublishPolicy(PendingPolicy.Generation,
                                                   std::move(PreparedPolicy));
                    return true;
                }
            }
        }

        [[nodiscard]] auto Find(CredentialView Credential) const -> SharedAccountRecord
        {
            if (!Credential.IsValid())
            {
                return {};
            }
            const auto Snapshot = Records_.load(std::memory_order_acquire);
            for (const auto &Record : *Snapshot)
            {
                if (Credential::ConstantTimeEqual(Record->Credential(), Credential))
                {
                    return Record;
                }
            }
            return {};
        }

        [[nodiscard]] auto FindById(Preview::AccountId AccountId) const -> SharedAccountRecord
        {
            if (!AccountId)
            {
                return {};
            }
            const auto Snapshot = Records_.load(std::memory_order_acquire);
            for (const auto &Record : *Snapshot)
            {
                if (Record->AccountId() == AccountId)
                {
                    return Record;
                }
            }
            return {};
        }

        [[nodiscard]] auto Remove(Preview::AccountId AccountId) -> bool
        {
            if (!AccountId)
            {
                return false;
            }
            auto Current = Records_.load(std::memory_order_acquire);
            while (true)
            {
                auto Next = std::make_shared<Records>(*Current);
                const auto It = std::find_if(
                    Next->begin(), Next->end(),
                    [AccountId](const auto &Record) { return Record->AccountId() == AccountId; });
                if (It == Next->end())
                {
                    return false;
                }
                Next->erase(It);

                std::shared_ptr<const Records> Published = std::move(Next);
                if (Records_.compare_exchange_weak(Current, Published, std::memory_order_release,
                                                   std::memory_order_acquire))
                {
                    return true;
                }
            }
        }

        [[nodiscard]] auto Revoke(Preview::AccountId AccountId) const -> bool
        {
            const auto Record = FindById(AccountId);
            if (!Record)
            {
                return false;
            }
            Record->Runtime()->Revoke();
            return true;
        }

        [[nodiscard]] auto TryAcquire(AcquireRequest Request) const -> AcquireResult
        {
            AcquireResult Result;
            if (!Request.Credential.IsValid())
            {
                Result.Failure = AcquireFailure::InvalidCredential;
                return Result;
            }
            while (true)
            {
                Result.Record = Find(Request.Credential);
                if (!Result.Record)
                {
                    Result.Failure = AcquireFailure::NotFound;
                    return Result;
                }

                const auto RecordGeneration = Result.Record->PolicyGeneration();
                const auto Runtime = Result.Record->Runtime();
                if (Runtime->PolicyGeneration() != RecordGeneration)
                {
                    continue;
                }
                const auto Policy = Runtime->PolicyFor(RecordGeneration);
                if (!Policy)
                {
                    continue;
                }
                if (Runtime->IsRevoked())
                {
                    Result.Failure = AcquireFailure::Revoked;
                    return Result;
                }
                if (!Runtime->TryAcquireConnection(Result.Record->Quota().MaxConnections))
                {
                    Result.Failure = Runtime->IsRevoked() ? AcquireFailure::Revoked
                                                           : AcquireFailure::ConnectionQuota;
                    return Result;
                }
                if (!Policy->TryConsume(Request.Rate))
                {
                    Runtime->ReleaseConnection();
                    Result.Failure = AcquireFailure::RateLimited;
                    return Result;
                }

                Result.Lease = AccountLease(AccountLease::Binding{Result.Record, Runtime, Policy});
                Result.Failure = AcquireFailure::None;
                return Result;
            }
        }

        [[nodiscard]] auto Size() const -> std::size_t
        {
            const auto Snapshot = Records_.load(std::memory_order_acquire);
            return Snapshot->size();
        }

        /**
         * @brief 遍历当前账户快照
         * @param Function 接收共享账户记录的回调
         * @details 回调只借用快照中的共享记录；快照本身在遍历期间保持存活。
         */
        template <typename Fn>
        void ForEach(Fn &&Function) const
        {
            const auto Snapshot = Records_.load(std::memory_order_acquire);
            for (const auto &Record : *Snapshot)
            {
                Function(Record);
            }
        }

    private:
        using Records = std::vector<SharedAccountRecord>;

        [[nodiscard]] auto NextPolicyGeneration() noexcept -> Preview::GenerationId
        {
            return Preview::GenerationId{
                NextGeneration_.fetch_add(1, std::memory_order_relaxed)};
        }

        std::atomic<std::shared_ptr<const Records>> Records_;
        std::atomic<std::uint64_t> NextGeneration_{1};
    };

} // namespace Preview::Account
