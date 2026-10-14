/**
 * @file RuntimeRegistry.hpp
 * @brief 稳定账户 runtime 登记，并将准入与撤销投影到运行时 publication。
 */
#pragma once

#include <Preview/Account/Failure.hpp>
#include <Preview/Account/PolicyVersion.hpp>
#include <Preview/Account/RateTypes.hpp>
#include <Preview/Account/Runtime.hpp>
#include <Preview/Contract/Account/AdmissionAuthority.hpp>
#include <Preview/Foundation/Identifier/Id.hpp>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <span>
#include <stdexcept>
#include <utility>

namespace Preview::Account
{

    /** @brief 多代 binding 共用的稳定 runtime 登记；撤销事实只由 publication 持有。 */
    class AccountRuntimeRegistry final : public std::enable_shared_from_this<AccountRuntimeRegistry>
    {
        using Failure = Fault::Failure;
        using Code = Fault::Code;
        static constexpr std::size_t MaxRuntimeRecords{4096U};

        class Mutation final
        {
        public:
            explicit Mutation(std::atomic_flag &Gate) noexcept : Gate_(Gate)
            {
                Acquired_ = !Gate_.test_and_set(std::memory_order_acquire);
            }
            ~Mutation()
            {
                if (Acquired_)
                {
                    Gate_.clear(std::memory_order_release);
                }
            }
            [[nodiscard]] auto Acquired() const noexcept -> bool { return Acquired_; }

        private:
            std::atomic_flag &Gate_;
            bool Acquired_{false};
        };

    public:
        explicit AccountRuntimeRegistry(const PolicyVersion InitialVersion = PolicyVersion{1U})
            : NextPolicyVersion_(InitialVersion.Value())
        {
            if (!InitialVersion)
            {
                throw std::invalid_argument("invalid initial account policy version");
            }
        }

        AccountRuntimeRegistry(const AccountRuntimeRegistry &) = delete;
        auto operator=(const AccountRuntimeRegistry &) -> AccountRuntimeRegistry & = delete;

        /** @brief 启动发布器后一次性接入 authority，并补挂启动准备期间创建的 runtime。 */
        [[nodiscard]] auto AttachAdmissionAuthority(
            const std::shared_ptr<Preview::Contract::AccountAdmissionAuthority> &Authority)
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

        [[nodiscard]] auto FindOrCreate(
            const Preview::AccountId Id,
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
                Runtimes_.emplace(Id, Runtime);
                return Runtime;
            }
            catch (...)
            {
                return std::unexpected(Failure{Code::ResourceUnavailable});
            }
        }

        [[nodiscard]] auto Revoke(const Preview::AccountId Id) noexcept
            -> std::expected<void, Failure>
        {
            return RevokeMany(std::span<const Preview::AccountId>(&Id, 1U));
        }

        /** @brief 手工撤销只通过 publication 的成员/墓碑 CAS 改变准入事实。 */
        [[nodiscard]] auto RevokeMany(
            const std::span<const Preview::AccountId> Ids) noexcept
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

        /** @brief Store seal 只关 authority；真实 session/socket drain 仍归 application owner。 */
        [[nodiscard]] auto RevokeAll() noexcept -> std::expected<void, Failure>
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

        /** @brief 按单一 runtime owner 严格分配递增策略版本。 */
        [[nodiscard]] auto AllocatePolicyVersion() noexcept -> std::expected<PolicyVersion, Failure>
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

        [[nodiscard]] auto IsRevoked(const Preview::AccountId Id) const noexcept -> bool
        {
            const auto Authority = Authority_.lock();
            if (!Authority)
            {
                return true;
            }
            const auto Snapshot = Authority->Load();
            return !Snapshot || Snapshot->IsRevoked(Id);
        }

    private:
        std::map<Preview::AccountId, std::weak_ptr<AccountRuntime>> Runtimes_;
        std::weak_ptr<Preview::Contract::AccountAdmissionAuthority> Authority_;
        std::atomic<std::uint64_t> NextPolicyVersion_{1U};
        std::atomic_flag Mutation_ = ATOMIC_FLAG_INIT;
        bool Closed_{false};
    };

} // namespace Preview::Account
