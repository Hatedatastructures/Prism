/**
 * @file RuntimeRegistry.hpp
 * @brief 稳定账户 runtime 登记，并将准入与撤销投影到运行时 publication。
 */
#pragma once

#include <Prism/Account/Failure.hpp>
#include <Prism/Account/PolicyVersion.hpp>
#include <Prism/Account/RateTypes.hpp>
#include <Prism/Account/Runtime.hpp>
#include <Prism/Account/Policy.hpp>
#include <Prism/Contract/Account/AdmissionAuthority.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace Prism::Account
{
    using Failure = Fault::Failure;

    /** @brief 多代 binding 共用的稳定 runtime 登记；撤销事实只由 publication 持有。 */
    class AccountRuntimeRegistry final : public std::enable_shared_from_this<AccountRuntimeRegistry>
    {
    public:
        struct RuntimeBindingRequest final
        {
            std::shared_ptr<AccountRuntime> Runtime;
            std::string StableKey;
        };
        class RuntimeBindingTransaction;

        /**
         * @brief 先准备、后统一发布的 runtime 账本变更。
         * @details Prepare 只生成本事务私有结果；Publish 一次替换稳定键、transfer budget
         *          和 runtime 映射，失败可恢复旧代。事务析构时未发布变更自动放弃。
         */
        class RuntimeBindingTransaction final
        {
        public:
            RuntimeBindingTransaction(const RuntimeBindingTransaction &) = delete;
            auto operator=(const RuntimeBindingTransaction &)
                -> RuntimeBindingTransaction & = delete;
            RuntimeBindingTransaction(RuntimeBindingTransaction &&) = delete;
            auto operator=(RuntimeBindingTransaction &&)
                -> RuntimeBindingTransaction & = delete;
            ~RuntimeBindingTransaction();

            [[nodiscard]] auto Publish() noexcept
                -> std::expected<void, Failure>;
            /** @brief generation CAS 已成功，释放恢复信息且不再回滚。 */
            auto Finalize() noexcept -> void;
            auto Rollback() noexcept -> void;

        private:
            friend class AccountRuntimeRegistry;
            struct Change final
            {
                std::shared_ptr<AccountRuntime> Runtime;
                std::string StableKey;
                std::shared_ptr<TransferBudget> Transfer;
                std::string PreviousStableKey;
                std::shared_ptr<TransferBudget> PreviousTransfer;
                std::weak_ptr<AccountRuntime> PreviousRuntime;
                bool WasRegistered{false};
            };

            RuntimeBindingTransaction(
                std::shared_ptr<AccountRuntimeRegistry> Owner,
                std::vector<Change> Changes);
            std::shared_ptr<AccountRuntimeRegistry> Owner_;
            std::vector<Change> Changes_;
            bool Applied_{false};
            bool Finalized_{false};
            bool RolledBack_{false};
        };

    private:
        using Code = Fault::Code;
        static constexpr std::size_t MaxRuntimeRecords{4096U};

        class Mutation final
        {
        public:
            explicit Mutation(std::atomic_flag &Gate) noexcept;
            ~Mutation();
            [[nodiscard]] auto Acquired() const noexcept -> bool;

        private:
            std::atomic_flag &Gate_;
            bool Acquired_{false};
        };

    public:
        explicit AccountRuntimeRegistry(const PolicyVersion InitialVersion = PolicyVersion{1U});

        AccountRuntimeRegistry(const AccountRuntimeRegistry &) = delete;
        auto operator=(const AccountRuntimeRegistry &) -> AccountRuntimeRegistry & = delete;

        /** @brief Application 在网络启动前一次性安装正式 publication 读取端口。 */
        [[nodiscard]] auto AttachPolicySource(std::shared_ptr<PolicySource> Source)
            -> std::expected<void, Failure>;
        /** @brief 存储在网络启动前安装；已有 runtime 缺少稳定键时整次接入失败。 */
        [[nodiscard]] auto AttachUsagePersistence(std::shared_ptr<UsagePersistence> Persistence,
            std::string Incarnation) -> std::expected<void, Failure>;

        /** @brief 应用完成正式发布后预热有限额度；停机时在会话退出后结清全部信用。 */
        [[nodiscard]] auto FlushUsage(const bool Final = false)
            -> Net::awaitable<std::expected<void, Failure>>;

        /** @brief 启动发布器后一次性接入 authority，并补挂启动准备期间创建的 runtime。 */
        [[nodiscard]] auto AttachAdmissionAuthority(
            const std::shared_ptr<Prism::Contract::AccountAdmissionAuthority> &Authority)
            -> std::expected<void, Failure>;

        [[nodiscard]] auto FindOrCreate(
            const Prism::AccountId Id,
            const std::uint32_t WorkerCount)
            -> std::expected<std::shared_ptr<AccountRuntime>, Failure>;

        [[nodiscard]] auto Revoke(const Prism::AccountId Id) noexcept
            -> std::expected<void, Failure>;

        /** @brief 手工撤销只通过 publication 的成员/墓碑 CAS 改变准入事实。 */
        [[nodiscard]] auto RevokeMany(
            const std::span<const Prism::AccountId> Ids) noexcept
            -> std::expected<void, Failure>;

        /** @brief Store seal 只关 authority；真实 session/socket drain 仍归 application owner。 */
        [[nodiscard]] auto RevokeAll() noexcept -> std::expected<void, Failure>;

        /** @brief 按单一 runtime owner 严格分配递增策略版本。 */
        [[nodiscard]] auto AllocatePolicyVersion() noexcept -> std::expected<PolicyVersion, Failure>;

        [[nodiscard]] auto IsRevoked(const Prism::AccountId Id) const noexcept -> bool;

    private:
        friend class AccountStore;
        /** @brief 在一个 registry 临界区内验证并冻结全部 runtime 键和预算绑定。 */
        [[nodiscard]] auto PrepareRuntimeBindings(
            std::span<const RuntimeBindingRequest> Bindings)
            -> std::expected<std::shared_ptr<RuntimeBindingTransaction>, Failure>;
        /** @brief 应用事务变更；只在已持有 registry 锁时调用。 */
        auto ApplyRuntimeBindings(RuntimeBindingTransaction &Transaction) -> void;
        /** @brief 恢复事务覆盖的键、预算与登记；只在已持有 registry 锁时调用。 */
        auto RestoreRuntimeBindingsLocked(RuntimeBindingTransaction &Transaction) noexcept
            -> void;
        /** @brief 复用已发布 runtime；没有则返回未注册候选，Prepare 失败不污染 registry。 */
        [[nodiscard]] auto ResolveForPreparation(
            Prism::AccountId Id,
            std::string_view StableKey,
            std::uint32_t WorkerCount)
            -> std::expected<std::shared_ptr<AccountRuntime>, Failure>;
        std::map<Prism::AccountId, std::weak_ptr<AccountRuntime>> Runtimes_;
        std::weak_ptr<Prism::Contract::AccountAdmissionAuthority> Authority_;
        std::shared_ptr<PolicySource> PolicySource_;
        std::shared_ptr<UsagePersistence> Persistence_;
        std::string Incarnation_;
        std::atomic<std::uint64_t> NextPolicyVersion_{1U};
        std::atomic_flag Mutation_ = ATOMIC_FLAG_INIT;
        bool Closed_{false};
    };

} // namespace Prism::Account
