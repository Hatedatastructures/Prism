/** @file Store.hpp
 * @brief process 唯一账户store，冷准备/单次提交完整Binding与全部credential索引。
 */
#pragma once
#include <Prism/Account/Failure.hpp>
#include <Prism/Account/Index.hpp>
#include <Prism/Account/RuntimeRegistry.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
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

        /** @brief 将 runtime 变更连同认证快照交给唯一 generation 发布事务。 */
        [[nodiscard]] auto DetachRuntimeTransaction() noexcept
            -> std::shared_ptr<AccountRuntimeRegistry::RuntimeBindingTransaction>;

    private:
        friend class AccountStore;
        std::shared_ptr<Detail::AccountStoreState> Owner_;
        std::shared_ptr<const Detail::AccountSnapshot> Base_;
        std::shared_ptr<const Detail::AccountSnapshot> Next_;
        std::shared_ptr<AccountRuntimeRegistry::RuntimeBindingTransaction>
            RuntimeTransaction_;
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
            explicit Mutation(std::atomic_flag& Gate) noexcept;
            ~Mutation();
            [[nodiscard]] auto Acquired() const noexcept -> bool;

        private:
            std::atomic_flag& Gate_;
            bool Acquired_{false};
        };

    public:
        explicit AccountStore(StoreOptions Options = {});
        AccountStore(const AccountStore&) = delete;
        auto operator=(const AccountStore&) -> AccountStore& = delete;
        ~AccountStore();
        /** @brief 控制owner与Commit串行封止新认证，不替代I/O关闭；view保活state而不能绕过封止。 */
        auto Seal() noexcept -> void;
        [[nodiscard]] auto RuntimeRegistry() const noexcept -> const std::shared_ptr<AccountRuntimeRegistry>&;
        /** @brief 冷注册数值scope并冻结ordinal，热不再查scope名称。 */
        [[nodiscard]] auto CompileScope(const CredentialScope Scope)
            -> std::expected<CredentialIndexView, Failure>;
        /** @brief 准备单账户替换，完整材料集替换该AccountId的全部scope。 */
        [[nodiscard]] auto PrepareUpsert(AccountDefinition Definition)
            -> std::expected<PreparedAccountUpdate, Failure>;
        /** @brief Reload完整账户集合准备，失败不部分发布；旧lease继续pin旧Binding。 */
        [[nodiscard]] auto PrepareReplacement(const std::span<const AccountDefinition> Definitions)
            -> std::expected<PreparedAccountUpdate, Failure>;
        [[nodiscard]] auto PrepareRemove(const Prism::AccountId Id)
            -> std::expected<PreparedAccountUpdate, Failure>;
        /** @brief 原子提交认证索引与 runtime 账本；generation 成员与撤销在 Publication CAS 中提交。 */
        [[nodiscard]] auto Commit(PreparedAccountUpdate& Update) -> std::expected<void, Failure>;
        /** @brief 只提交候选认证快照，然后由调用者在 publication gate 中提交 runtime。 */
        [[nodiscard]] auto CommitSnapshot(PreparedAccountUpdate &Update)
            -> std::expected<void, Failure>;
        /** @brief 为候选快照准备可回滚 runtime 事务；失败不改变 registry。 */
        [[nodiscard]] auto PrepareRuntimeTransaction(PreparedAccountUpdate &Update)
            -> std::expected<
                std::shared_ptr<AccountRuntimeRegistry::RuntimeBindingTransaction>, Failure>;
        [[nodiscard]] auto FindById(const Prism::AccountId Id) const noexcept
            -> std::shared_ptr<const AccountBinding>;
        [[nodiscard]] auto Revoke(const Prism::AccountId Id) const noexcept -> std::expected<void, Failure>;
        [[nodiscard]] auto Size() const noexcept -> std::size_t;
        /** @brief 返回此冻结 store 当前完整成员；只用于 generation publication 的冷 prepare。 */
        [[nodiscard]] auto AccountIds() const -> std::vector<Prism::AccountId>;
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
        [[nodiscard]] auto EnsureScope(const CredentialScope Scope) -> std::expected<std::size_t, Failure>;
        [[nodiscard]] auto RuntimeFor(const Prism::AccountId Id)
            -> std::expected<std::shared_ptr<AccountRuntime>, Failure>;
        [[nodiscard]] auto BuildBinding(AccountDefinition Definition,
            const std::shared_ptr<const Detail::AccountSnapshot>& Base)
            -> std::expected<std::shared_ptr<const AccountBinding>, Failure>;
        [[nodiscard]] auto FinishPrepared(const std::shared_ptr<const Detail::AccountSnapshot>& Base,
            std::shared_ptr<Detail::AccountSnapshot> Next) -> std::expected<PreparedAccountUpdate, Failure>;
        [[nodiscard]] static auto PrepareRuntimeTransactionUnlocked(
            const std::shared_ptr<AccountRuntimeRegistry> &RuntimeRegistry,
            PreparedAccountUpdate &Update)
            -> std::expected<
                std::shared_ptr<AccountRuntimeRegistry::RuntimeBindingTransaction>, Failure>;
        [[nodiscard]] auto CommitSnapshotLocked(PreparedAccountUpdate &Update)
            -> std::expected<void, Failure>;
        const StoreOptions Options_;
        std::shared_ptr<AccountRuntimeRegistry> RuntimeRegistry_;
        std::shared_ptr<Detail::AccountStoreState> State_;
        std::atomic_flag Mutation_ = ATOMIC_FLAG_INIT;
        std::vector<CredentialScope> Scopes_;
    };
} // namespace Prism::Account
