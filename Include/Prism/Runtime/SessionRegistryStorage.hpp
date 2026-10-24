/**
 * @file SessionRegistryStorage.hpp
 * @brief SessionRegistry 的快照存储、逻辑删除和 hook 投递 owner。
 * @details 该 owner 不暴露注册表 API，只操作注册表生命周期所需的 typed
 *          状态。CAS 发布、删除压实和 callback 隔离集中在这里，避免
 *          SessionRegistry 同时承担值查询与底层快照维护。
 */

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <set>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Runtime/SessionRegistryRetirement.hpp>
#include <Prism/Runtime/SessionControl.hpp>
#include <Prism/Runtime/SessionRegistryModel.hpp>

namespace Prism::Runtime::Detail
{

    struct SessionRegistryRecord final
    {
        SessionInfo Info;
        std::shared_ptr<SessionRegistryEntry> Entry;
    };

    using SessionRegistryRecordMap = std::map<std::uint64_t, SessionRegistryRecord>;

    struct AccountRuntimeKey final
    {
        std::uint64_t Account{0};
        Prism::Account::AccountRuntimeIdentity Runtime{};

        friend auto operator<(const AccountRuntimeKey &Left,
                             const AccountRuntimeKey &Right) noexcept -> bool
        {
            if (Left.Account != Right.Account)
            {
                return Left.Account < Right.Account;
            }
            return Left.Runtime < Right.Runtime;
        }
    };

    using DeniedAccountRuntimeSet = std::set<AccountRuntimeKey>;

    struct SessionRegistryState final
    {
        std::atomic<std::shared_ptr<const SessionRegistryRecordMap>> Records{
            std::make_shared<const SessionRegistryRecordMap>()};
        std::atomic<std::shared_ptr<const DeniedAccountRuntimeSet>> DeniedAccountRuntimes{
            std::make_shared<const DeniedAccountRuntimeSet>()};
        std::atomic<bool> ShuttingDown{false};
        std::atomic<std::size_t> FailNextRemovalCompaction{0};
        std::atomic<std::size_t> FailNextMetricsHookInstallation{0};
        std::function<void(std::uint64_t, Prism::Fault::Failure)> OnError;
        std::function<void(std::uint64_t, const SessionMetrics &)> OnMetrics;
    };

    struct SessionRegistryHookContext final
    {
        std::weak_ptr<SessionRegistryState> StateValue;
        std::weak_ptr<SessionRegistryEntry> EntryValue;
        std::uint64_t Id{0};
    };

    class SessionRegistryStorage final
    {
    public:
        struct UpdateRequest final
        {
            std::shared_ptr<SessionRegistryEntry> EntryValue;
            std::uint64_t Id{0};
            SessionInfo Info;
        };

        [[nodiscard]] static auto CopyActive(const SessionRegistryRecordMap &Records)
            -> std::shared_ptr<SessionRegistryRecordMap>;

        [[nodiscard]] static auto GetActiveControl(
            const std::shared_ptr<SessionRegistryEntry> &Entry)
            -> std::shared_ptr<SessionControl>;

        [[nodiscard]] static auto IsAccountRuntimeDenied(
            const std::shared_ptr<SessionRegistryState> &StateValue,
            const std::uint64_t Account,
            const Prism::Account::AccountRuntimeIdentity &Runtime) -> bool;

        [[nodiscard]] static auto DenyAccountRuntime(
            const std::shared_ptr<SessionRegistryState> &StateValue,
            const std::uint64_t Account,
            const Prism::Account::AccountRuntimeIdentity &Runtime)
            -> std::expected<void, Prism::Fault::Failure>;
        [[nodiscard]] static auto RemoveAccountRuntimeDenial(
            const std::shared_ptr<SessionRegistryState> &StateValue,
            const std::uint64_t Account,
            const Prism::Account::AccountRuntimeIdentity &Runtime)
            -> std::expected<void, Prism::Fault::Failure>;
        static auto RetireRecord(const std::shared_ptr<SessionRegistryEntry> &Entry) noexcept
            -> bool;

        [[nodiscard]] static auto AccountRegistrationDenied(
            const std::shared_ptr<SessionRegistryState> &StateValue,
            const SessionInfo &Info) -> bool;
        /** @brief 非析构边界压实快照；普通注入拒绝保持已移除记录的逻辑事实。 */
        static auto TryCompact(const std::shared_ptr<SessionRegistryState> &StateValue) -> void;

        static auto ClearRecords(const std::shared_ptr<SessionRegistryState> &StateValue) -> void;

        /**
         * @brief 使用同一 registration entry 原子发布 admission 后的完整值更新。
         * @details CAS 前后验证账户与 Runtime owner identity。CAS 与撤销门采用顺序一致
         *          次序，拒绝在门前发布的竞态更新会逻辑退休并由 admission 返回取消；
         *          accountless session 必须同时没有 AccountId 和 Runtime identity。
         */
        [[nodiscard]] static auto Update(
            const std::shared_ptr<SessionRegistryState> &StateValue,
            UpdateRequest Request) -> bool;
        static auto InstallHooks(const std::shared_ptr<SessionRegistryState> &StateValue,
                                 std::uint64_t Id,
                                 const std::shared_ptr<SessionRegistryEntry> &Entry)
            -> std::expected<void, Prism::Fault::Failure>;

        static auto DispatchError(const SessionRegistryHookContext &Context,
                                   Prism::Fault::Failure Failure) -> void;

        static auto DispatchMetrics(const SessionRegistryHookContext &Context,
                                    const SessionMetrics &Metrics) -> void;

    private:
        static auto ConsumeCompactionFailure(
            const std::shared_ptr<SessionRegistryState> &StateValue) -> bool;

        static auto CompactRemoved(const std::shared_ptr<SessionRegistryState> &StateValue) -> void;
    };

} // namespace Prism::Runtime::Detail
