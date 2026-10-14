/**
 * @file SessionRegistryStorage.hpp
 * @brief SessionRegistry 的快照存储、逻辑删除和 hook 投递 owner。
 * @details 该 owner 不暴露注册表 API，只操作注册表生命周期所需的 typed
 *          状态。CAS 发布、删除压实和 callback 隔离集中在这里，避免
 *          SessionRegistry 同时承担值查询与底层快照维护。
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <new>
#include <set>
#include <system_error>
#include <utility>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Runtime/SessionRegistryRetirement.hpp>
#include <Preview/Runtime/SessionControl.hpp>
#include <Preview/Runtime/SessionRegistryModel.hpp>

namespace Preview::Runtime::Detail
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
        Preview::Account::AccountRuntimeIdentity Runtime{};

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
        std::function<void(std::uint64_t, Preview::Fault::Failure)> OnError;
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
            -> std::shared_ptr<SessionRegistryRecordMap>
        {
            auto Result = std::make_shared<SessionRegistryRecordMap>();
            for (const auto &[Id, RecordValue] : Records)
            {
                if (!RecordValue.Entry->Removed.load(std::memory_order_seq_cst))
                {
                    Result->emplace(Id, RecordValue);
                }
            }
            return Result;
        }

        [[nodiscard]] static auto GetActiveControl(
            const std::shared_ptr<SessionRegistryEntry> &Entry)
            -> std::shared_ptr<SessionControl>
        {
            if (!Entry || Entry->Removed.load(std::memory_order_seq_cst))
            {
                return {};
            }
            auto Control = Entry->Control.load(std::memory_order_seq_cst);
            if (!Control || Entry->Removed.load(std::memory_order_seq_cst))
            {
                return {};
            }
            return Control;
        }

        [[nodiscard]] static auto IsAccountRuntimeDenied(
            const std::shared_ptr<SessionRegistryState> &StateValue,
            const std::uint64_t Account,
            const Preview::Account::AccountRuntimeIdentity &Runtime) -> bool
        {
            const auto Denied = StateValue->DeniedAccountRuntimes.load(std::memory_order_seq_cst);
            return Denied->contains(AccountRuntimeKey{Account, Runtime});
        }

        [[nodiscard]] static auto DenyAccountRuntime(
            const std::shared_ptr<SessionRegistryState> &StateValue,
            const std::uint64_t Account,
            const Preview::Account::AccountRuntimeIdentity &Runtime)
            -> std::expected<void, Preview::Fault::Failure>
        {
            if (Account == 0U || !Runtime.IsValid())
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            try
            {
                const AccountRuntimeKey Key{Account, Runtime};
                while (true)
                {
                    auto Current = StateValue->DeniedAccountRuntimes.load(
                        std::memory_order_seq_cst);
                    if (Current->contains(Key))
                    {
                        return {};
                    }
                    auto Next = std::make_shared<DeniedAccountRuntimeSet>(*Current);
                    Next->insert(Key);
                    std::shared_ptr<const DeniedAccountRuntimeSet> Published(std::move(Next));
                    if (StateValue->DeniedAccountRuntimes.compare_exchange_weak(
                            Current, Published, std::memory_order_seq_cst))
                    {
                        return {};
                    }
                }
            }
            catch (const std::bad_alloc &)
            {
                return std::unexpected(Preview::Fault::Failure{
                    Preview::Fault::Code::ResourceUnavailable});
            }
            catch (const std::system_error &Error)
            {
                return std::unexpected(Preview::Fault::FromNative(Error.code()));
            }
            catch (...)
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
        }
        [[nodiscard]] static auto RemoveAccountRuntimeDenial(
            const std::shared_ptr<SessionRegistryState> &StateValue,
            const std::uint64_t Account,
            const Preview::Account::AccountRuntimeIdentity &Runtime)
            -> std::expected<void, Preview::Fault::Failure>
        {
            if (Account == 0U || !Runtime.IsValid())
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            try
            {
                const AccountRuntimeKey Key{Account, Runtime};
                while (true)
                {
                    auto Current = StateValue->DeniedAccountRuntimes.load(
                        std::memory_order_seq_cst);
                    if (!Current->contains(Key))
                    {
                        return {};
                    }
                    auto Next = std::make_shared<DeniedAccountRuntimeSet>(*Current);
                    Next->erase(Key);
                    std::shared_ptr<const DeniedAccountRuntimeSet> Published(std::move(Next));
                    if (StateValue->DeniedAccountRuntimes.compare_exchange_weak(
                            Current, Published, std::memory_order_seq_cst))
                    {
                        return {};
                    }
                }
            }
            catch (const std::bad_alloc &)
            {
                return std::unexpected(Preview::Fault::Failure{
                    Preview::Fault::Code::ResourceUnavailable});
            }
            catch (const std::system_error &Error)
            {
                return std::unexpected(Preview::Fault::FromNative(Error.code()));
            }
            catch (...)
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
        }
        static auto RetireRecord(const std::shared_ptr<SessionRegistryEntry> &Entry) noexcept
            -> bool
        {
            if (!Entry || Entry->Removed.exchange(true, std::memory_order_seq_cst))
            {
                return false;
            }
            Entry->Control.store(std::shared_ptr<SessionControl>{}, std::memory_order_seq_cst);
            return true;
        }

        [[nodiscard]] static auto AccountRegistrationDenied(
            const std::shared_ptr<SessionRegistryState> &StateValue,
            const SessionInfo &Info) -> bool
        {
            if (StateValue->ShuttingDown.load(std::memory_order_acquire))
            {
                return true;
            }
            if (!Info.AccountId)
            {
                return Info.AccountRuntime.IsValid();
            }
            if (!Info.AccountRuntime.IsValid())
            {
                return true;
            }
            return IsAccountRuntimeDenied(
                StateValue, Info.AccountId.Value(), Info.AccountRuntime);
        }
        /** @brief 非析构边界压实快照；普通注入拒绝保持已移除记录的逻辑事实。 */
        static auto TryCompact(const std::shared_ptr<SessionRegistryState> &StateValue) -> void
        {
            CompactRemoved(StateValue);
        }

        static auto ClearRecords(const std::shared_ptr<SessionRegistryState> &StateValue) -> void
        {
            while (true)
            {
                auto Current = StateValue->Records.load(std::memory_order_acquire);
                if (Current->empty())
                {
                    return;
                }
                for (const auto &[Id, RecordValue] : *Current)
                {
                    (void)Id;
                    RecordValue.Entry->Removed.store(true, std::memory_order_seq_cst);
                    RecordValue.Entry->Control.store(
                        std::shared_ptr<SessionControl>{}, std::memory_order_seq_cst);
                }
                auto Empty = std::make_shared<const SessionRegistryRecordMap>();
                if (StateValue->Records.compare_exchange_weak(
                        Current, Empty, std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    return;
                }
            }
        }

        /**
         * @brief 使用同一 registration entry 原子发布 admission 后的完整值更新。
         * @details CAS 前后验证账户与 Runtime owner identity。CAS 与撤销门采用顺序一致
         *          次序，拒绝在门前发布的竞态更新会逻辑退休并由 admission 返回取消；
         *          accountless session 必须同时没有 AccountId 和 Runtime identity。
         */
        [[nodiscard]] static auto Update(
            const std::shared_ptr<SessionRegistryState> &StateValue,
            UpdateRequest Request) -> bool
        {
            const auto &Entry = Request.EntryValue;
            const auto Id = Request.Id;
            const auto &Info = Request.Info;
            if (!Entry || Entry->Removed.load(std::memory_order_seq_cst) || Info.Id != Id)
            {
                return false;
            }
            while (true)
            {
                if (AccountRegistrationDenied(StateValue, Info))
                {
                    return false;
                }
                auto Current = StateValue->Records.load(std::memory_order_seq_cst);
                const auto It = Current->find(Id);
                if (It == Current->end() || It->second.Entry != Entry ||
                    Entry->Removed.load(std::memory_order_seq_cst))
                {
                    return false;
                }
                if (It->second.Info.Generation != Info.Generation ||
                    It->second.Info.Worker != Info.Worker)
                {
                    return false;
                }
                auto Next = CopyActive(*Current);
                const auto NextIt = Next->find(Id);
                if (NextIt == Next->end())
                {
                    return false;
                }
                auto &CurrentInfo = NextIt->second.Info;
                CurrentInfo.AccountId = Info.AccountId;
                CurrentInfo.AccountRuntime = Info.AccountRuntime;
                CurrentInfo.identity = Info.identity;
                CurrentInfo.peer = Info.peer;
                CurrentInfo.Target = Info.Target;
                CurrentInfo.Protocol = Info.Protocol;
                std::shared_ptr<const SessionRegistryRecordMap> Published(std::move(Next));
                if (StateValue->Records.compare_exchange_weak(
                        Current, Published, std::memory_order_seq_cst))
                {
                    if (AccountRegistrationDenied(StateValue, Info))
                    {
                        RetireRecord(Entry);
                        return false;
                    }
                    return true;
                }
            }
        }
        static auto InstallHooks(const std::shared_ptr<SessionRegistryState> &StateValue,
                                 std::uint64_t Id,
                                 const std::shared_ptr<SessionRegistryEntry> &Entry) -> std::expected<void, Preview::Fault::Failure>
        {
            const std::weak_ptr<SessionRegistryState> WeakState = StateValue;
            const std::weak_ptr<SessionRegistryEntry> WeakEntry = Entry;
            const auto Control = Entry->Control.load(std::memory_order_seq_cst);
            if (!Control)
            {
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            const SessionRegistryHookContext Context{WeakState, WeakEntry, Id};
            Control->SetErrorHook([Context](Preview::Fault::Failure Failure)
                                  { DispatchError(Context, Failure); });
            auto Failures = StateValue->FailNextMetricsHookInstallation.load(
                std::memory_order_acquire);
            while (Failures != 0)
            {
                if (StateValue->FailNextMetricsHookInstallation.compare_exchange_weak(
                        Failures, Failures - 1, std::memory_order_acq_rel,
                        std::memory_order_acquire))
                {
                    return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::ResourceUnavailable});
                }
            }
            Control->SetMetricsHook([Context](const SessionMetrics &Metrics)
                                    { DispatchMetrics(Context, Metrics); });
            return {};
        }

        static auto DispatchError(const SessionRegistryHookContext &Context,
                                   Preview::Fault::Failure Failure) -> void
        {
            const auto Entry = Context.EntryValue.lock();
            if (!Entry || Entry->Removed.load(std::memory_order_seq_cst))
            {
                return;
            }
            if (const auto StateValue = Context.StateValue.lock();
                StateValue && StateValue->OnError)
            {
                StateValue->OnError(Context.Id, Failure);
            }
        }

        static auto DispatchMetrics(const SessionRegistryHookContext &Context,
                                    const SessionMetrics &Metrics) -> void
        {
            const auto Entry = Context.EntryValue.lock();
            if (!Entry || Entry->Removed.load(std::memory_order_seq_cst))
            {
                return;
            }
            if (const auto StateValue = Context.StateValue.lock();
                StateValue && StateValue->OnMetrics)
            {
                StateValue->OnMetrics(Context.Id, Metrics);
            }
        }

    private:
        static auto ConsumeCompactionFailure(
            const std::shared_ptr<SessionRegistryState> &StateValue) -> bool
        {
            auto Failures = StateValue->FailNextRemovalCompaction.load(std::memory_order_acquire);
            while (Failures != 0)
            {
                if (StateValue->FailNextRemovalCompaction.compare_exchange_weak(
                        Failures, Failures - 1, std::memory_order_acq_rel,
                        std::memory_order_acquire))
                {
                    return true;
                }
            }
            return false;
        }

        static auto CompactRemoved(const std::shared_ptr<SessionRegistryState> &StateValue) -> void
        {
            while (true)
            {
                auto Current = StateValue->Records.load(std::memory_order_acquire);
                bool HasRemoved = false;
                for (const auto &[Id, RecordValue] : *Current)
                {
                    (void)Id;
                    HasRemoved = HasRemoved ||
                                 RecordValue.Entry->Removed.load(std::memory_order_seq_cst);
                }
                if (!HasRemoved)
                {
                    return;
                }

                if (ConsumeCompactionFailure(StateValue)) return;
                auto Next = CopyActive(*Current);
                std::shared_ptr<const SessionRegistryRecordMap> Published(std::move(Next));
                if (StateValue->Records.compare_exchange_weak(
                        Current, Published, std::memory_order_acq_rel,
                        std::memory_order_acquire))
                {
                    continue;
                }
            }
        }
    };

} // namespace Preview::Runtime::Detail

