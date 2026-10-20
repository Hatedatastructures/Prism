/** @file SessionRegistry.cpp @brief registry 有界记录快照的 typed 更新入口。 */
#include <Prism/Runtime/SessionRegistry.hpp>
#include <Prism/Runtime/SessionRegistryRetirement.hpp>

#include <boost/asio/this_coro.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <memory>
#include <new>
#include <optional>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Runtime
{
    SessionRegistry::Registration::Registration(Registration&& Other) noexcept
        : State_(std::move(Other.State_)),
          Entry_(std::move(Other.Entry_)),
          Id_(Other.Id_),
          Active_(Other.Active_)
    {
        Other.Id_ = 0;
        Other.Active_ = false;
    }

    auto SessionRegistry::Registration::operator=(Registration&& Other) noexcept
        -> Registration&
    {
        if (this != &Other)
        {
            Reset();
            State_ = std::move(Other.State_);
            Entry_ = std::move(Other.Entry_);
            Id_ = Other.Id_;
            Active_ = Other.Active_;
            Other.Id_ = 0;
            Other.Active_ = false;
        }
        return *this;
    }

    SessionRegistry::Registration::~Registration()
    {
        Reset();
    }

    auto SessionRegistry::Registration::Reset() noexcept -> void
    {
        if (!Active_ || !State_)
        {
            return;
        }
        Active_ = false;
        SessionRegistry::Storage::RetireRecord(Entry_);
        Detail::SessionRegistryRetirement::AcknowledgeRetirement(Entry_);
        State_.reset();
        Entry_.reset();
        Id_ = 0;
    }

    auto SessionRegistry::Registration::Update(SessionInfo Info) -> bool
    {
        if (!Active_ || !State_ || Info.Id != Id_)
        {
            return false;
        }
        return SessionRegistry::Update(
            State_, Storage::UpdateRequest{Entry_, Id_, std::move(Info)});
    }

    SessionRegistry::Registration::Registration(
        std::shared_ptr<State> StateValue,
        const std::uint64_t Id,
        std::shared_ptr<EntryState> EntryValue) noexcept
        : State_(std::move(StateValue)),
          Entry_(std::move(EntryValue)),
          Id_(Id),
          Active_(true)
    {
    }

    SessionRegistry::SessionRegistry()
        : State_(std::make_shared<State>()), StreamCatalog_(State_)
    {
    }

    auto SessionRegistry::SetErrorHook(ErrorHook Hook) -> void
    {
        State_->OnError = std::move(Hook);
    }

    auto SessionRegistry::SetMetricsHook(MetricsHook Hook) -> void
    {
        State_->OnMetrics = std::move(Hook);
    }

    auto SessionRegistry::Update(const std::shared_ptr<State>& StateValue,
        Storage::UpdateRequest Request) -> bool
    {
        return Storage::Update(StateValue, std::move(Request));
    }

    auto SessionRegistry::Register(SessionInfo Info,
        std::shared_ptr<SessionControl> Control) -> Registration
    {
        if (!Control || Storage::AccountRegistrationDenied(State_, Info)) return {};

        const auto Id = Info.Id;
        const auto Executor = Control->Executor();
        if (!Executor) return {};
        const auto Entry = std::make_shared<EntryState>(Control, *Executor);
        while (true)
        {
            if (Storage::AccountRegistrationDenied(State_, Info)) return {};
            auto Current = State_->Records.load(std::memory_order_seq_cst);
            const auto Existing = Current->find(Id);
            if (Existing != Current->end() &&
                !Existing->second.Entry->Removed.load(std::memory_order_seq_cst))
                return {};
            auto Next = Storage::CopyActive(*Current);
            Next->emplace(Id, Record{Info, Entry});
            std::shared_ptr<const RecordMap> Published(std::move(Next));
            if (State_->Records.compare_exchange_weak(Current, Published, std::memory_order_seq_cst))
            {
                const auto Rollback = [&]() noexcept
                {
                    Storage::RetireRecord(Entry);
                    Detail::SessionRegistryRetirement::AcknowledgeRejectedRegistration(Entry);
                    try { Storage::TryCompact(State_); } catch (...) {}
                };
                try
                {
                    if (Storage::AccountRegistrationDenied(State_, Info))
                    {
                        Rollback();
                        return {};
                    }
                    const auto Installed = Storage::InstallHooks(State_, Id, Entry);
                    if (!Installed || Storage::AccountRegistrationDenied(State_, Info))
                    {
                        Rollback();
                        return {};
                    }
                    Entry->RegistrationPublished.store(true, std::memory_order_release);
                    return Registration(State_, Id, Entry);
                }
                catch (...)
                {
                    Rollback();
                    return {};
                }
            }
        }
    }

    auto SessionRegistry::Remove(const std::uint64_t Id) -> bool
    {
        const auto Current = State_->Records.load(std::memory_order_acquire);
        const auto It = Current->find(Id);
        return It != Current->end() && Storage::RetireRecord(It->second.Entry);
    }

    auto SessionRegistry::Cancel(const std::uint64_t Id) -> bool
    {
        const auto Current = State_->Records.load(std::memory_order_acquire);
        const auto It = Current->find(Id);
        if (It == Current->end()) return false;
        const auto Control = Storage::GetActiveControl(It->second.Entry);
        if (!Control) return false;
        Control->Cancel();
        return true;
    }

    auto SessionRegistry::CancelAndDrain(const std::uint64_t Id)
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await boost::asio::this_coro::throw_if_cancelled(false);
        const auto Current = State_->Records.load(std::memory_order_acquire);
        const auto It = Current->find(Id);
        if (It == Current->end())
            co_return std::expected<void, Prism::Fault::Failure>{};
        const auto Control = Storage::GetActiveControl(It->second.Entry);
        if (!Control)
        {
            if (It->second.Entry->Removed.load(std::memory_order_acquire))
                co_return co_await Detail::SessionRegistryRetirement::AwaitRetirement(It->second.Entry);
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        const auto Cancelled = Control->Cancel();
        const auto Drained = co_await Control->Drain();
        if (!Cancelled) co_return std::unexpected(Cancelled.error());
        if (!Drained) co_return std::unexpected(Drained.error());
        co_return co_await Detail::SessionRegistryRetirement::AwaitRetirement(It->second.Entry);
    }

    auto SessionRegistry::CancelAccountAndDrain(
        const Prism::AccountId Account,
        const Prism::Account::AccountRuntimeIdentity Runtime)
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        return Detail::SessionRegistryAccountRetirement::CancelAndDrain(State_, Account, Runtime);
    }

    auto SessionRegistry::ReleaseAccountRuntimeGate(
        const Prism::AccountId Account,
        const Prism::Account::AccountRuntimeIdentity Runtime)
        -> std::expected<void, Prism::Fault::Failure>
    {
        return Detail::SessionRegistryAccountRetirement::ReleaseGate(State_, Account, Runtime);
    }

    auto SessionRegistry::CancelAll() -> std::size_t
    {
        std::size_t Count = 0;
        const auto Current = State_->Records.load(std::memory_order_acquire);
        for (const auto& [Id, RecordValue] : *Current)
        {
            (void)Id;
            if (const auto Control = Storage::GetActiveControl(RecordValue.Entry))
            {
                Control->Cancel();
                ++Count;
            }
        }
        return Count;
    }

    auto SessionRegistry::BeginShutdown() noexcept -> void
    {
        State_->ShuttingDown.store(true, std::memory_order_seq_cst);
    }

    auto SessionRegistry::RequestShutdown() noexcept -> void
    {
        BeginShutdown();
        const auto Current = State_->Records.load(std::memory_order_seq_cst);
        for (const auto& [Id, RecordValue] : *Current)
        {
            (void)Id;
            if (const auto Control = Storage::GetActiveControl(RecordValue.Entry))
            {
                try
                {
                    (void)Control->CancelForShutdown();
                }
                catch (...)
                {
                }
            }
        }
    }

    auto SessionRegistry::Find(const std::uint64_t Id, SessionInfo& Out) const -> bool
    {
        const auto Current = State_->Records.load(std::memory_order_acquire);
        const auto It = Current->find(Id);
        if (It == Current->end() || It->second.Entry->Removed.load(std::memory_order_seq_cst))
            return false;
        Out = It->second.Info;
        return true;
    }

    auto SessionRegistry::FindStream(
        const Prism::Contract::Ingress::StreamIdentity& Identity) const noexcept
        -> Prism::Contract::Ingress::StreamCatalogLookup
    {
        return StreamCatalog_.Find(Identity);
    }

    auto SessionRegistry::ListStreams(
        const Prism::Contract::Ingress::StreamListRequest& Request) const
        -> Prism::Contract::Ingress::StreamCatalogPage
    {
        return StreamCatalog_.List(Request);
    }

    auto SessionRegistry::ResetStreamAndDrain(
        Prism::Contract::Ingress::StreamResetRequest Request)
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        return StreamCatalog_.ResetAndDrain(std::move(Request));
    }

    auto SessionRegistry::Size() const -> std::size_t
    {
        std::size_t Count = 0;
        const auto Current = State_->Records.load(std::memory_order_acquire);
        for (const auto& [Id, RecordValue] : *Current)
        {
            (void)Id;
            if (!RecordValue.Entry->Removed.load(std::memory_order_seq_cst)) ++Count;
        }
        return Count;
    }

    auto SessionRegistry::PendingRemovals() const noexcept -> std::size_t
    {
        std::size_t Count = 0;
        const auto Current = State_->Records.load(std::memory_order_acquire);
        for (const auto& [Id, RecordValue] : *Current)
        {
            (void)Id;
            if (RecordValue.Entry->Removed.load(std::memory_order_seq_cst)) ++Count;
        }
        return Count;
    }

    auto SessionRegistry::Snapshot() const -> std::shared_ptr<const MapT>
    {
        auto Result = std::make_shared<MapT>();
        const auto Current = State_->Records.load(std::memory_order_acquire);
        for (const auto& [Id, RecordValue] : *Current)
        {
            if (!RecordValue.Entry->Removed.load(std::memory_order_seq_cst))
                Result->emplace(Id, RecordValue.Info);
        }
        return Result;
    }

    auto SessionRegistry::Drain()
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await boost::asio::this_coro::throw_if_cancelled(false);
        const auto Current = State_->Records.load(std::memory_order_acquire);
        for (const auto& [Id, RecordValue] : *Current)
        {
            (void)Id;
            if (auto Control = Storage::GetActiveControl(RecordValue.Entry))
            {
                auto Result = co_await Control->Drain();
                if (!Result) co_return Result;
            }
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto SessionRegistry::Shutdown()
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await boost::asio::this_coro::throw_if_cancelled(false);
        BeginShutdown();
        const auto Current = State_->Records.load(std::memory_order_acquire);
        for (const auto& [Id, RecordValue] : *Current)
        {
            (void)Id;
            if (auto Control = Storage::GetActiveControl(RecordValue.Entry))
                (void)Control->CancelForShutdown();
        }
        auto Result = co_await Drain();
        if (!Result) co_return Result;
        Storage::ClearRecords(State_);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }
}

namespace Prism::Runtime::Detail
{
    auto SessionRegistryRetirement::AcknowledgeRetirement(
        const std::shared_ptr<SessionRegistryEntry>& Entry) noexcept -> void
    {
        if (!Entry || !Entry->RegistrationPublished.load(std::memory_order_acquire))
        {
            return;
        }
        PublishRetirementReceipt(Entry);
    }

    auto SessionRegistryRetirement::AcknowledgeRejectedRegistration(
        const std::shared_ptr<SessionRegistryEntry>& Entry) noexcept -> void
    {
        if (!Entry || Entry->RegistrationPublished.load(std::memory_order_acquire))
        {
            return;
        }
        PublishRetirementReceipt(Entry);
    }

    auto SessionRegistryStorage::CopyActive(const SessionRegistryRecordMap& Records)
        -> std::shared_ptr<SessionRegistryRecordMap>
    {
        auto Result = std::make_shared<SessionRegistryRecordMap>();
        for (const auto& [Id, RecordValue] : Records)
        {
            if (!RecordValue.Entry->Removed.load(std::memory_order_seq_cst))
            {
                Result->emplace(Id, RecordValue);
            }
        }
        return Result;
    }

    auto SessionRegistryStorage::GetActiveControl(
        const std::shared_ptr<SessionRegistryEntry>& Entry) -> std::shared_ptr<SessionControl>
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

    auto SessionRegistryStorage::IsAccountRuntimeDenied(
        const std::shared_ptr<SessionRegistryState>& StateValue,
        const std::uint64_t Account,
        const Prism::Account::AccountRuntimeIdentity& Runtime) -> bool
    {
        const auto Denied = StateValue->DeniedAccountRuntimes.load(std::memory_order_seq_cst);
        return Denied->contains(AccountRuntimeKey{Account, Runtime});
    }

    auto SessionRegistryStorage::DenyAccountRuntime(
        const std::shared_ptr<SessionRegistryState>& StateValue,
        const std::uint64_t Account,
        const Prism::Account::AccountRuntimeIdentity& Runtime)
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (Account == 0U || !Runtime.IsValid())
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        try
        {
            const AccountRuntimeKey Key{Account, Runtime};
            while (true)
            {
                auto Current = StateValue->DeniedAccountRuntimes.load(std::memory_order_seq_cst);
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
        catch (const std::bad_alloc&)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        catch (const std::system_error& Error)
        {
            return std::unexpected(Prism::Fault::FromNative(Error.code()));
        }
        catch (...)
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
    }

    auto SessionRegistryStorage::RemoveAccountRuntimeDenial(
        const std::shared_ptr<SessionRegistryState>& StateValue,
        const std::uint64_t Account,
        const Prism::Account::AccountRuntimeIdentity& Runtime)
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (Account == 0U || !Runtime.IsValid())
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        try
        {
            const AccountRuntimeKey Key{Account, Runtime};
            while (true)
            {
                auto Current = StateValue->DeniedAccountRuntimes.load(std::memory_order_seq_cst);
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
        catch (const std::bad_alloc&)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        catch (const std::system_error& Error)
        {
            return std::unexpected(Prism::Fault::FromNative(Error.code()));
        }
        catch (...)
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
    }

    auto SessionRegistryStorage::RetireRecord(
        const std::shared_ptr<SessionRegistryEntry>& Entry) noexcept -> bool
    {
        if (!Entry || Entry->Removed.exchange(true, std::memory_order_seq_cst))
        {
            return false;
        }
        Entry->Control.store(std::shared_ptr<SessionControl>{}, std::memory_order_seq_cst);
        return true;
    }

    auto SessionRegistryStorage::AccountRegistrationDenied(
        const std::shared_ptr<SessionRegistryState>& StateValue,
        const SessionInfo& Info) -> bool
    {
        if (StateValue->ShuttingDown.load(std::memory_order_seq_cst))
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
        return IsAccountRuntimeDenied(StateValue, Info.AccountId.Value(), Info.AccountRuntime);
    }

    auto SessionRegistryStorage::TryCompact(
        const std::shared_ptr<SessionRegistryState>& StateValue) -> void
    {
        CompactRemoved(StateValue);
    }

    auto SessionRegistryStorage::ClearRecords(
        const std::shared_ptr<SessionRegistryState>& StateValue) -> void
    {
        while (true)
        {
            auto Current = StateValue->Records.load(std::memory_order_acquire);
            if (Current->empty())
            {
                return;
            }
            for (const auto& [Id, RecordValue] : *Current)
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

    auto SessionRegistryStorage::Update(
        const std::shared_ptr<SessionRegistryState>& StateValue,
        UpdateRequest Request) -> bool
    {
        const auto& Entry = Request.EntryValue;
        const auto Id = Request.Id;
        const auto& Info = Request.Info;
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
            auto& CurrentInfo = NextIt->second.Info;
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

    auto SessionRegistryStorage::InstallHooks(
        const std::shared_ptr<SessionRegistryState>& StateValue,
        const std::uint64_t Id,
        const std::shared_ptr<SessionRegistryEntry>& Entry)
        -> std::expected<void, Prism::Fault::Failure>
    {
        const std::weak_ptr<SessionRegistryState> WeakState = StateValue;
        const std::weak_ptr<SessionRegistryEntry> WeakEntry = Entry;
        const auto Control = Entry->Control.load(std::memory_order_seq_cst);
        if (!Control)
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        const SessionRegistryHookContext Context{WeakState, WeakEntry, Id};
        Control->SetErrorHook([Context](Prism::Fault::Failure Failure)
            { DispatchError(Context, Failure); });
        auto Failures = StateValue->FailNextMetricsHookInstallation.load(
            std::memory_order_acquire);
        while (Failures != 0)
        {
            if (StateValue->FailNextMetricsHookInstallation.compare_exchange_weak(
                    Failures, Failures - 1, std::memory_order_acq_rel,
                    std::memory_order_acquire))
            {
                return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
            }
        }
        Control->SetMetricsHook([Context](const SessionMetrics& Metrics)
            { DispatchMetrics(Context, Metrics); });
        return {};
    }

    auto SessionRegistryStorage::DispatchError(
        const SessionRegistryHookContext& Context,
        Prism::Fault::Failure Failure) -> void
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

    auto SessionRegistryStorage::DispatchMetrics(
        const SessionRegistryHookContext& Context,
        const SessionMetrics& Metrics) -> void
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

    auto SessionRegistryStorage::ConsumeCompactionFailure(
        const std::shared_ptr<SessionRegistryState>& StateValue) -> bool
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

    auto SessionRegistryStorage::CompactRemoved(
        const std::shared_ptr<SessionRegistryState>& StateValue) -> void
    {
        while (true)
        {
            auto Current = StateValue->Records.load(std::memory_order_acquire);
            bool HasRemoved = false;
            for (const auto& [Id, RecordValue] : *Current)
            {
                (void)Id;
                HasRemoved = HasRemoved || RecordValue.Entry->Removed.load(std::memory_order_seq_cst);
            }
            if (!HasRemoved)
            {
                return;
            }
            if (ConsumeCompactionFailure(StateValue)) return;
            auto Next = CopyActive(*Current);
            std::shared_ptr<const SessionRegistryRecordMap> Published(std::move(Next));
            if (StateValue->Records.compare_exchange_weak(
                    Current, Published, std::memory_order_acq_rel, std::memory_order_acquire))
            {
                continue;
            }
        }
    }

    SessionRegistryEntry::RetirementWaiter::RetirementWaiter(
        boost::asio::any_io_executor ExecutorValue)
        : Signal(std::move(ExecutorValue), 1U)
    {
    }

    SessionRegistryEntry::SessionRegistryEntry(
        std::shared_ptr<SessionControl> ControlValue,
        boost::asio::any_io_executor ExecutorValue)
        : Control(std::move(ControlValue)), RetirementExecutor(std::move(ExecutorValue))
    {
    }

    auto SessionRegistryRetirement::AwaitRetirement(
        const std::shared_ptr<SessionRegistryEntry>& Entry)
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (!Entry)
        {
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        co_await boost::asio::this_coro::throw_if_cancelled(false);
        auto Result = RetirementResult(Entry);
        if (Result)
        {
            co_return Result;
        }
        if (Entry->RetirementFailure.Load().Failed())
        {
            co_return Result;
        }

        std::shared_ptr<SessionRegistryEntry::RetirementWaiter> Waiter;
        try
        {
            Waiter = std::make_shared<SessionRegistryEntry::RetirementWaiter>(
                Entry->RetirementExecutor);
        }
        catch (const std::bad_alloc&)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        catch (const boost::system::system_error& Error)
        {
            co_return std::unexpected(Prism::Fault::FromNative(
                static_cast<std::error_code>(Error.code())));
        }
        catch (const std::system_error& Error)
        {
            co_return std::unexpected(Prism::Fault::FromNative(Error.code()));
        }
        catch (...)
        {
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }

        while (!Entry->RetirementAcknowledged.load(std::memory_order_acquire))
        {
            auto Current = Entry->RetirementWaiters.load(std::memory_order_acquire);
            Waiter->Next = Current;
            if (Entry->RetirementWaiters.compare_exchange_weak(
                    Current, Waiter, std::memory_order_acq_rel, std::memory_order_acquire))
            {
                break;
            }
        }
        Result = RetirementResult(Entry);
        if (Result || Entry->RetirementFailure.Load().Failed())
        {
            co_return Result;
        }

        boost::system::error_code Error;
        co_await Waiter->Signal.async_receive(
            boost::asio::redirect_error(boost::asio::use_awaitable, Error));
        if (Error)
        {
            const auto Failure = Entry->RetirementFailure.Load();
            if (Failure.Failed())
            {
                co_return std::unexpected(Failure);
            }
            co_return std::unexpected(Prism::Fault::FromNative(
                static_cast<std::error_code>(Error)));
        }
        Result = RetirementResult(Entry);
        co_return Result;
    }

    auto SessionRegistryRetirement::PublishRetirementReceipt(
        const std::shared_ptr<SessionRegistryEntry>& Entry) noexcept -> void
    {
        if (Entry->RetirementAcknowledged.exchange(true, std::memory_order_acq_rel))
        {
            return;
        }
        auto Waiter = Entry->RetirementWaiters.exchange(
            std::shared_ptr<SessionRegistryEntry::RetirementWaiter>{},
            std::memory_order_acq_rel);
        while (Waiter)
        {
            auto Next = std::move(Waiter->Next);
            NotifyWaiter(Entry, Waiter);
            Waiter = std::move(Next);
        }
    }

    auto SessionRegistryRetirement::RetirementResult(
        const std::shared_ptr<SessionRegistryEntry>& Entry)
        -> std::expected<void, Prism::Fault::Failure>
    {
        const auto Failure = Entry->RetirementFailure.Load();
        if (Failure.Failed())
        {
            return std::unexpected(Failure);
        }
        if (Entry->RetirementAcknowledged.load(std::memory_order_acquire) &&
            Entry->Removed.load(std::memory_order_acquire))
        {
            return {};
        }
        return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
    }

    auto SessionRegistryRetirement::RecordFailure(
        const std::shared_ptr<SessionRegistryEntry>& Entry,
        Prism::Fault::Failure Failure) noexcept -> void
    {
        (void)Entry->RetirementFailure.TrySet(Failure);
    }

    auto SessionRegistryRetirement::NotifyWaiter(
        const std::shared_ptr<SessionRegistryEntry>& Entry,
        const std::shared_ptr<SessionRegistryEntry::RetirementWaiter>& Waiter) noexcept -> void
    {
        try
        {
            if (Waiter->Signal.try_send(boost::system::error_code{}))
            {
                return;
            }
            RecordFailure(Entry, Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            CloseWaiter(Entry, Waiter);
        }
        catch (const boost::system::system_error& Error)
        {
            RecordFailure(Entry, Prism::Fault::FromNative(
                static_cast<std::error_code>(Error.code())));
            CloseWaiter(Entry, Waiter);
        }
        catch (const std::system_error& Error)
        {
            RecordFailure(Entry, Prism::Fault::FromNative(Error.code()));
            CloseWaiter(Entry, Waiter);
        }
        catch (...)
        {
            RecordFailure(Entry, Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            CloseWaiter(Entry, Waiter);
        }
    }

    auto SessionRegistryRetirement::CloseWaiter(
        const std::shared_ptr<SessionRegistryEntry>& Entry,
        const std::shared_ptr<SessionRegistryEntry::RetirementWaiter>& Waiter) noexcept -> void
    {
        try
        {
            Waiter->Signal.close();
        }
        catch (const boost::system::system_error& Error)
        {
            RecordFailure(Entry, Prism::Fault::FromNative(
                static_cast<std::error_code>(Error.code())));
        }
        catch (const std::system_error& Error)
        {
            RecordFailure(Entry, Prism::Fault::FromNative(Error.code()));
        }
        catch (...)
        {
            RecordFailure(Entry, Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
    }

    auto SessionRegistryAccountRetirement::CancelAndDrain(
        std::shared_ptr<SessionRegistryState> State,
        const Prism::AccountId Account,
        const Prism::Account::AccountRuntimeIdentity Runtime)
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await boost::asio::this_coro::throw_if_cancelled(false);
        if (!Account || !Runtime.IsValid())
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        const auto Denied = SessionRegistryStorage::DenyAccountRuntime(
            State, Account.Value(), Runtime);
        if (!Denied)
        {
            co_return std::unexpected(Denied.error());
        }

        const auto Current = State->Records.load(std::memory_order_seq_cst);
        struct PendingOwner final
        {
            std::shared_ptr<SessionRegistryEntry> Entry;
            std::shared_ptr<SessionControl> Control;
        };
        std::vector<PendingOwner> Owners;
        std::optional<Prism::Fault::Failure> FirstFailure;
        for (const auto& [Id, RecordValue] : *Current)
        {
            (void)Id;
            if (RecordValue.Info.AccountId != Account ||
                RecordValue.Info.AccountRuntime != Runtime)
            {
                continue;
            }
            auto Control = SessionRegistryStorage::GetActiveControl(RecordValue.Entry);
            if (!Control && !RecordValue.Entry->Removed.load(std::memory_order_acquire))
            {
                if (!FirstFailure)
                {
                    FirstFailure = Prism::Fault::Failure{Prism::Fault::Code::Blocked};
                }
                continue;
            }
            Owners.push_back(PendingOwner{RecordValue.Entry, std::move(Control)});
        }

        for (const auto& Owner : Owners)
        {
            if (!Owner.Control)
            {
                continue;
            }
            const auto Cancelled = Owner.Control->Cancel();
            if (!Cancelled && !FirstFailure)
            {
                FirstFailure = Cancelled.error();
            }
        }
        for (const auto& Owner : Owners)
        {
            if (!Owner.Control)
            {
                continue;
            }
            const auto Drained = co_await Owner.Control->Drain();
            if (!Drained && !FirstFailure)
            {
                FirstFailure = Drained.error();
            }
        }
        if (FirstFailure)
        {
            co_return std::unexpected(*FirstFailure);
        }
        for (const auto& Owner : Owners)
        {
            const auto Retired = co_await SessionRegistryRetirement::AwaitRetirement(Owner.Entry);
            if (!Retired && !FirstFailure)
            {
                FirstFailure = Retired.error();
            }
        }
        if (FirstFailure)
        {
            co_return std::unexpected(*FirstFailure);
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto SessionRegistryAccountRetirement::ReleaseGate(
        const std::shared_ptr<SessionRegistryState>& State,
        const Prism::AccountId Account,
        const Prism::Account::AccountRuntimeIdentity Runtime)
        -> std::expected<void, Prism::Fault::Failure>
    {
        return SessionRegistryStorage::RemoveAccountRuntimeDenial(
            State, Account.Value(), Runtime);
    }

    auto SessionRegistryStreamCatalog::Find(
        const Prism::Contract::Ingress::StreamIdentity& Identity) const noexcept
        -> Prism::Contract::Ingress::StreamCatalogLookup
    {
        using Lookup = Prism::Contract::Ingress::StreamCatalogLookup;
        using Status = Prism::Contract::Ingress::StreamCatalogStatus;
        const auto NotFound = Lookup{Status::NotFound, {}};
        if (!Identity.Session || !Identity.Id) return NotFound;
        const auto Current = State_->Records.load(std::memory_order_acquire);
        const auto It = Current->find(Identity.Session.Value());
        if (It == Current->end() || It->second.Entry->Removed.load(std::memory_order_seq_cst))
            return NotFound;
        const auto& RecordValue = It->second;
        if (RecordValue.Info.Worker != Identity.Worker ||
            RecordValue.Info.Generation != Identity.Generation) return NotFound;
        const auto Control = Storage::GetActiveControl(RecordValue.Entry);
        if (!Control)
        {
            auto Result = Status::CapabilityUnavailable;
            if (RecordValue.Entry->Removed.load(std::memory_order_seq_cst)) Result = Status::NotFound;
            return {Result, {}};
        }
        const auto Parent = Control->CurrentIdentity();
        if (Parent.SessionId != Identity.Session || Parent.WorkerId != Identity.Worker ||
            Parent.Generation != Identity.Generation) return NotFound;
        const auto Snapshot = Control->FindStream(Identity);
        if (RecordValue.Entry->Removed.load(std::memory_order_seq_cst)) return NotFound;
        return Snapshot;
    }

    auto SessionRegistryStreamCatalog::List(
        const Prism::Contract::Ingress::StreamListRequest& Request) const
        -> Prism::Contract::Ingress::StreamCatalogPage
    {
        using Status = Prism::Contract::Ingress::StreamCatalogStatus;
        if (!Request.Parent.Session || !Request.Parent.Worker || !Request.Parent.Generation)
        {
            return {Status::NotFound, {}, Request.Cursor, false};
        }
        const auto Current = State_->Records.load(std::memory_order_acquire);
        const auto It = Current->find(Request.Parent.Session.Value());
        if (It == Current->end() || It->second.Entry->Removed.load(std::memory_order_seq_cst) ||
            It->second.Info.Worker != Request.Parent.Worker ||
            It->second.Info.Generation != Request.Parent.Generation)
        {
            return {Status::NotFound, {}, Request.Cursor, false};
        }
        const auto Control = Storage::GetActiveControl(It->second.Entry);
        if (!Control)
        {
            return {Status::CapabilityUnavailable, {}, Request.Cursor, false};
        }
        auto Result = Control->ListStreams(Request);
        if (It->second.Entry->Removed.load(std::memory_order_seq_cst))
        {
            return {Status::NotFound, {}, Request.Cursor, false};
        }
        return Result;
    }

    auto SessionRegistryStreamCatalog::RunReset(
        std::shared_ptr<State> StateValue,
        Prism::Contract::Ingress::StreamResetRequest Request)
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        using Failure = Prism::Fault::Failure;
        if (!Request.Identity.Session || !Request.Identity.Worker ||
            !Request.Identity.Generation || !Request.Identity.Id ||
            !Request.Task || !Request.ParentTask)
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        }
        const auto Current = StateValue->Records.load(std::memory_order_acquire);
        const auto It = Current->find(Request.Identity.Session.Value());
        if (It == Current->end() || It->second.Entry->Removed.load(std::memory_order_seq_cst))
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        const auto& RecordValue = It->second;
        if (RecordValue.Info.Worker != Request.Identity.Worker ||
            RecordValue.Info.Generation != Request.Identity.Generation)
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        const auto Control = Storage::GetActiveControl(RecordValue.Entry);
        if (!Control)
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
        const auto Parent = Control->CurrentIdentity();
        if (Parent.SessionId != Request.Identity.Session ||
            Parent.WorkerId != Request.Identity.Worker ||
            Parent.Generation != Request.Identity.Generation ||
            Parent.TaskId != Request.ParentTask)
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        co_return co_await Control->ResetStreamAndDrain(std::move(Request));
    }
}
