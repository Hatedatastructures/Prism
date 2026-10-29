/** @file Control.cpp @brief 会话取消交付、观察与关闭边界。 */
#include <Prism/Runtime/Session/Control.hpp>

#include <boost/asio/this_coro.hpp>

#include <memory>
#include <new>
#include <stdexcept>
#include <utility>

namespace Prism::Runtime
{
    auto SessionControl::State::PublishIdentity(const Identity& Value) -> void
    {
        if (ParentIdentity.load()) return;
        auto Candidate = std::make_shared<const Identity>(Value);
        std::shared_ptr<const Identity> Empty;
        (void)ParentIdentity.compare_exchange_strong(Empty, std::move(Candidate));
    }

    SessionControl::SessionControl() : State_(std::make_shared<State>())
    {
    }

    SessionControl::SessionControl(Net::any_io_executor Executor) : SessionControl()
    {
        (void)Bind(std::move(Executor));
    }

    auto SessionControl::Bind(Net::any_io_executor Executor) -> bool
    {
        if (State_->Bound.load()) return false;
        return InstallBinding(std::make_shared<Registry>(std::move(Executor), FailureReporter()));
    }

    auto SessionControl::Bind(Net::any_io_executor, Registry& Parent) -> bool
    {
        if (State_->Bound.load()) return false;
        return InstallBinding(Parent.CreateChild(FailureReporter()));
    }

    auto SessionControl::SetErrorHook(ErrorHook Hook) -> void
    {
        const auto Injection = State_->ErrorHookFailureInjection.exchange(
            State::HookFailureInjection::None, std::memory_order_acq_rel);
        if (Injection == State::HookFailureInjection::RuntimeError)
            throw std::runtime_error("injected SessionControl error hook failure");
        if (Injection == State::HookFailureInjection::AllocationFailure)
            throw std::bad_alloc{};
        State_->OnError.store(std::make_shared<ErrorHook>(std::move(Hook)));
    }

    auto SessionControl::SetErrorHook(IdentityErrorHook Hook) -> void
    {
        State_->OnIdentityError.store(std::make_shared<IdentityErrorHook>(std::move(Hook)));
    }

    auto SessionControl::SetMetricsHook(MetricsHook Hook) -> void
    {
        const auto Injection = State_->MetricsHookFailureInjection.exchange(
            State::HookFailureInjection::None, std::memory_order_acq_rel);
        if (Injection == State::HookFailureInjection::RuntimeError)
            throw std::runtime_error("injected SessionControl metrics hook failure");
        if (Injection == State::HookFailureInjection::AllocationFailure)
            throw std::bad_alloc{};
        State_->OnMetrics.store(std::make_shared<MetricsHook>(std::move(Hook)));
    }

    auto SessionControl::AddCancelHook(CancelFn Hook) -> std::expected<void, Failure>
    {
        auto Bound = State_->Bound.load();
        if (!Bound || !Hook) return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        auto Entry = std::make_shared<Prepared>(Bound->Tasks->Reclaimer(),
            [Hook = std::move(Hook)]() -> std::expected<void, Failure> { Hook(); return {}; });
        auto Count = State_->HookCount.load();
        for (;;)
        {
            if (Count == State_->CancelHooks.size())
                return std::unexpected(Failure{Prism::Fault::Code::ResourceUnavailable});
            if (State_->HookCount.compare_exchange_weak(Count, Count + 1)) break;
        }
        State_->CancelHooks[Count].store(Entry);
        if (State_->CancelRequested.load()) return Entry->Submit();
        return {};
    }

    auto SessionControl::SetCloseAction(CloseFn Work) -> std::expected<void, Failure>
    {
        auto Bound = State_->Bound.load();
        if (!Bound || !Work) return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        auto Action = std::make_shared<Prepared>(Bound->Tasks->Reclaimer(), std::move(Work));
        std::shared_ptr<Prepared> Empty;
        if (!State_->CloseAction.compare_exchange_strong(Empty, Action))
            return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        return {};
    }

    auto SessionControl::SetIdentity(const Identity& Value) -> bool
    {
        if (auto Current = State_->ParentIdentity.load()) return Current->TaskId == Value.TaskId;
        auto Candidate = std::make_shared<const Identity>(Value);
        std::shared_ptr<const Identity> Empty;
        return State_->ParentIdentity.compare_exchange_strong(Empty, std::move(Candidate));
    }

    auto SessionControl::CancellationReason() const noexcept -> SessionCancellationReason
    {
        if (State_->ExplicitCancelRequested.load(std::memory_order_acquire))
            return SessionCancellationReason::Explicit;
        if (State_->ShutdownCancelRequested.load(std::memory_order_acquire))
            return SessionCancellationReason::Shutdown;
        return SessionCancellationReason::None;
    }

    auto SessionControl::IsCancelled() const noexcept -> bool
    {
        if (State_->CancelRequested.load()) return true;
        auto Bound = State_->Bound.load();
        return Bound && Bound->Tasks->Domain()->IsCancellationRequested();
    }

    auto SessionControl::AttachStreamCatalog(
        std::shared_ptr<Prism::Contract::Ingress::StreamCatalog> Value) noexcept -> bool
    {
        if (!Value || State_->Sealed.load(std::memory_order_acquire)) return false;
        std::shared_ptr<Prism::Contract::Ingress::StreamCatalog> Empty;
        return State_->StreamCatalogOwner.compare_exchange_strong(
            Empty, std::move(Value), std::memory_order_acq_rel);
    }

    auto SessionControl::FindStream(
        const Prism::Contract::Ingress::StreamIdentity& Identity) const noexcept
        -> Prism::Contract::Ingress::StreamCatalogLookup
    {
        const auto Catalog = State_->StreamCatalogOwner.load(std::memory_order_acquire);
        if (!Catalog)
            return {Prism::Contract::Ingress::StreamCatalogStatus::CapabilityUnavailable, {}};
        return Catalog->Find(Identity);
    }

    auto SessionControl::ListStreams(
        const Prism::Contract::Ingress::StreamListRequest& Request) const
        -> Prism::Contract::Ingress::StreamCatalogPage
    {
        const auto Parent = CurrentIdentity();
        if (Parent.SessionId != Request.Parent.Session || Parent.WorkerId != Request.Parent.Worker ||
            Parent.Generation != Request.Parent.Generation)
        {
            return {Prism::Contract::Ingress::StreamCatalogStatus::NotFound, {}, Request.Cursor, false};
        }
        const auto Catalog = State_->StreamCatalogOwner.load(std::memory_order_acquire);
        if (!Catalog)
            return {Prism::Contract::Ingress::StreamCatalogStatus::CapabilityUnavailable,
                {}, Request.Cursor, false};
        return Catalog->List(Request);
    }

    auto SessionControl::ResetStreamAndDrain(Prism::Contract::Ingress::StreamResetRequest Request)
        -> Net::awaitable<std::expected<void, Failure>>
    {
        const auto Parent = CurrentIdentity();
        if (!Parent.TaskId || Request.Identity.Session != Parent.SessionId ||
            Request.Identity.Worker != Parent.WorkerId ||
            Request.Identity.Generation != Parent.Generation ||
            Request.ParentTask != Parent.TaskId || !Request.Task)
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        }
        const auto Catalog = State_->StreamCatalogOwner.load(std::memory_order_acquire);
        if (!Catalog)
            co_return std::unexpected(Failure{Prism::Fault::Code::NotSupported});
        co_return co_await Catalog->ResetAndDrain(std::move(Request));
    }

    auto SessionControl::Cancel() -> std::expected<void, Failure>
    {
        State_->ExplicitCancelRequested.store(true, std::memory_order_release);
        return RequestCancellation();
    }

    auto SessionControl::CancelForShutdown() -> std::expected<void, Failure>
    {
        State_->ShutdownCancelRequested.store(true, std::memory_order_release);
        return RequestCancellation();
    }

    auto SessionControl::CloseOnce() -> std::expected<void, Failure>
    {
        State_->Sealed.store(true);
        auto Action = State_->CloseAction.load();
        if (!Action)
        {
            MarkBlocked(State_);
            return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        }
        if (auto Bound = State_->Bound.load()) Bound->Tasks->Seal();
        auto Result = Action->Submit();
        if (!State_->Closed.exchange(true)) State_->CloseCalls.fetch_add(1);
        if (!Result)
        {
            (void)State_->ControlFailure.TrySet(Result.error());
            State_->CloseDispatchFailed.store(true);
            MarkBlocked(State_);
        }
        return Result;
    }

    auto SessionControl::Drain() -> Net::awaitable<std::expected<void, Failure>>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        auto Bound = State_->Bound.load();
        State_->Sealed.store(true);
        const auto ControlFailure = State_->ControlFailure.Load();
        if (ControlFailure.Failed()) co_return std::unexpected(ControlFailure);
        if (!Bound || State_->Blocked.load())
            co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        co_return co_await Bound->Tasks->Drain();
    }

    auto SessionControl::ReportError(Failure Error) -> void
    {
        ReportError(CurrentIdentity(), Error);
    }

    auto SessionControl::ReportError(const Identity& Id, Failure Error) -> void
    {
        auto Bound = State_->Bound.load();
        if (!Bound)
        {
            MarkBlocked(State_);
            return;
        }
        if (!Bound->Tasks->Reclaimer()->Post([Value = State_, Id, Error] { Report(Value, {Id, Error}); }))
            MarkBlocked(State_);
    }

    auto SessionControl::AwaitDelivery() -> Net::awaitable<std::expected<void, Failure>>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        auto Bound = State_->Bound.load();
        if (!Bound) co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        if (State_->Blocked.load()) co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        auto Batch = CaptureDelivery(State_);
        auto Result = co_await Bound->Delivery->Await();
        if (!Result)
        {
            MarkBlocked(State_);
            co_return Result;
        }
        Batch.Cancellation = Batch.Cancellation || State_->CancelRequested.load();
        Result = co_await DeliverCancellation(Batch);
        if (!Result)
        {
            MarkBlocked(State_);
            co_return Result;
        }
        // 初始错误前缀与有限 hook 已完成；只等待此时已经提交的唯一 close 的自身确认。
        const auto IncludeClose = Batch.Close && State_->Closed.load();
        if (IncludeClose) Result = co_await Batch.Close->Await();
        if (State_->Blocked.load() && Result)
            Result = std::unexpected(Failure{Prism::Fault::Code::Blocked});
        if (!Result) MarkBlocked(State_);
        co_return Result;
    }

    auto SessionControl::CaptureDelivery(const std::shared_ptr<State>& Value) -> DeliveryBatch
    {
        DeliveryBatch Batch;
        Batch.Cancellation = Value->CancelRequested.load();
        Batch.Close = Value->CloseAction.load();
        if (const auto Bound = Value->Bound.load()) Batch.Cancel = Bound->CancelAction;
        for (std::size_t Index = 0; Index < Batch.Hooks.size(); ++Index)
            Batch.Hooks[Index] = Value->CancelHooks[Index].load();
        return Batch;
    }

    auto SessionControl::DeliverCancellation(const DeliveryBatch& Batch)
        -> Net::awaitable<std::expected<void, Failure>>
    {
        if (!Batch.Cancellation) co_return std::expected<void, Failure>{};
        const auto Submitted = Batch.Cancel->Submit();
        if (!Submitted) co_return Submitted;
        for (const auto& Hook : Batch.Hooks)
            if (Hook)
                if (const auto Result = Hook->Submit(); !Result) co_return Result;
        auto Cancelled = co_await Batch.Cancel->Await();
        if (!Cancelled) co_return Cancelled;
        for (const auto& Hook : Batch.Hooks)
            if (Hook)
            {
                const auto Result = co_await Hook->Await();
                if (!Result) co_return Result;
            }
        co_return std::expected<void, Failure>{};
    }

    auto SessionControl::MakeMetrics(const std::shared_ptr<State>& Value) noexcept -> SessionMetrics
    {
        Prism::Lifecycle::TaskStats Snapshot;
        if (const auto Bound = Value->Bound.load()) Snapshot = Bound->Tasks->Stats();
        return {Snapshot.Started, Snapshot.Completed, Snapshot.Active, Value->CancelRequests.load(),
            Value->ErrorCalls.load(), Value->CloseCalls.load(),
            Value->Blocked.load() || Snapshot.DrainBlocked, Value->CloseDispatchFailed.load()};
    }

    auto SessionControl::EmitMetrics(const std::shared_ptr<State>& Value) -> void
    {
        if (const auto Hook = Value->OnMetrics.load(); Hook && *Hook) (*Hook)(MakeMetrics(Value));
    }

    auto SessionControl::MarkBlocked(const std::shared_ptr<State>& Value) noexcept -> void
    {
        Value->Blocked.store(true);
        if (const auto Bound = Value->Bound.load()) Bound->Tasks->Block();
    }

    auto SessionControl::DispatchCancel(const std::shared_ptr<State>& Value) -> void
    {
        for (const auto& Slot : Value->CancelHooks)
            if (const auto Hook = Slot.load(); Hook && !Hook->Submit()) MarkBlocked(Value);
        EmitMetrics(Value);
    }

    auto SessionControl::Report(const std::shared_ptr<State>& Value,
        std::pair<Identity, Failure> Error) -> void
    {
        Value->ErrorCalls.fetch_add(1);
        if (const auto Hook = Value->OnError.load(); Hook && *Hook) (*Hook)(Error.second);
        if (const auto Hook = Value->OnIdentityError.load(); Hook && *Hook)
            (*Hook)(Error.first, Error.second);
        EmitMetrics(Value);
    }

    auto SessionControl::InstallBinding(std::shared_ptr<Registry> Tasks) -> bool
    {
        auto Bound = std::make_shared<Binding>();
        Bound->Tasks = std::move(Tasks);
        Bound->Delivery = std::make_shared<SessionDelivery>(Bound->Tasks->Reclaimer());
        const auto Weak = std::weak_ptr<State>(State_);
        Bound->CancelAction = std::make_shared<Prepared>(Bound->Tasks->Reclaimer(),
            [Weak]() -> std::expected<void, Failure>
            {
                if (const auto Value = Weak.lock())
                {
                    DispatchCancel(Value);
                    if (Value->Blocked.load())
                        return std::unexpected(Failure{Prism::Fault::Code::Blocked});
                }
                return {};
            });
        std::shared_ptr<Binding> Empty;
        if (!State_->Bound.compare_exchange_strong(Empty, Bound)) return false;
        if (State_->CancelRequested.load())
        {
            (void)Bound->Tasks->Cancel();
            if (!Bound->CancelAction->Submit()) MarkBlocked(State_);
        }
        return true;
    }

    auto SessionControl::FailureReporter() -> Registry::FailureHandler
    {
        return [Weak = std::weak_ptr<State>(State_)](const Identity& Id, Failure Error)
        {
            if (const auto Value = Weak.lock()) Report(Value, {Id, Error});
        };
    }

    auto SessionControl::RequestCancellation() -> std::expected<void, Failure>
    {
        if (State_->CancelRequested.exchange(true))
        {
            const auto Failure = State_->ControlFailure.Load();
            if (Failure.Failed()) return std::unexpected(Failure);
            if (State_->Blocked.load())
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            return {};
        }
        State_->CancelRequests.fetch_add(1);
        State_->Sealed.store(true);
        const auto Bound = State_->Bound.load();
        if (!Bound)
        {
            const auto Failure = Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument};
            (void)State_->ControlFailure.TrySet(Failure);
            MarkBlocked(State_);
            return std::unexpected(Failure);
        }
        (void)Bound->Tasks->Cancel();
        const auto Delivered = Bound->CancelAction->Submit();
        if (Bound->Tasks->IsDrainBlocked())
        {
            const auto Failure = Prism::Fault::Failure{Prism::Fault::Code::Blocked};
            (void)State_->ControlFailure.TrySet(Failure);
            MarkBlocked(State_);
            return std::unexpected(Failure);
        }
        if (!Delivered)
        {
            (void)State_->ControlFailure.TrySet(Delivered.error());
            MarkBlocked(State_);
            return Delivered;
        }
        return {};
    }

    auto SessionControl::Executor() const -> std::optional<Net::any_io_executor>
    {
        const auto Bound = State_->Bound.load();
        if (!Bound) return std::nullopt;
        return Bound->Tasks->Executor();
    }
}
