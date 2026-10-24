/** @file CancellationDomain.cpp @brief 取消树状态与 executor 通知实现。 */
#include <Prism/Lifecycle/CancellationDomain.hpp>

#include <atomic>
#include <memory>
#include <utility>

namespace Prism::Lifecycle
{
    struct CancellationDomain::State final : std::enable_shared_from_this<State>
    {
        explicit State(std::shared_ptr<Prism::Executor::ExecutorReclaimer> Value)
            : Reclaimer(std::move(Value)) {}

        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer;
        std::weak_ptr<State> Parent;
        std::shared_ptr<State> First;
        std::shared_ptr<State> Next;
        Net::cancellation_signal Signal;
        std::atomic<std::weak_ptr<CancellationObserver>> Observer;
        std::atomic<bool> Requested{false};
        std::atomic<bool> Cancelled{false};
        std::atomic<bool> Blocked{false};
        std::atomic<bool> Detached{false};

        auto Attach(const std::shared_ptr<State>& Child) -> void
        {
            Prune();
            if (Child->Detached.load()) return;
            Child->Next = std::move(First);
            First = Child;
            if (Requested.load()) Child->Requested.store(true);
            if (Cancelled.load()) Child->Emit();
        }

        auto Prune() -> void
        {
            auto* Link = &First;
            while (*Link)
            {
                if ((*Link)->Detached.load())
                {
                    *Link = std::move((*Link)->Next);
                    continue;
                }
                Link = &(*Link)->Next;
            }
        }

        auto Emit() -> void
        {
            Prune();
            if (Cancelled.exchange(true)) return;
            Requested.store(true);
            if (auto Value = Observer.load().lock())
            {
                try { Value->OnCancellation(); }
                catch (...) { Blocked.store(true, std::memory_order_release); }
            }
            Signal.emit(Net::cancellation_type::all);
            for (auto Child = First; Child; Child = Child->Next) Child->Emit();
        }
    };

    CancellationDomain::CancellationDomain(std::shared_ptr<State> Value)
        : State_(std::move(Value)) {}

    CancellationDomain::CancellationDomain(Net::any_io_executor Executor,
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer)
    {
        if (!Reclaimer)
            Reclaimer = std::make_shared<Prism::Executor::ExecutorReclaimer>(std::move(Executor));
        State_ = std::make_shared<State>(std::move(Reclaimer));
    }

    CancellationDomain::~CancellationDomain()
    {
        Detach();
    }

    auto CancellationDomain::CreateChild() -> std::shared_ptr<CancellationDomain>
    {
        auto ChildState = std::make_shared<State>(State_->Reclaimer);
        ChildState->Parent = State_;
        auto Child = std::shared_ptr<CancellationDomain>(new CancellationDomain(ChildState));
        if (!State_->Reclaimer->Post([Parent = State_, ChildState] { Parent->Attach(ChildState); }))
            ChildState->Blocked.store(true);
        return Child;
    }

    auto CancellationDomain::Detach() noexcept -> void
    {
        State_->Detached.store(true);
    }

    auto CancellationDomain::Cancel() -> bool
    {
        if (State_->Requested.exchange(true) && State_->Cancelled.load()) return false;
        if (!State_->Reclaimer->Post([Value = State_] { Value->Emit(); }))
            State_->Blocked.store(true);
        return true;
    }

    auto CancellationDomain::Observe(std::weak_ptr<CancellationObserver> Observer) noexcept -> void
    {
        State_->Observer.store(std::move(Observer));
    }

    auto CancellationDomain::RequestCancellation() noexcept -> void
    {
        State_->Requested.store(true);
    }

    auto CancellationDomain::IsCancelled() const noexcept -> bool
    {
        return State_->Cancelled.load();
    }

    auto CancellationDomain::IsCancellationRequested() const noexcept -> bool
    {
        for (auto Value = State_; Value; Value = Value->Parent.lock())
            if (Value->Requested.load()) return true;
        return false;
    }

    auto CancellationDomain::IsDispatchBlocked() const noexcept -> bool
    {
        return State_->Blocked.load() || !State_->Reclaimer->CanDispatch();
    }

    auto CancellationDomain::Slot() noexcept -> Net::cancellation_slot
    {
        return State_->Signal.slot();
    }

    auto CancellationDomain::Executor() const -> Net::any_io_executor
    {
        return State_->Reclaimer->Executor();
    }

    auto CancellationDomain::Reclaimer() const
        -> const std::shared_ptr<Prism::Executor::ExecutorReclaimer>&
    {
        return State_->Reclaimer;
    }
}
