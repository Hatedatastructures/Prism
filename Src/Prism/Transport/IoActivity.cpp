/** @file IoActivity.cpp @brief typed I/O预约、completion回收与Drain状态实现。 */
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <Prism/Transport/Activity/Io.hpp>
#include <Prism/Transport/Activity/TrackedCompletion.hpp>

#include <atomic>
#include <system_error>
#include <utility>

namespace Prism::Transport::Detail
{
    TrackedCompletion::TrackedCompletion(
        IoActivity::Operation Operation, IoCompletion Handler)
        : Operation_(std::move(Operation)), Handler_(std::move(Handler))
    {
    }

    TrackedCompletion::TrackedCompletion(TrackedCompletion&& Other) noexcept
        : Operation_(std::move(Other.Operation_)), Handler_(std::move(Other.Handler_)),
          Returned_(Other.Returned_.load(std::memory_order_acquire))
    {
    }

    TrackedCompletion::~TrackedCompletion()
    {
        if (!Returned_.load(std::memory_order_acquire) && Handler_)
        {
            Operation_.RetainHandler(std::move(Handler_));
        }
    }

    auto TrackedCompletion::get_executor() const noexcept -> executor_type
    {
        return boost::asio::get_associated_executor(Handler_);
    }

    auto TrackedCompletion::get_allocator() const noexcept -> allocator_type
    {
        return boost::asio::get_associated_allocator(Handler_);
    }

    auto TrackedCompletion::get_cancellation_slot() const noexcept
        -> cancellation_slot_type
    {
        return boost::asio::get_associated_cancellation_slot(Handler_);
    }

    auto TrackedCompletion::operator()(Prism::IoResult Result) -> void
    {
        if (Returned_.exchange(true, std::memory_order_acq_rel))
        {
            return;
        }
        struct ReturnGuard final
        {
            IoActivity::Operation& Operation;
            ~ReturnGuard() { Operation.Returned(); }
        } Guard{Operation_};
        auto Handler = std::move(Handler_);
        if (Handler)
        {
            Handler(Result);
        }
    }

    IoActivity::State::State(boost::asio::any_io_executor Executor, RetirementPolicy Policy)
        : RequiresCloseReceipt(Policy != RetirementPolicy::OperationsDrained),
          Context(Prism::Executor::ContextOwner::Find(Executor)),
          Storage(Prism::Executor::ContextOwner::Storage(Executor)),
          Reclaimer(std::make_shared<Prism::Executor::ExecutorReclaimer>(std::move(Executor))),
          Barrier(Reclaimer), DrainChanges(Reclaimer->Executor(), 1),
          DrainNotificationAvailable(Prism::Lifecycle::BindDrainNotification(Reclaimer->Executor()))
    {
        for (auto& Entry : Slots)
            Entry.Returned = std::make_unique<Signal>(Reclaimer->Executor(), 1);
    }

    auto IoActivity::State::ClosePending() const noexcept -> bool
    {
        return CloseAccepted.load(std::memory_order_acquire) &&
            !CloseDelivered.load(std::memory_order_acquire);
    }

    auto IoActivity::State::HasReportableControlFailure() const noexcept -> bool
    {
        return KnownControlFailures.load(std::memory_order_acquire) != 0 &&
            (!ClosePending() || KnownCloseControlFailures.load(std::memory_order_acquire) != 0);
    }

    auto IoActivity::State::NotifyDrainState() noexcept -> void
    {
        if (DrainWaiters.load(std::memory_order_acquire) == 0 ||
            !DrainNotificationAvailable->load(std::memory_order_acquire)) return;
        (void)DrainChanges.try_send(boost::system::error_code{});
    }

    auto IoActivity::State::Fail(Prism::Fault::Failure Error) noexcept -> void
    {
        (void)Failure.TrySet(Error);
        Unrecoverable.store(true, std::memory_order_release);
        Blocked.store(true, std::memory_order_release);
        Barrier.Block();
        Storage->Retain(shared_from_this());
        NotifyDrainState();
    }

    auto IoActivity::State::RecordControlFailure(
        Prism::Fault::Failure Error, bool NewForCommand, bool IsClose) noexcept -> void
    {
        if (NewForCommand)
        {
            KnownControlFailures.fetch_add(1, std::memory_order_acq_rel);
            if (IsClose)
                KnownCloseControlFailures.fetch_add(1, std::memory_order_acq_rel);
        }
        if (Unrecoverable.load(std::memory_order_acquire))
        {
            Fail(Error);
            return;
        }
        (void)Failure.TrySet(Error);
        Blocked.store(true, std::memory_order_release);
        Storage->Retain(shared_from_this());
        NotifyDrainState();
    }

    auto IoActivity::State::ResolveControlFailure(bool IsClose) noexcept -> void
    {
        auto Count = KnownControlFailures.load(std::memory_order_acquire);
        while (Count != 0 && !KnownControlFailures.compare_exchange_weak(
            Count, Count - 1, std::memory_order_acq_rel, std::memory_order_acquire)) {}
        if (IsClose)
        {
            auto CloseCount = KnownCloseControlFailures.load(std::memory_order_acquire);
            while (CloseCount != 0 && !KnownCloseControlFailures.compare_exchange_weak(
                CloseCount, CloseCount - 1, std::memory_order_acq_rel,
                std::memory_order_acquire)) {}
        }
        NotifyDrainState();
        if (CloseDelivered.load(std::memory_order_acquire) &&
            KnownControlFailures.load(std::memory_order_acquire) == 0)
            Storage->Collect();
    }

    auto IoActivity::State::RecordCloseDelivered() noexcept -> void
    {
        CloseDelivered.store(true, std::memory_order_release);
        NotifyDrainState();
    }

    auto IoActivity::State::RecordCloseAccepted() noexcept -> void
    {
        CloseAccepted.store(true, std::memory_order_release);
        NotifyDrainState();
    }

    auto IoActivity::State::BeginControlRetry() noexcept -> void
    {
        ControlRetriesInFlight.fetch_add(1, std::memory_order_acq_rel);
    }

    auto IoActivity::State::EndControlRetry() noexcept -> void
    {
        auto Count = ControlRetriesInFlight.load(std::memory_order_acquire);
        while (Count != 0 && !ControlRetriesInFlight.compare_exchange_weak(
            Count, Count - 1, std::memory_order_acq_rel, std::memory_order_acquire)) {}
        if (Count == 1 && CloseDelivered.load(std::memory_order_acquire) &&
            KnownControlFailures.load(std::memory_order_acquire) == 0) Storage->Collect();
        NotifyDrainState();
    }

    auto IoActivity::State::RequestRetirement() -> void
    {
    }

    auto IoActivity::State::IsRetired() const noexcept -> bool
    {
        return (!RequiresCloseReceipt || CloseDelivered.load(std::memory_order_acquire)) &&
            !ClosePending() && !Unrecoverable.load(std::memory_order_acquire) &&
            ControlRetriesInFlight.load(std::memory_order_acquire) == 0 &&
            Barrier.Active() == 0 && HasNoUsedSlots();
    }

    auto IoActivity::State::IsDispatchUnavailable() const noexcept -> bool
    {
        if (!Unrecoverable.load(std::memory_order_acquire) &&
            KnownControlFailures.load(std::memory_order_acquire) != 0 && Reclaimer->CanDispatch()) return false;
        return Unrecoverable.load(std::memory_order_acquire) ||
            (Blocked.load(std::memory_order_acquire) && !Reclaimer->CanDispatch());
    }

    auto IoActivity::State::HasNoUsedSlots() const noexcept -> bool
    {
        for (const auto& Entry : Slots)
            if (Entry.Used.load(std::memory_order_acquire)) return false;
        return true;
    }

    IoActivity::Retirement::Retirement(std::shared_ptr<State> Value, std::size_t SlotIndex)
        : Owner(std::move(Value)), Index(SlotIndex)
    {
    }

    IoActivity::Retirement::Retirement(Retirement&& Other) noexcept
        : Owner(std::move(Other.Owner)), Index(Other.Index)
    {
    }

    IoActivity::Retirement::~Retirement()
    {
        if (Owner && !Executed) Owner->Fail();
    }

    auto IoActivity::Retirement::operator()(boost::system::error_code Error) -> void
    {
        if (Error)
        {
            Owner->Fail(Prism::Fault::FromNative(static_cast<std::error_code>(Error)));
            Executed = true;
            return;
        }
        Owner->Slots[Index].Carrier.store({});
        Owner->Slots[Index].Used.store(false, std::memory_order_release);
        Owner->Barrier.Leave();
        Owner->NotifyDrainState();
        Executed = true;
        if (Owner->CloseDelivered.load(std::memory_order_acquire)) Owner->Storage->Collect();
    }

    IoActivity::Operation::Operation(std::shared_ptr<State> Owner, std::size_t Index)
        : Owner_(std::move(Owner)), Index_(Index)
    {
    }

    IoActivity::Operation::Operation(Operation&& Other) noexcept
        : Owner_(std::move(Other.Owner_)), Index_(Other.Index_), Returned_(Other.Returned_)
    {
    }

    IoActivity::Operation::~Operation()
    {
        if (!Owner_) return;
        if (!Returned_) { Owner_->Fail(); return; }
        if (!Owner_->Slots[Index_].Returned->try_send(boost::system::error_code{})) Owner_->Fail();
    }

    auto IoActivity::Operation::Returned() noexcept -> void
    {
        Returned_ = true;
    }

    auto IoActivity::Operation::RetainHandler(IoCompletion Handler) noexcept -> void
    {
        if (Owner_) Owner_->Slots[Index_].Abandoned = std::move(Handler);
    }

    IoActivity::IoActivity(boost::asio::any_io_executor Executor, RetirementPolicy Policy)
        : State_(std::make_shared<State>(std::move(Executor), Policy))
    {
    }

    auto IoActivity::TryAcquire(std::shared_ptr<void> Carrier)
        -> std::expected<Operation, Prism::Fault::Failure>
    {
        return Acquire(std::move(Carrier), Range{0, Capacity});
    }

    auto IoActivity::TryAcquireControl(std::shared_ptr<void> Carrier)
        -> std::expected<Operation, Prism::Fault::Failure>
    {
        return Acquire(std::move(Carrier), Range{Capacity, Capacity + ControlCapacity});
    }

    auto IoActivity::TryAcquireCloseControl(std::shared_ptr<void> Carrier)
        -> std::expected<Operation, Prism::Fault::Failure>
    {
        return Acquire(std::move(Carrier), Range{Capacity, Capacity + ControlCapacity}, true);
    }

    auto IoActivity::Block(Prism::Fault::Failure Failure) noexcept -> void
    {
        State_->Fail(Failure);
    }

    auto IoActivity::RecordControlFailure(
        Prism::Fault::Failure Failure, bool NewForCommand, bool IsClose) noexcept -> void
    {
        State_->RecordControlFailure(Failure, NewForCommand, IsClose);
    }

    auto IoActivity::ResolveControlFailure(bool IsClose) noexcept -> void
    {
        State_->ResolveControlFailure(IsClose);
    }

    auto IoActivity::BeginControlRetry() noexcept -> void
    {
        State_->BeginControlRetry();
    }

    auto IoActivity::EndControlRetry() noexcept -> void
    {
        State_->EndControlRetry();
    }

    auto IoActivity::RecordCloseDelivered() noexcept -> void
    {
        State_->RecordCloseDelivered();
    }

    auto IoActivity::RecordCloseAccepted() noexcept -> void
    {
        State_->RecordCloseAccepted();
    }

    auto IoActivity::IsIdle() const noexcept -> bool
    {
        return State_->Barrier.Active() == 0 && !State_->Barrier.IsBlocked() &&
            !State_->Blocked.load(std::memory_order_acquire);
    }

    auto IoActivity::IsRetired() const noexcept -> bool
    {
        return State_->Barrier.IsSealed() && State_->IsRetired();
    }

    auto IoActivity::Seal() noexcept -> void
    {
        State_->Barrier.Seal();
    }

    auto IoActivity::Executor() const -> boost::asio::any_io_executor
    {
        return State_->Reclaimer->Executor();
    }

    auto IoActivity::Drain() -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        Seal();
        return DrainState(State_);
    }

    auto IoActivity::DrainState(std::shared_ptr<State> Owner)
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await boost::asio::this_coro::throw_if_cancelled(false);
        auto Result = std::expected<void, Prism::Fault::Failure>{};
        for (;;)
        {
            const auto Failure = Owner->Failure.Load();
            const auto RetryInFlight = Owner->ControlRetriesInFlight.load(std::memory_order_acquire) != 0;
            if (Owner->Unrecoverable.load(std::memory_order_acquire) ||
                (!RetryInFlight && Owner->HasReportableControlFailure()))
            {
                if (Failure.Failed()) Result = std::unexpected(Failure);
                else Result = std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                break;
            }
            if (!RetryInFlight && Owner->Barrier.Active() == 0 && !Owner->ClosePending())
            {
                if (!Owner->CloseDelivered.load(std::memory_order_acquire) && Failure.Failed())
                    Result = std::unexpected(Failure);
                break;
            }
            if (!Owner->Reclaimer->CanDispatch())
            {
                if (Failure.Failed()) Result = std::unexpected(Failure);
                else Result = std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                break;
            }
            struct DrainWaiter final
            {
                explicit DrainWaiter(std::shared_ptr<State> Value) : Owner(std::move(Value))
                { Owner->DrainWaiters.fetch_add(1, std::memory_order_acq_rel); }
                ~DrainWaiter() { Owner->DrainWaiters.fetch_sub(1, std::memory_order_acq_rel); }
                std::shared_ptr<State> Owner;
            } Waiter(Owner);
            const bool RetryPending =
                Owner->ControlRetriesInFlight.load(std::memory_order_acquire) != 0;
            if (Owner->Unrecoverable.load(std::memory_order_acquire) ||
                (!RetryPending && Owner->HasReportableControlFailure()) ||
                (!RetryPending && Owner->Barrier.Active() == 0 && !Owner->ClosePending()))
                continue;
            if (!Owner->Reclaimer->CanDispatch()) continue;
            boost::system::error_code Error;
            co_await Owner->DrainChanges.async_receive(
                boost::asio::redirect_error(boost::asio::use_awaitable, Error));
            if (Error)
            {
                const auto RecordedFailure = Owner->Failure.Load();
                if (RecordedFailure.Failed()) Result = std::unexpected(RecordedFailure);
                else Result = std::unexpected(Prism::Fault::FromNative(static_cast<std::error_code>(Error)));
                break;
            }
        }
        Owner->NotifyDrainState();
        co_return Result;
    }

    auto IoActivity::Acquire(
        std::shared_ptr<void> Carrier, Range Slots, bool AllowKnownControlFailure)
        -> std::expected<Operation, Prism::Fault::Failure>
    {
        if (!Carrier) return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        const auto CanPassKnownFailure = AllowKnownControlFailure &&
            !State_->Unrecoverable.load(std::memory_order_acquire);
        if (State_->Blocked.load(std::memory_order_acquire) && !CanPassKnownFailure)
            return std::unexpected(State_->Failure.Load());
        if (!State_->Barrier.Enter())
        {
            State_->NotifyDrainState();
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }
        if (State_->Blocked.load(std::memory_order_acquire) &&
            (State_->Unrecoverable.load(std::memory_order_acquire) || !AllowKnownControlFailure))
        {
            State_->Barrier.Leave();
            State_->NotifyDrainState();
            return std::unexpected(State_->Failure.Load());
        }
        for (std::size_t Index = Slots.Begin; Index < Slots.End; ++Index)
        {
            if (State_->Slots[Index].Used.exchange(true, std::memory_order_acq_rel)) continue;
            State_->Slots[Index].Carrier.store(std::move(Carrier));
            Operation Result(State_, Index);
            State_->Slots[Index].Returned->async_receive(boost::asio::bind_allocator(State_->CleanupMemory,
                boost::asio::bind_executor(State_->Reclaimer->Executor(), Retirement(State_, Index))));
            return Result;
        }
        State_->Barrier.Leave();
        State_->NotifyDrainState();
        return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
    }
} // namespace Prism::Transport::Detail
