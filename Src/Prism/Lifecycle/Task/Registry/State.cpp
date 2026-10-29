/** @file State.cpp @brief task registry 聚合状态与退休命令实现。 */
#include <Prism/Lifecycle/Task/Registry/State.hpp>
#include <Prism/Lifecycle/Task/Submission.hpp>

#include <boost/asio/strand.hpp>

#include <atomic>
#include <cstddef>
#include <exception>
#include <expected>
#include <functional>
#include <memory>
#include <utility>

namespace Prism::Lifecycle::Detail
{
    TaskRegistryState::TaskRegistryState(
        boost::asio::any_io_executor ExecutorValue,
        std::function<void(const TaskIdentity &, Prism::Fault::Failure)> Failure)
        : ContextPin(Prism::Executor::ContextOwner::Find(ExecutorValue)),
          Executor(std::move(ExecutorValue)),
          CommandExecutor(boost::asio::make_strand(Executor)),
          Reclaimer(std::make_shared<Prism::Executor::ExecutorReclaimer>(CommandExecutor)),
          Domain(std::make_shared<CancellationDomain>(CommandExecutor, Reclaimer)),
          Barrier(Reclaimer),
          ClosingStorage(Prism::Executor::ContextOwner::Storage(Executor)),
          Pool(std::make_shared<TaskSlotPool>()),
          OnFailure(std::move(Failure))
    {
    }

    TaskRegistryState::TaskRegistryState(
        boost::asio::any_io_executor ExecutorValue,
        std::function<void(const TaskIdentity &, Prism::Fault::Failure)> Failure,
        std::shared_ptr<TaskRegistryState> ParentState)
        : ContextPin(Prism::Executor::ContextOwner::Find(ExecutorValue)),
          Executor(std::move(ExecutorValue)),
          CommandExecutor(ParentState->CommandExecutor),
          Reclaimer(ParentState->Reclaimer),
          Parent(ParentState),
          Domain(ParentState->Domain->CreateChild()),
          Traffic(ParentState->Traffic),
          Barrier(Reclaimer),
          ClosingStorage(Prism::Executor::ContextOwner::Storage(Executor)),
          Pool(ParentState->Pool),
          OnFailure(std::move(Failure))
    {
    }

    auto TaskRegistryState::RetainClosing() noexcept -> void
    {
        RetirementPending.store(true, std::memory_order_release);
        ClosingRetained.store(true, std::memory_order_release);
        ClosingStorage->Retain(shared_from_this());
    }

    auto TaskRegistryState::RetainUnavailableRetirement() noexcept -> void
    {
        RetirementUnavailable.store(
            !Reclaimer->IsQuarantined() && !Reclaimer->CanDispatch(),
            std::memory_order_release);
        if (Reclaimer->IsQuarantined() || Reclaimer->CanDispatch())
        {
            Blocked.store(true, std::memory_order_release);
            Barrier.Block();
            MarkAggregateBlocked(shared_from_this());
        }
        RetirementPending.store(false, std::memory_order_release);
        ClosingRetained.store(true, std::memory_order_release);
        ClosingStorage->Retain(shared_from_this());
    }

    auto TaskRegistryState::IsRetired() const noexcept -> bool
    {
        return !RetirementPending.load(std::memory_order_acquire) &&
               !RetirementUnavailable.load(std::memory_order_acquire) &&
               !Blocked.load(std::memory_order_acquire) && !Barrier.IsBlocked() &&
               Barrier.Active() == 0 && Descendants.Active.load(std::memory_order_acquire) == 0;
    }

    auto TaskRegistryState::IsDispatchUnavailable() const noexcept -> bool
    {
        return Blocked.load() || !Reclaimer->CanDispatch();
    }

    auto AggregateCounter(TaskRegistryState &StateValue,
        const AggregateMetric Metric) noexcept -> std::atomic<std::size_t>&
    {
        switch (Metric)
        {
        case AggregateMetric::Active: return StateValue.Descendants.Active;
        case AggregateMetric::Started: return StateValue.Descendants.Started;
        case AggregateMetric::Completed: return StateValue.Descendants.Completed;
        case AggregateMetric::Cancelled: return StateValue.Descendants.Cancelled;
        case AggregateMetric::Failed: return StateValue.Descendants.Failed;
        case AggregateMetric::Quarantined: return StateValue.Descendants.Quarantined;
        }
        std::terminate();
    }

    auto AddAggregate(const std::shared_ptr<TaskRegistryState>& StateValue,
        const AggregateMetric Metric, const bool Increment) noexcept -> void
    {
        std::shared_ptr<TaskRegistryState> Parent;
        if (StateValue) Parent = StateValue->Parent;
        while (Parent)
        {
            auto& Counter = AggregateCounter(*Parent, Metric);
            if (Increment) Counter.fetch_add(1, std::memory_order_relaxed);
            else Counter.fetch_sub(1, std::memory_order_relaxed);
            Parent = Parent->Parent;
        }
    }

    auto MarkAggregateBlocked(const std::shared_ptr<TaskRegistryState>& StateValue) noexcept -> void
    {
        std::shared_ptr<TaskRegistryState> Parent;
        if (StateValue) Parent = StateValue->Parent;
        while (Parent)
        {
            Parent->Descendants.DrainBlocked.store(true, std::memory_order_release);
            Parent = Parent->Parent;
        }
    }

    auto MarkTaskRegistryBlocked(const std::shared_ptr<TaskRegistryState>& State) noexcept -> void
    {
        State->Blocked.store(true);
        State->Barrier.Block();
        MarkAggregateBlocked(State);
    }

    auto SealTaskRegistryState(const std::shared_ptr<TaskRegistryState>& State) noexcept -> void
    {
        State->Accepting.store(false);
        State->Barrier.Seal();
    }

    auto RequestTaskCancel(
        const std::shared_ptr<TaskRegistryState>& State,
        const std::shared_ptr<TaskState>& Task) -> void
    {
        if (!Task) return;
        (void)Task->RequestCancel();
        if (Task->IsCancelDispatchFailed()) MarkTaskRegistryBlocked(State);
    }

    auto LeaveTrackedTask(const std::shared_ptr<TaskRegistryState>& StateValue) noexcept -> void
    {
        AddAggregate(StateValue, AggregateMetric::Active, false);
        StateValue->Barrier.Leave();
        for (auto Value = StateValue; Value; Value = Value->Parent)
        {
            if (!Value->ClosingRetained.load()) continue;
            Value->ClosingStorage->Collect();
            break;
        }
    }

    auto RecordStarted(const std::shared_ptr<TaskRegistryState>& StateValue) noexcept -> void
    {
        StateValue->Started.fetch_add(1, std::memory_order_relaxed);
        AddAggregate(StateValue, AggregateMetric::Started, true);
    }

    auto RecordCompleted(const std::shared_ptr<TaskRegistryState>& StateValue,
        const TaskOutcome Outcome) noexcept -> void
    {
        StateValue->Completed.fetch_add(1, std::memory_order_relaxed);
        AddAggregate(StateValue, AggregateMetric::Completed, true);
        switch (Outcome)
        {
        case TaskOutcome::Cancelled:
            StateValue->Cancelled.fetch_add(1, std::memory_order_relaxed);
            AddAggregate(StateValue, AggregateMetric::Cancelled, true);
            break;
        case TaskOutcome::Failed:
            StateValue->Failed.fetch_add(1, std::memory_order_relaxed);
            AddAggregate(StateValue, AggregateMetric::Failed, true);
            break;
        case TaskOutcome::Quarantined:
            StateValue->Quarantined.fetch_add(1, std::memory_order_relaxed);
            AddAggregate(StateValue, AggregateMetric::Quarantined, true);
            break;
        case TaskOutcome::Pending:
        case TaskOutcome::Succeeded:
            break;
        }
    }

    auto AddTaskStats(TaskStats& Result,
        const std::shared_ptr<TaskRegistryState>& StateValue) noexcept -> void
    {
        if (!StateValue) return;
        Result.Active += StateValue->Barrier.Active();
        Result.Started += StateValue->Started.load(std::memory_order_acquire);
        Result.Completed += StateValue->Completed.load(std::memory_order_acquire);
        Result.Cancelled += StateValue->Cancelled.load(std::memory_order_acquire);
        Result.Failed += StateValue->Failed.load(std::memory_order_acquire);
        Result.Quarantined += StateValue->Quarantined.load(std::memory_order_acquire);
        Result.DrainBlocked = Result.DrainBlocked ||
            StateValue->Blocked.load(std::memory_order_acquire) || StateValue->Barrier.IsBlocked() ||
            StateValue->Descendants.DrainBlocked.load(std::memory_order_acquire);
        Result.Active += StateValue->Descendants.Active.load(std::memory_order_acquire);
        Result.Started += StateValue->Descendants.Started.load(std::memory_order_acquire);
        Result.Completed += StateValue->Descendants.Completed.load(std::memory_order_acquire);
        Result.Cancelled += StateValue->Descendants.Cancelled.load(std::memory_order_acquire);
        Result.Failed += StateValue->Descendants.Failed.load(std::memory_order_acquire);
        Result.Quarantined += StateValue->Descendants.Quarantined.load(std::memory_order_acquire);
    }

    auto QuarantineTaskSlots(const std::shared_ptr<TaskRegistryState>& StateValue) noexcept -> void
    {
        StateValue->CommandCancelled.store(true, std::memory_order_release);
        for (auto& Slot : StateValue->Pool->Slots)
        {
            if (Slot.Scope.load(std::memory_order_acquire) != StateValue.get()) continue;
            try
            {
                if (Slot.Quarantine) Slot.Quarantine();
                else if (Slot.Task) (void)Slot.Task->RequestCancel();
            }
            catch (...)
            {
                StateValue->Blocked.store(true, std::memory_order_release);
                StateValue->Barrier.Block();
            }
        }
    }

    auto TaskRegistryRetirementCommand::operator()() noexcept -> void
    {
        QuarantineTaskSlots(State);
        State->RetirementUnavailable.store(false, std::memory_order_release);
        State->RetirementPending.store(false, std::memory_order_release);
        if (State->ClosingRetained.load(std::memory_order_acquire))
            State->ClosingStorage->Collect();
    }

    auto TaskRegistryRetirementCommand::OnQuarantine() noexcept -> void
    {
        if (!State) return;
        State->Blocked.store(true, std::memory_order_release);
        State->Barrier.Block();
        MarkAggregateBlocked(State);
        QuarantineTaskSlots(State);
        State->RetirementPending.store(false, std::memory_order_release);
    }

    auto TaskRegistryState::RequestRetirement() -> void
    {
        Accepting.store(false);
        CancelRequested.store(true);
        TearingDown.store(true, std::memory_order_release);
        Barrier.Seal();
        bool Expected = false;
        if (!RetirementPending.compare_exchange_strong(
                Expected, true, std::memory_order_acq_rel, std::memory_order_acquire)) return;
        RetirementUnavailable.store(false, std::memory_order_release);
        auto Self = shared_from_this();
        ClosingRetained.store(true, std::memory_order_release);
        ClosingStorage->Retain(Self);
        if (!Reclaimer->Post(TaskRegistryRetirementCommand(Self)))
        {
            RetainUnavailableRetirement();
        }
    }
}

namespace Prism::Lifecycle
{
    TaskReservation::TaskReservation(TaskReservation&& Other) noexcept
        : Owner_(std::move(Other.Owner_)), Slot_(Other.Slot_), Domain_(std::move(Other.Domain_)),
          Published_(std::exchange(Other.Published_, false))
    {
    }

    TaskReservation::~TaskReservation()
    {
        if (!Owner_) return;
        if (Domain_) Domain_->Detach();
        if (Published_)
        {
            if (auto Task = Owner_->Pool->Slots[Slot_].Task) Task->Retire();
            Owner_->Pool->Slots[Slot_].Task.reset();
        }
        Owner_->Pool->Slots[Slot_].Quarantine = {};
        Owner_->Pool->Slots[Slot_].Scope.store(nullptr);
        Owner_->Pool->Slots[Slot_].Used.store(false, std::memory_order_release);
        Detail::LeaveTrackedTask(Owner_);
    }

    auto TaskReservation::Acquire(std::shared_ptr<State> Owner)
        -> std::expected<TaskReservation, Prism::Fault::Failure>
    {
        for (std::size_t Index = 0; Index < Detail::TaskSlotPool::Capacity; ++Index)
        {
            bool Empty = false;
            if (!Owner->Pool->Slots[Index].Used.compare_exchange_strong(Empty, true)) continue;
            if (!Owner->Barrier.Enter())
            {
                Owner->Pool->Slots[Index].Used.store(false);
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Canceled});
            }
            TaskReservation Result(std::move(Owner), Index);
            Result.Owner_->Pool->Slots[Index].Scope.store(Result.Owner_.get());
            Detail::AddAggregate(Result.Owner_, Detail::AggregateMetric::Active, true);
            return Result;
        }
        return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
    }

    auto TaskReservation::Attach(std::shared_ptr<CancellationDomain> Domain) noexcept -> void
    {
        Domain_ = std::move(Domain);
    }

    auto TaskReservation::Publish(std::shared_ptr<TaskState> Task) -> void
    {
        Published_ = true;
        Owner_->Pool->Slots[Slot_].Task = std::move(Task);
    }

    auto TaskReservation::SetQuarantine(std::function<void()> Callback) -> void
    {
        Owner_->Pool->Slots[Slot_].Quarantine = std::move(Callback);
    }

    TaskReservation::TaskReservation(std::shared_ptr<State> Owner, std::size_t Slot) noexcept
        : Owner_(std::move(Owner)), Slot_(Slot)
    {
    }
}
