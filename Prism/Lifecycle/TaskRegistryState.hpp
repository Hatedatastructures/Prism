/**
 * @file TaskRegistryState.hpp
 * @brief TaskRegistry 的状态模型、ID reservation 和统计快照 owner。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <array>
#include <memory>
#include <utility>

#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <Prism/Lifecycle/CancellationDomain.hpp>
#include <Prism/Lifecycle/TaskState.hpp>


namespace Prism::Lifecycle
{

    struct TaskStats final
    {
        std::size_t Active{0};
        std::size_t Started{0};
        std::size_t Completed{0};
        std::size_t Cancelled{0};
        std::size_t Failed{0};
        std::size_t Quarantined{0};
        bool DrainBlocked{false};
    };

    namespace Detail
    {

        struct TaskRegistryState;
        /** @brief 同一根 scope 的后代共享有限活动槽，避免每会话重复分配历史容量。 */
        struct TaskSlotPool final
        {
            static constexpr std::size_t Capacity = 4096;
            struct Slot final
            {
                std::atomic<bool> Used{false};
                std::atomic<TaskRegistryState*> Scope{nullptr};
                std::shared_ptr<TaskState> Task;
                std::function<void()> Quarantine;
            };
            std::array<Slot, Capacity> Slots;
        };
        struct TaskRegistryState final : Prism::Executor::ClosingResource, std::enable_shared_from_this<TaskRegistryState>
        {
            struct DescendantStats final
            {
                std::atomic<std::size_t> Active{0};
                std::atomic<std::size_t> Started{0};
                std::atomic<std::size_t> Completed{0};
                std::atomic<std::size_t> Cancelled{0};
                std::atomic<std::size_t> Failed{0};
                std::atomic<std::size_t> Quarantined{0};
                std::atomic<bool> DrainBlocked{false};
            };


            TaskRegistryState(
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

            TaskRegistryState(
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

            /** @brief 保活实际 executor context；声明在所有 service 使用者之前，最后释放。 */
            std::shared_ptr<Prism::Executor::ContextOwner> ContextPin;
            boost::asio::any_io_executor Executor;
            boost::asio::any_io_executor CommandExecutor;
            std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer;
            std::shared_ptr<TaskRegistryState> Parent;
            std::shared_ptr<CancellationDomain> Domain;
            /** @brief 冷绑定的唯一数值统计 sink；子 scope 继承强引用至最终退休。 */
            std::shared_ptr<Prism::Foundation::TrafficSink> Traffic;
            /** @brief 退役 scope 只在析构时保留实物/context；恢复投递由显式 storage Retry 发起。 */
            auto RetainClosing() noexcept -> void
            {
                RetirementPending.store(true, std::memory_order_release);
                ClosingRetained.store(true, std::memory_order_release);
                ClosingStorage->Retain(shared_from_this());
            }
            auto RequestRetirement() -> void override;
            [[nodiscard]] auto IsRetired() const noexcept -> bool override
            {
                return !RetirementPending.load(std::memory_order_acquire) &&
                       !Blocked.load(std::memory_order_acquire) && !Barrier.IsBlocked() &&
                       Barrier.Active() == 0 && Descendants.Active.load(std::memory_order_acquire) == 0;
            }
            [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
            { return Blocked.load() || !Reclaimer->CanDispatch(); }
            DrainBarrier Barrier;
            std::shared_ptr<Prism::Executor::ClosingStorage> ClosingStorage;
            std::atomic<bool> ClosingRetained{false};
            /** @brief 原 executor 退休命令尚未完成时为 true；失败事实由 Blocked 单独保留。 */
            std::atomic<bool> RetirementPending{false};
            std::shared_ptr<TaskSlotPool> Pool;
            DescendantStats Descendants;

            std::atomic<std::size_t> Started{0};
            std::atomic<std::size_t> Completed{0};
            std::atomic<std::size_t> Cancelled{0};
            std::atomic<std::size_t> Failed{0};
            std::atomic<std::size_t> Quarantined{0};
            std::atomic<bool> Accepting{true};
            std::atomic<bool> CancelRequested{false};
            std::atomic<bool> TearingDown{false};
            std::atomic<bool> CommandCancelled{false};
            std::atomic<bool> Blocked{false};
            std::function<void(const TaskIdentity &, Prism::Fault::Failure)> OnFailure;
        };

        enum class AggregateMetric : std::uint8_t
        {
            Active,
            Started,
            Completed,
            Cancelled,
            Failed,
            Quarantined,
        };

        inline auto AggregateCounter(
            TaskRegistryState &StateValue,
            const AggregateMetric Metric) noexcept -> std::atomic<std::size_t> &
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

        inline auto AddAggregate(
            const std::shared_ptr<TaskRegistryState> &StateValue,
            const AggregateMetric Metric,
            const bool Increment) noexcept -> void
        {
            std::shared_ptr<TaskRegistryState> Parent;
            if (StateValue) Parent = StateValue->Parent;
            while (Parent)
            {
                auto &Counter = AggregateCounter(*Parent, Metric);
                if (Increment)
                {
                    Counter.fetch_add(1, std::memory_order_relaxed);
                }
                else
                {
                    Counter.fetch_sub(1, std::memory_order_relaxed);
                }
                Parent = Parent->Parent;
            }
        }

        inline auto MarkAggregateBlocked(
            const std::shared_ptr<TaskRegistryState> &StateValue) noexcept -> void
        {
            std::shared_ptr<TaskRegistryState> Parent;
            if (StateValue) Parent = StateValue->Parent;
            while (Parent)
            {
                Parent->Descendants.DrainBlocked.store(true, std::memory_order_release);
                Parent = Parent->Parent;
            }
        }

        inline auto LeaveTrackedTask(
            const std::shared_ptr<TaskRegistryState> &StateValue) noexcept -> void
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

        inline auto RecordStarted(
            const std::shared_ptr<TaskRegistryState> &StateValue) noexcept -> void
        {
            StateValue->Started.fetch_add(1, std::memory_order_relaxed);
            AddAggregate(StateValue, AggregateMetric::Started, true);
        }

        inline auto RecordCompleted(
            const std::shared_ptr<TaskRegistryState> &StateValue,
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

        inline auto AddTaskStats(
            TaskStats &Result,
            const std::shared_ptr<TaskRegistryState> &StateValue) noexcept -> void
        {
            if (!StateValue)
            {
                return;
            }
            Result.Active += StateValue->Barrier.Active();
            Result.Started += StateValue->Started.load(std::memory_order_acquire);
            Result.Completed += StateValue->Completed.load(std::memory_order_acquire);
            Result.Cancelled += StateValue->Cancelled.load(std::memory_order_acquire);
            Result.Failed += StateValue->Failed.load(std::memory_order_acquire);
            Result.Quarantined += StateValue->Quarantined.load(std::memory_order_acquire);
            Result.DrainBlocked = Result.DrainBlocked ||
                                  StateValue->Blocked.load(std::memory_order_acquire) ||
                                  StateValue->Barrier.IsBlocked() ||
                                  StateValue->Descendants.DrainBlocked.load(std::memory_order_acquire);
            Result.Active += StateValue->Descendants.Active.load(std::memory_order_acquire);
            Result.Started += StateValue->Descendants.Started.load(std::memory_order_acquire);
            Result.Completed += StateValue->Descendants.Completed.load(std::memory_order_acquire);
            Result.Cancelled += StateValue->Descendants.Cancelled.load(std::memory_order_acquire);
            Result.Failed += StateValue->Descendants.Failed.load(std::memory_order_acquire);
            Result.Quarantined += StateValue->Descendants.Quarantined.load(std::memory_order_acquire);
        }

        inline auto QuarantineTaskSlots(
            const std::shared_ptr<TaskRegistryState>& StateValue) noexcept -> void
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

        /** @brief registry 退休命令在原 executor 被隔离时仍逐 slot 收口，不静默丢弃。 */
        struct TaskRegistryRetirementCommand final
        {
            std::shared_ptr<TaskRegistryState> State;

            explicit TaskRegistryRetirementCommand(std::shared_ptr<TaskRegistryState> Value)
                : State(std::move(Value)) {}

            auto operator()() noexcept -> void
            {
                QuarantineTaskSlots(State);
                State->RetirementPending.store(false, std::memory_order_release);
                if (State->ClosingRetained.load(std::memory_order_acquire))
                    State->ClosingStorage->Collect();
            }

            auto OnQuarantine() noexcept -> void
            {
                if (!State) return;
                State->Blocked.store(true, std::memory_order_release);
                State->Barrier.Block();
                MarkAggregateBlocked(State);
                QuarantineTaskSlots(State);
                State->RetirementPending.store(false, std::memory_order_release);
            }
        };

        /** @brief 由进程恢复本 scope 退休，不取消仍有独立 owner 的后代，不修改 active 事实。 */
        inline auto TaskRegistryState::RequestRetirement() -> void
        {
            Accepting.store(false);
            CancelRequested.store(true);
            TearingDown.store(true, std::memory_order_release);
            Barrier.Seal();
            bool Expected = false;
            if (!RetirementPending.compare_exchange_strong(
                    Expected, true, std::memory_order_acq_rel, std::memory_order_acquire))
                return;
            auto Self = shared_from_this();
            ClosingRetained.store(true, std::memory_order_release);
            ClosingStorage->Retain(Self);
            if (!Reclaimer->Post(TaskRegistryRetirementCommand(Self)))
            {
                Blocked.store(true, std::memory_order_release);
                Barrier.Block();
                MarkAggregateBlocked(Self);
                ClosingStorage->Retain(Self);
            }
        }
    } // namespace Detail

} // namespace Prism::Lifecycle
