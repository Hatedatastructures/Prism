/** @file TaskRegistryCommands.hpp @brief 任务提交、真实完成与取消的唯一执行域。 */
#pragma once
#include <Preview/Lifecycle/TaskReservation.hpp>
namespace Preview::Lifecycle::Detail
{
    inline auto MarkTaskRegistryBlocked(const std::shared_ptr<TaskRegistryState>& State) noexcept -> void
    { State->Blocked.store(true); State->Barrier.Block(); MarkAggregateBlocked(State); }
    inline auto SealTaskRegistryState(const std::shared_ptr<TaskRegistryState>& State) noexcept -> void
    { State->Accepting.store(false); State->Barrier.Seal(); }
    template<class Action>
    inline auto PostTaskRegistryCommand(const std::shared_ptr<TaskRegistryState>& State, Action Command) -> bool
    {
        if (State->Reclaimer->Post(std::move(Command))) return true;
        MarkTaskRegistryBlocked(State);
        return false;
    }
    inline auto RequestTaskCancel(const std::shared_ptr<TaskRegistryState>& State,
        const std::shared_ptr<TaskState>& Task) -> void
    {
        if (!Task) return;
        (void)Task->RequestCancel();
        if (Task->IsCancelDispatchFailed()) MarkTaskRegistryBlocked(State);
    }
}
