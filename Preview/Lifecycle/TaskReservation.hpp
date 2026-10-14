/** @file TaskReservation.hpp @brief task slot、取消节点与 drain 的唯一 move-only 预约。 */
#pragma once
#include <Preview/Lifecycle/TaskRegistryState.hpp>
#include <expected>
#include <functional>
#include <optional>
namespace Preview::Lifecycle
{
    /** @brief 入场即接管 slot 和屏障，析构只归还仍持有的真实预约。
     * @details owner 跨投递/协程/完成保活；取消节点在原 executor 解链；无半关闭。
     * 禁止根据逻辑完成提前归还；完成 handler 析构表示协程已经退栈。
     */
    class TaskReservation final
    {
    public:
        using State = Detail::TaskRegistryState;
        TaskReservation(const TaskReservation&) = delete;
        auto operator=(const TaskReservation&) -> TaskReservation& = delete;
        TaskReservation(TaskReservation&& Other) noexcept
            : Owner_(std::move(Other.Owner_)), Slot_(Other.Slot_), Domain_(std::move(Other.Domain_)), Published_(std::exchange(Other.Published_, false)) {}
        ~TaskReservation()
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
        /** @brief 同步预约有限 slot；成功 Enter 后立即形成 RAII，不夹入任何分配。 */
        [[nodiscard]] static auto Acquire(std::shared_ptr<State> Owner)
            -> std::expected<TaskReservation, Preview::Fault::Failure>
        {
            for (std::size_t Index = 0; Index < Detail::TaskSlotPool::Capacity; ++Index)
            {
                bool Empty = false;
                if (!Owner->Pool->Slots[Index].Used.compare_exchange_strong(Empty, true)) continue;
                if (!Owner->Barrier.Enter())
                {
                    Owner->Pool->Slots[Index].Used.store(false);
                    return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Canceled});
                }
                TaskReservation Result(std::move(Owner), Index);
                Result.Owner_->Pool->Slots[Index].Scope.store(Result.Owner_.get());
                Detail::AddAggregate(Result.Owner_, Detail::AggregateMetric::Active, true);
                return Result;
            }
            return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::ResourceUnavailable});
        }
        /** @brief 预约拥有本任务独立取消节点，节点失败同预约回滚。 */
        auto Attach(std::shared_ptr<CancellationDomain> Domain) noexcept -> void { Domain_ = std::move(Domain); }
        /** @brief 仅原 command executor 发布活动任务；返回借用不能越过预约。 */
        auto Publish(std::shared_ptr<TaskState> Task) -> void
        { Published_ = true; Owner_->Pool->Slots[Slot_].Task = std::move(Task); }
        /** @brief 登记原 executor 上的 submission quarantine 入口，不保存反向强引用。 */
        auto SetQuarantine(std::function<void()> Callback) -> void
        { Owner_->Pool->Slots[Slot_].Quarantine = std::move(Callback); }
        [[nodiscard]] auto Owner() const noexcept -> const std::shared_ptr<State>& { return Owner_; }
    private:
        TaskReservation(std::shared_ptr<State> Owner, std::size_t Slot) noexcept
            : Owner_(std::move(Owner)), Slot_(Slot) {}
        std::shared_ptr<State> Owner_;
        std::size_t Slot_{};
        std::shared_ptr<CancellationDomain> Domain_;
        bool Published_{false};
    };
}
