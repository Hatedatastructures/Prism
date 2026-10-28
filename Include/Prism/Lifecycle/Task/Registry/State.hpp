/**
 * @file State.hpp
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
#include <Prism/Lifecycle/Task/State.hpp>


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
                std::function<void(const TaskIdentity &, Prism::Fault::Failure)> Failure);

            TaskRegistryState(
                boost::asio::any_io_executor ExecutorValue,
                std::function<void(const TaskIdentity &, Prism::Fault::Failure)> Failure,
                std::shared_ptr<TaskRegistryState> ParentState);

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
            auto RetainClosing() noexcept -> void;
            /** @brief 保留未投递的退役请求；executor 恢复后允许显式 Retry 重投。 */
            auto RetainUnavailableRetirement() noexcept -> void;
            auto RequestRetirement() -> void override;
            [[nodiscard]] auto IsRetired() const noexcept -> bool override;
            [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override;
            DrainBarrier Barrier;
            std::shared_ptr<Prism::Executor::ClosingStorage> ClosingStorage;
            std::atomic<bool> ClosingRetained{false};
            /** @brief 原 executor 退休命令尚未完成时为 true；失败事实由 Blocked 单独保留。 */
            std::atomic<bool> RetirementPending{false};
            /** @brief 尚未交付、等待 ClosingStorage 在 executor 恢复后重试的退休请求。 */
            std::atomic<bool> RetirementUnavailable{false};
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

        auto AggregateCounter(
            TaskRegistryState &StateValue,
            const AggregateMetric Metric) noexcept -> std::atomic<std::size_t> &;

        auto AddAggregate(
            const std::shared_ptr<TaskRegistryState> &StateValue,
            const AggregateMetric Metric,
            const bool Increment) noexcept -> void;

        auto MarkAggregateBlocked(
            const std::shared_ptr<TaskRegistryState> &StateValue) noexcept -> void;

        auto LeaveTrackedTask(
            const std::shared_ptr<TaskRegistryState> &StateValue) noexcept -> void;

        auto RecordStarted(
            const std::shared_ptr<TaskRegistryState> &StateValue) noexcept -> void;

        auto RecordCompleted(
            const std::shared_ptr<TaskRegistryState> &StateValue,
            const TaskOutcome Outcome) noexcept -> void;

        auto AddTaskStats(
            TaskStats &Result,
            const std::shared_ptr<TaskRegistryState> &StateValue) noexcept -> void;

        auto QuarantineTaskSlots(
            const std::shared_ptr<TaskRegistryState>& StateValue) noexcept -> void;

        /** @brief registry 退休命令在原 executor 被隔离时仍逐 slot 收口，不静默丢弃。 */
        struct TaskRegistryRetirementCommand final
        {
            std::shared_ptr<TaskRegistryState> State;

            explicit TaskRegistryRetirementCommand(std::shared_ptr<TaskRegistryState> Value)
                : State(std::move(Value)) {}

            auto operator()() noexcept -> void;
            auto OnQuarantine() noexcept -> void;
        };

    } // namespace Detail

} // namespace Prism::Lifecycle
