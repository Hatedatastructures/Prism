/**
 * @file AdmissionInput.hpp
 * @brief TUIC admission 输入交付的私有状态声明。
 */
#pragma once

#include <Prism/Protocols/Tuic/Admission.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>

namespace Prism::Tuic
{
    class ConnectionAdmission::InputDelivery final : public Prism::Executor::ClosingResource,
        public std::enable_shared_from_this<ConnectionAdmission::InputDelivery>
    {
        friend class ConnectionAdmission;
        enum class DeliveryState : std::uint8_t
        {
            Created,
            Queued,
            Retryable,
            Running,
            Failed,
            Quarantined,
            Completed
        };
        static constexpr std::size_t NoRetrySlot = MaxRetryableInputDeliveries;
        static constexpr std::size_t RegisteringRetrySlot = MaxRetryableInputDeliveries + 1U;

        struct InputDeliveryAction final
        {
            std::shared_ptr<InputDelivery> Delivery;
            auto operator()() noexcept -> void;
            auto OnQuarantine() noexcept -> void;
        };

    public:
        InputDelivery(std::shared_ptr<ConnectionAdmission> Owner, InputEvent Event);

        /** @brief 首次提交；只有 Reclaimer 明确拒收后才登记可复投状态。 */
        [[nodiscard]] auto SubmitInitial() -> std::expected<void, Prism::Fault::Failure>;

        /** @brief 只重投仍处于明确拒收状态的原始事件。 */
        [[nodiscard]] auto RetryRejected() -> std::expected<void, Prism::Fault::Failure>;

        /** @brief 由实际原 executor 处理已接受输入；失败与未知结果保留原 reservation。 */
        auto Deliver() noexcept -> void;

        /** @brief 已接受动作被隔离后标为未知终态；绝不把它当作可复投拒收。 */
        auto OnQuarantine() noexcept -> void;

        auto RequestRetirement() -> void override;
        [[nodiscard]] auto IsRetired() const noexcept -> bool override;
        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override;

    private:
        [[nodiscard]] auto Submit(DeliveryState ExpectedState)
            -> std::expected<void, Prism::Fault::Failure>;
        [[nodiscard]] auto IsCurrentEvent() const noexcept -> bool;
        [[nodiscard]] auto DeliverEvent() -> bool;
        auto Fail(Prism::Fault::Failure Reason) noexcept -> void;
        auto RetainFailure(Prism::Fault::Failure Reason) noexcept -> void;
        auto MarkRetryIndexMissing() noexcept -> void;
        auto ClearRetryIndexMissing() noexcept -> void;

        std::shared_ptr<ConnectionAdmission> Owner_;
        InputEvent Event_;
        std::shared_ptr<Prism::Executor::ClosingStorage> Storage_;
        Prism::Lifecycle::TaskIdentity Identity_{};
        std::atomic<DeliveryState> State_{DeliveryState::Created};
        std::atomic<std::size_t> RetrySlot_{NoRetrySlot};
        std::atomic<bool> RetryIndexMissing_{false};
    };
}
