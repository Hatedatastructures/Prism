/** @file TransmissionControl.hpp @brief Transmission 原 executor 控制 owner。 */
#pragma once

#include <Prism/Contract/Io/CarrierCloseReceipt.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Transport/Detail/IoActivity.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <mutex>
#include <memory>
#include <optional>
#include <utility>

namespace Prism
{
    class Transmission;

    namespace Transport::Detail
    {
        /** @brief 固定原 executor 的唯一 close/cancel 提交、重试与外部终态回执 owner。 */
        class TransmissionControlOwner final
            : public Prism::Executor::ClosingResource,
              public Prism::Contract::CarrierCloseReceipt,
              public std::enable_shared_from_this<TransmissionControlOwner>
        {
        public:
            static constexpr unsigned CancelFlag = 1;
            static constexpr unsigned CloseFlag = 2;
            static constexpr std::size_t CancelCapacity = 64;
            using ControlResult = std::expected<void, Prism::Fault::Failure>;
            enum class KnownFailurePhase : std::uint8_t
            {
                None,
                Recording,
                Recorded,
                ResolveRequested,
                Resolving,
            };
            enum class RetryState : std::uint8_t
            {
                Idle,
                InFlight,
                ClosePending,
            };
            enum class CloseAttemptPhase : std::uint8_t
            {
                Idle,
                Posting,
                Accepted,
                Terminal,
            };

            struct Command final
            {
                std::atomic<bool> Used{false};
                std::atomic<bool> Retryable{false};
                std::atomic<RetryState> Retry{RetryState::Idle};
                std::atomic<KnownFailurePhase> KnownControlFailure{KnownFailurePhase::None};
                std::atomic<bool> ReleaseRequested{false};
                std::atomic<bool> AwaitingExternalReceipt{false};
                std::atomic<std::shared_ptr<Prism::Transmission>> Carrier;
                std::optional<IoActivity::Operation> Reservation;
            };

            TransmissionControlOwner(
                boost::asio::any_io_executor Domain,
                std::shared_ptr<IoActivity> ActivityOwner);

            struct Delivery final
            {
                std::shared_ptr<TransmissionControlOwner> Owner;
                std::size_t Index;
                bool Invoked{false};
                bool HandlerInvoked{false};
                bool Returned{false};
                bool Succeeded{false};
                bool Retry{false};

                Delivery(std::shared_ptr<TransmissionControlOwner> Value,
                    std::size_t Slot, bool IsRetry = false);
                Delivery(Delivery&& Other) noexcept;
                auto FinishRetry() noexcept -> void;
                ~Delivery();

                auto operator()() -> void;
                auto OnQuarantine() noexcept -> void;
            };

            /** @brief 真实外部关闭回执的原域交付；已接受后丢弃仍是未知失败。 */
            struct ExternalCloseDelivery final
            {
                std::shared_ptr<TransmissionControlOwner> Owner;
                bool Invoked{false};
                bool Retry{false};
                ExternalCloseDelivery(std::shared_ptr<TransmissionControlOwner> Value, bool IsRetry);
                ExternalCloseDelivery(ExternalCloseDelivery&& Other) noexcept;
                ~ExternalCloseDelivery();
                auto operator()() noexcept -> void;
                auto OnQuarantine() noexcept -> void;
            };

            [[nodiscard]] auto Submit(
                std::shared_ptr<Prism::Transmission> Carrier,
                unsigned Flag) -> ControlResult;

            auto ConfirmExternalClose() noexcept -> void override;

            /** @brief 返回本控制 owner 的真实活动排空，不依赖 wrapper 对象存活。 */
            [[nodiscard]] auto Drain()
                -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override;

            [[nodiscard]] auto AwaitCloseDispatch()
                -> boost::asio::awaitable<ControlResult> override;

            auto MarkCloseAttemptAccepted() noexcept -> void;
            auto CompleteCloseAttempt(Prism::Fault::Failure Failure = {}) noexcept -> void;
            auto NotifyCloseAttemptWaiter() noexcept -> void;

            auto DeliverExternalClose() noexcept -> void;
            /** @brief 成功 close 接管空闲命令；进行中的重试收到关闭待处理状态。 */
            [[nodiscard]] auto TryClaimCloseRetry(std::size_t Index) noexcept -> bool;

            /** @brief 请求释放控制预约；失败登记并发时延后释放至其计数结算。 */
            auto ReleaseCommand(std::size_t Index) noexcept -> void;

            auto CompleteCommandRelease(std::size_t Index) noexcept -> void;

            /** @brief 已无控制操作可重试时，将关闭抢占后的预约结算交回原 executor。 */
            auto CompleteRetryWithoutOperation(std::size_t Index) noexcept -> bool;

            /** @brief 成功的最终 close 退休已经完成的可重试 cancel 命令。 */
            auto ReleaseKnownCancelFailuresAfterClose() noexcept -> void;

            auto Execute(std::size_t Index, bool& HandlerInvoked, bool IsRetry) -> bool;

            auto RecordKnownFailure(
                std::size_t Index,
                Prism::Fault::Failure Error) noexcept -> bool;

            [[nodiscard]] auto ResolveKnownFailure(std::size_t Index) noexcept -> bool;

            [[nodiscard]] auto IsControlClosed(std::size_t Index) const noexcept -> bool;

            auto FailUnknown(
                Prism::Fault::Failure Error =
                    {Prism::Fault::Code::Blocked}) noexcept -> void;

            auto RequestRetirement() -> void override;

            [[nodiscard]] auto IsRetired() const noexcept -> bool override;

            [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override;

            [[nodiscard]] auto BeginCloseAttempt() noexcept -> bool;

            std::shared_ptr<Prism::Executor::ContextOwner> Context;
            std::shared_ptr<Prism::Executor::ClosingStorage> Storage;
            std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer;
            /** @brief 关闭回执等待状态只由等待协程持有；owner 仅保存弱引用。 */
            struct CloseWaitState;
            std::weak_ptr<CloseWaitState> CloseWaiter;
            std::shared_ptr<IoActivity> Activity;
            std::array<Command, CancelCapacity + 1> Commands;
            std::atomic<bool> Finished{false};
            std::atomic<bool> LocalClosed{false};
            std::atomic<bool> Blocked{false};
            std::atomic<bool> Unrecoverable{false};
            std::atomic<bool> AcceptedClose{false};
            std::atomic<CloseAttemptPhase> CloseAttempt{CloseAttemptPhase::Idle};
            std::atomic<std::size_t> CloseAttemptWaiters{0};
            std::atomic<bool> CloseAttemptCompletionClaimed{false};
            std::mutex CloseDispatchMutex;
            std::atomic<bool> ExternalReceiptPending{false}, ExternalCloseConfirmed{false};
            std::atomic<bool> ExternalReceiptRetryInFlight{false};
            Prism::Fault::FailureState Failure;
            Prism::Fault::FailureState CloseAttemptFailure;
        };

    }
}
