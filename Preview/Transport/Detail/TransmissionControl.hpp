/** @file TransmissionControl.hpp @brief Transmission 原 executor 控制 owner。 */
#pragma once

#include <Preview/Contract/Io/CarrierCloseReceipt.hpp>
#include <Preview/Foundation/Executor/ClosingStorage.hpp>
#include <Preview/Foundation/Executor/ContextOwner.hpp>
#include <Preview/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Preview/Foundation/Fault/FailureState.hpp>
#include <Preview/Transport/Detail/IoActivity.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <utility>

namespace Preview
{
    class Transmission;

    namespace Transport::Detail
    {
        /** @brief 固定原 executor 的唯一 close/cancel 提交、重试与外部终态回执 owner。 */
        class TransmissionControlOwner final
            : public Preview::Executor::ClosingResource,
              public Preview::Contract::CarrierCloseReceipt,
              public std::enable_shared_from_this<TransmissionControlOwner>
        {
        public:
            static constexpr unsigned CancelFlag = 1;
            static constexpr unsigned CloseFlag = 2;
            static constexpr std::size_t CancelCapacity = 64;
            using ControlResult = std::expected<void, Preview::Fault::Failure>;
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

            struct Command final
            {
                std::atomic<bool> Used{false};
                std::atomic<bool> Retryable{false};
                std::atomic<RetryState> Retry{RetryState::Idle};
                std::atomic<KnownFailurePhase> KnownControlFailure{KnownFailurePhase::None};
                std::atomic<bool> ReleaseRequested{false};
                std::atomic<bool> AwaitingExternalReceipt{false};
                std::atomic<std::shared_ptr<Preview::Transmission>> Carrier;
                std::optional<IoActivity::Operation> Reservation;
            };

            TransmissionControlOwner(
                boost::asio::any_io_executor Domain,
                std::shared_ptr<IoActivity> ActivityOwner)
                : Context(Preview::Executor::ContextOwner::Find(Domain)),
                  Storage(Preview::Executor::ContextOwner::Storage(Domain)),
                  Reclaimer(std::make_shared<Preview::Executor::ExecutorReclaimer>(
                      boost::asio::make_strand(std::move(Domain)))),
                  Activity(std::move(ActivityOwner))
            {
            }

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
                    std::size_t Slot, bool IsRetry = false)
                    : Owner(std::move(Value)), Index(Slot), Retry(IsRetry)
                {
                }

                Delivery(Delivery&& Other) noexcept
                    : Owner(std::move(Other.Owner)), Index(Other.Index), Invoked(Other.Invoked),
                      HandlerInvoked(Other.HandlerInvoked), Returned(Other.Returned),
                      Succeeded(Other.Succeeded), Retry(Other.Retry)
                {
                }

                auto FinishRetry() noexcept -> void
                {
                    if (!Retry || !Owner) return;
                    Owner->Commands[Index].Retry.store(
                        RetryState::Idle, std::memory_order_release);
                    Owner->Activity->EndControlRetry();
                    Retry = false;
                }

                ~Delivery()
                {
                    if (!Owner) return;
                    auto& CommandValue = Owner->Commands[Index];
                    if (!Invoked || !HandlerInvoked)
                    {
                        OnQuarantine();
                        return;
                    }
                    if (!Returned)
                    {
                        const auto Recorded = Owner->RecordKnownFailure(Index,
                            {Preview::Fault::Code::Blocked});
                        if (!Recorded) Owner->ReleaseCommand(Index);
                    }
                    if (!Succeeded)
                    {
                        if (Owner->IsControlClosed(Index))
                            Owner->ReleaseCommand(Index);
                        else if (!Owner->Unrecoverable.load(std::memory_order_acquire))
                            CommandValue.Retryable.store(true, std::memory_order_release);
                        FinishRetry();
                        return;
                    }
                    if (Index == CancelCapacity &&
                        CommandValue.AwaitingExternalReceipt.load(std::memory_order_acquire))
                    {
                        Owner->Storage->Retain(Owner);
                        FinishRetry();
                        return;
                    }
                    if (Index == CancelCapacity)
                        Owner->ReleaseKnownCancelFailuresAfterClose();
                    Owner->ReleaseCommand(Index);
                    if (Index == CancelCapacity)
                        Owner->Activity->RecordCloseDelivered();
                    Owner->Storage->Collect();
                    FinishRetry();
                }

                auto operator()() -> void;
                auto OnQuarantine() noexcept -> void
                {
                    if (!Owner) return;
                    const bool CloseSettled =
                        Retry && Owner->CompleteRetryWithoutOperation(Index);
                    Retry = false;
                    if (!CloseSettled && Owner->IsControlClosed(Index))
                        Owner->ReleaseCommand(Index);
                    else if (!CloseSettled) Owner->FailUnknown();
                    Owner.reset();
                }
            };

            /** @brief 真实外部关闭回执的原域交付；已接受后丢弃仍是未知失败。 */
            struct ExternalCloseDelivery final
            {
                std::shared_ptr<TransmissionControlOwner> Owner;
                bool Invoked{false};
                bool Retry{false};
                ExternalCloseDelivery(std::shared_ptr<TransmissionControlOwner> Value, bool IsRetry)
                    : Owner(std::move(Value)), Retry(IsRetry) {}
                ExternalCloseDelivery(ExternalCloseDelivery&& Other) noexcept
                    : Owner(std::move(Other.Owner)), Invoked(Other.Invoked), Retry(Other.Retry) {}
                ~ExternalCloseDelivery()
                {
                    if (!Owner) return;
                    if (!Invoked) Owner->FailUnknown();
                    Owner->ExternalReceiptRetryInFlight.store(false, std::memory_order_release);
                    if (Retry)
                    {
                        Owner->Activity->EndControlRetry();
                    }
                }
                auto operator()() noexcept -> void
                {
                    Invoked = true;
                    Owner->ExternalReceiptPending.store(false, std::memory_order_release);
                    Owner->DeliverExternalClose();
                }
                auto OnQuarantine() noexcept -> void { Owner->FailUnknown(); }
            };

            [[nodiscard]] auto Submit(
                std::shared_ptr<Preview::Transmission> Carrier,
                unsigned Flag) -> ControlResult;

            auto ConfirmExternalClose() noexcept -> void override
            {
                if (ExternalCloseConfirmed.load(std::memory_order_acquire) ||
                    ExternalReceiptPending.exchange(true, std::memory_order_acq_rel)) return;
                if (!Reclaimer->CanDispatch() && !Reclaimer->IsQuarantined())
                {
                    RecordKnownFailure(CancelCapacity, {Preview::Fault::Code::Blocked});
                    return;
                }
                ExternalReceiptRetryInFlight.store(true, std::memory_order_release);
                Activity->BeginControlRetry();
                const auto Posted = Reclaimer->Post(
                    ExternalCloseDelivery(shared_from_this(), true));
                if (!Posted) FailUnknown(Posted.error());
            }

            /** @brief 返回本控制 owner 的真实活动排空，不依赖 wrapper 对象存活。 */
            [[nodiscard]] auto Drain()
                -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>> override
            {
                const auto Retired = co_await Activity->Drain();
                if (!Retired) co_return std::unexpected(Retired.error());
                const auto Historical = Failure.Load();
                if (Historical.Failed()) co_return std::unexpected(Historical);
                co_return std::expected<void, Preview::Fault::Failure>{};
            }

            auto DeliverExternalClose() noexcept -> void
            {
                auto& CloseCommand = Commands[CancelCapacity];
                const auto CloseUsed = CloseCommand.Used.load(std::memory_order_acquire);
                if (CloseUsed && !CloseCommand.AwaitingExternalReceipt.exchange(
                        false, std::memory_order_acq_rel))
                {
                    FailUnknown();
                    return;
                }
                const bool OwnsCloseRetry = CloseUsed && TryClaimCloseRetry(CancelCapacity);
                ExternalCloseConfirmed.store(true, std::memory_order_release);
                if (!CloseUsed || OwnsCloseRetry)
                    (void)ResolveKnownFailure(CancelCapacity);
                Activity->Seal();
                LocalClosed.store(true, std::memory_order_release);
                Finished.store(true, std::memory_order_release);
                if (OwnsCloseRetry)
                {
                    ReleaseCommand(CancelCapacity);
                    CloseCommand.Retry.store(RetryState::Idle, std::memory_order_release);
                }
                ReleaseKnownCancelFailuresAfterClose();
                Activity->RecordCloseDelivered();
                Storage->Collect();
            }
            /** @brief 成功 close 接管空闲命令；进行中的重试收到关闭待处理状态。 */
            [[nodiscard]] auto TryClaimCloseRetry(std::size_t Index) noexcept -> bool
            {
                auto& Retry = Commands[Index].Retry;
                auto State = Retry.load(std::memory_order_acquire);
                while (State != RetryState::ClosePending)
                {
                    const auto Target = State == RetryState::Idle ? RetryState::InFlight : RetryState::ClosePending;
                    if (Retry.compare_exchange_weak(State, Target, std::memory_order_acq_rel))
                        return Target == RetryState::InFlight;
                }
                return false;
            }

            /** @brief 请求释放控制预约；失败登记并发时延后释放至其计数结算。 */
            auto ReleaseCommand(std::size_t Index) noexcept -> void
            {
                auto& CommandValue = Commands[Index];
                CommandValue.ReleaseRequested.store(true, std::memory_order_release);
                if (ResolveKnownFailure(Index)) CompleteCommandRelease(Index);
            }

            auto CompleteCommandRelease(std::size_t Index) noexcept -> void
            {
                auto& CommandValue = Commands[Index];
                if (!CommandValue.ReleaseRequested.exchange(false,
                        std::memory_order_acq_rel)) return;
                if (CommandValue.Reservation)
                {
                    CommandValue.Reservation->Returned();
                    CommandValue.Reservation.reset();
                }
                CommandValue.Carrier.store({});
                CommandValue.Retryable.store(false, std::memory_order_release);
                CommandValue.Used.store(false, std::memory_order_release);
            }

            /** @brief 已无控制操作可重试时，将关闭抢占后的预约结算交回原 executor。 */
            auto CompleteRetryWithoutOperation(std::size_t Index) noexcept -> bool
            {
                auto& CommandValue = Commands[Index];
                auto Expected = RetryState::InFlight;
                if (CommandValue.Retry.compare_exchange_strong(Expected,
                        RetryState::Idle, std::memory_order_acq_rel))
                {
                    Activity->EndControlRetry(); Storage->Collect();
                    return false;
                }
                const bool CloseWasPending = Expected == RetryState::ClosePending;
                if (CloseWasPending)
                {
                    ReleaseCommand(Index);
                    CommandValue.Retry.store(RetryState::Idle, std::memory_order_release);
                }
                Activity->EndControlRetry(); Storage->Collect();
                return CloseWasPending;
            }

            /** @brief 成功的最终 close 退休已经完成的可重试 cancel 命令。 */
            auto ReleaseKnownCancelFailuresAfterClose() noexcept -> void
            {
                for (std::size_t Index = 0U; Index < CancelCapacity; ++Index)
                {
                    auto& CommandValue = Commands[Index];
                    if (!TryClaimCloseRetry(Index)) continue;
                    if (CommandValue.Used.load(std::memory_order_acquire) &&
                        CommandValue.KnownControlFailure.load(std::memory_order_acquire) !=
                            KnownFailurePhase::None)
                    {
                        ReleaseCommand(Index);
                    }
                    CommandValue.Retry.store(RetryState::Idle, std::memory_order_release);
                }
            }

            auto Execute(std::size_t Index, bool& HandlerInvoked) -> bool;

            auto RecordKnownFailure(
                std::size_t Index,
                Preview::Fault::Failure Error) noexcept -> bool
            {
                auto& CommandValue = Commands[Index];
                auto Expected = KnownFailurePhase::None;
                if (!CommandValue.KnownControlFailure.compare_exchange_strong(
                        Expected, KnownFailurePhase::Recording,
                        std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    Storage->Retain(shared_from_this());
                    return true;
                }
                if (IsControlClosed(Index))
                {
                    Expected = KnownFailurePhase::Recording;
                    if (!CommandValue.KnownControlFailure.compare_exchange_strong(
                            Expected, KnownFailurePhase::None,
                            std::memory_order_acq_rel, std::memory_order_acquire) &&
                        Expected == KnownFailurePhase::ResolveRequested)
                    {
                        CommandValue.KnownControlFailure.store(
                            KnownFailurePhase::None, std::memory_order_release);
                    }
                    CommandValue.Retryable.store(false, std::memory_order_release);
                    CompleteCommandRelease(Index);
                    Storage->Retain(shared_from_this());
                    return false;
                }
                (void)Failure.TrySet(Error);
                Blocked.store(true, std::memory_order_release);
                Activity->RecordControlFailure(Error, true, Index == CancelCapacity);
                CommandValue.Retryable.store(true, std::memory_order_release);
                Expected = KnownFailurePhase::Recording;
                if (!CommandValue.KnownControlFailure.compare_exchange_strong(
                        Expected, KnownFailurePhase::Recorded,
                        std::memory_order_acq_rel, std::memory_order_acquire) &&
                    Expected == KnownFailurePhase::ResolveRequested)
                {
                    Activity->ResolveControlFailure(Index == CancelCapacity);
                    CommandValue.KnownControlFailure.store(
                        KnownFailurePhase::None, std::memory_order_release);
                    CommandValue.Retryable.store(false, std::memory_order_release);
                    CompleteCommandRelease(Index);
                }
                Storage->Retain(shared_from_this());
                return true;
            }

            [[nodiscard]] auto ResolveKnownFailure(std::size_t Index) noexcept -> bool
            {
                auto& CommandValue = Commands[Index];
                auto Phase = CommandValue.KnownControlFailure.load(
                    std::memory_order_acquire);
                for (;;)
                {
                    if (Phase == KnownFailurePhase::None)
                    {
                        CommandValue.Retryable.store(false, std::memory_order_release);
                        return true;
                    }
                    if (Phase == KnownFailurePhase::ResolveRequested ||
                        Phase == KnownFailurePhase::Resolving)
                    {
                        CommandValue.Retryable.store(false, std::memory_order_release);
                        return false;
                    }
                    if (Phase == KnownFailurePhase::Recording)
                    {
                        if (CommandValue.KnownControlFailure.compare_exchange_weak(
                                Phase, KnownFailurePhase::ResolveRequested,
                                std::memory_order_acq_rel, std::memory_order_acquire))
                        {
                            CommandValue.Retryable.store(false, std::memory_order_release);
                            return false;
                        }
                        continue;
                    }
                    if (CommandValue.KnownControlFailure.compare_exchange_weak(
                            Phase, KnownFailurePhase::Resolving,
                            std::memory_order_acq_rel, std::memory_order_acquire))
                    {
                        Activity->ResolveControlFailure(Index == CancelCapacity);
                        CommandValue.KnownControlFailure.store(
                            KnownFailurePhase::None, std::memory_order_release);
                        CommandValue.Retryable.store(false, std::memory_order_release);
                        CompleteCommandRelease(Index);
                        return true;
                    }
                }
            }

            [[nodiscard]] auto IsControlClosed(std::size_t Index) const noexcept -> bool
            {
                return LocalClosed.load(std::memory_order_acquire) ||
                    ExternalCloseConfirmed.load(std::memory_order_acquire) ||
                    Finished.load(std::memory_order_acquire);
            }

            auto FailUnknown(
                Preview::Fault::Failure Error =
                    {Preview::Fault::Code::Blocked}) noexcept -> void
            {
                (void)Failure.TrySet(Error);
                Blocked.store(true, std::memory_order_release);
                Unrecoverable.store(true, std::memory_order_release);
                Activity->Block(Error);
                Storage->Retain(shared_from_this());
            }

            auto RequestRetirement() -> void override
            {
                if (ExternalCloseConfirmed.load(std::memory_order_acquire) ||
                    LocalClosed.load(std::memory_order_acquire) ||
                    Finished.load(std::memory_order_acquire) ||
                    Unrecoverable.load(std::memory_order_acquire) || !Reclaimer->CanDispatch())
                    return;
                if (ExternalReceiptPending.load(std::memory_order_acquire))
                {
                    bool Idle = false;
                    if (ExternalReceiptRetryInFlight.compare_exchange_strong(
                            Idle, true, std::memory_order_acq_rel))
                    {
                        Activity->BeginControlRetry();
                        const auto Posted = Reclaimer->Post(
                            ExternalCloseDelivery(shared_from_this(), true));
                        if (!Posted) FailUnknown(Posted.error());
                    }
                    // 先消费已证明的真实关闭回执，不再并发重投即将归还的 close 槽。
                    return;
                }
                for (std::size_t Index = 0; Index <= CancelCapacity; ++Index)
                {
                    if (!Commands[Index].Used.load() || !Commands[Index].Carrier.load() ||
                        Commands[Index].KnownControlFailure.load(std::memory_order_acquire) !=
                            KnownFailurePhase::Recorded)
                        continue;
                    Activity->BeginControlRetry();
                    auto Expected = RetryState::Idle;
                    if (!Commands[Index].Retry.compare_exchange_strong(
                            Expected, RetryState::InFlight, std::memory_order_acq_rel))
                    {
                        Activity->EndControlRetry();
                        continue;
                    }
                    if (!Commands[Index].Retryable.exchange(false, std::memory_order_acq_rel))
                    {
                        CompleteRetryWithoutOperation(Index);
                        continue;
                    }
                    (void)Reclaimer->Post(Delivery(shared_from_this(), Index, true));
                }
            }

            [[nodiscard]] auto IsRetired() const noexcept -> bool override
            {
                for (const auto& CommandValue : Commands)
                    if (CommandValue.Used.load()) return false;
                return LocalClosed.load(std::memory_order_acquire);
            }

            [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
            {
                return Unrecoverable.load(std::memory_order_acquire) ||
                    (Blocked.load(std::memory_order_acquire) && !Reclaimer->CanDispatch());
            }

            std::shared_ptr<Preview::Executor::ContextOwner> Context;
            std::shared_ptr<Preview::Executor::ClosingStorage> Storage;
            std::shared_ptr<Preview::Executor::ExecutorReclaimer> Reclaimer;
            std::shared_ptr<IoActivity> Activity;
            std::array<Command, CancelCapacity + 1> Commands;
            std::atomic<bool> Finished{false};
            std::atomic<bool> LocalClosed{false};
            std::atomic<bool> Blocked{false};
            std::atomic<bool> Unrecoverable{false};
            std::atomic<bool> AcceptedClose{false};
            std::atomic<bool> ExternalReceiptPending{false}, ExternalCloseConfirmed{false};
            std::atomic<bool> ExternalReceiptRetryInFlight{false};
            Preview::Fault::FailureState Failure;
        };

        inline auto TransmissionControlOwner::Submit(
            std::shared_ptr<Transmission> Carrier, unsigned Flag) -> ControlResult
        {
            if (!Carrier)
                return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
            if (Flag == CancelFlag)
            {
                const auto CloseWasAccepted = AcceptedClose.load(std::memory_order_acquire);
                const auto WasClosedLocally = LocalClosed.load(std::memory_order_acquire);
                const auto WasFinished = Finished.load(std::memory_order_acquire);
                if (WasClosedLocally || WasFinished) return {};
                if (Blocked.load(std::memory_order_acquire)) return std::unexpected(Failure.Load());
                const auto ExistingFailure = Failure.Load();
                if (ExistingFailure.Failed()) return std::unexpected(ExistingFailure);
                if (CloseWasAccepted) return {};
            }
            else if (Finished.load(std::memory_order_acquire) ||
                (Flag == CloseFlag && (LocalClosed.load(std::memory_order_acquire) ||
                    ExternalCloseConfirmed.load(std::memory_order_acquire))))
            {
                return {};
            }

            std::size_t Index = CancelCapacity;
            if (Flag == CloseFlag)
            {
                if (Commands[Index].Used.exchange(true))
                {
                    if (Blocked.load(std::memory_order_acquire))
                        return std::unexpected(Failure.Load());
                    return {};
                }
            }
            else
            {
                for (Index = 0; Index < CancelCapacity; ++Index)
                    if (!Commands[Index].Used.exchange(true)) break;
                if (Index == CancelCapacity)
                    return std::unexpected(Fault::Failure{Fault::Code::ResourceUnavailable});
            }

            auto Reservation = Flag == CloseFlag
                ? Activity->TryAcquireCloseControl(Carrier)
                : Activity->TryAcquireControl(Carrier);
            if (!Reservation)
            {
                Commands[Index].Used.store(false);
                const auto ReservationFailure = Reservation.error();
                if (ReservationFailure.Code == Fault::Code::Canceled &&
                    (ExternalCloseConfirmed.load(std::memory_order_acquire) ||
                     LocalClosed.load(std::memory_order_acquire) ||
                     Finished.load(std::memory_order_acquire)))
                    return {};
                return std::unexpected(ReservationFailure);
            }
            Commands[Index].Reservation.emplace(std::move(*Reservation));
            Commands[Index].Carrier.store(std::move(Carrier));
            Commands[Index].Retryable.store(false);
            Commands[Index].Retry.store(RetryState::Idle, std::memory_order_release);
            Commands[Index].AwaitingExternalReceipt.store(false);

            if (Flag == CloseFlag && ExternalCloseConfirmed.load(std::memory_order_acquire))
            {
                ReleaseCommand(Index);
                return {};
            }

            // 原执行域停止是尚未交付的已知拒绝；保留同一命令和真实预约供显式重试。
            if (!Reclaimer->CanDispatch() && !Reclaimer->IsQuarantined())
            {
                const Fault::Failure Deferred{Fault::Code::Blocked};
                if (!RecordKnownFailure(Index, Deferred))
                {
                    ReleaseCommand(Index);
                    return {};
                }
                return std::unexpected(Deferred);
            }
            const auto Posted = Reclaimer->Post(Delivery(shared_from_this(), Index));
            if (!Posted)
            {
                FailUnknown(Posted.error());
            }
            else if (Flag == CloseFlag)
            {
                AcceptedClose.store(true, std::memory_order_release);
                Activity->RecordCloseAccepted();
            }
            return Posted;
        }
    }
}
