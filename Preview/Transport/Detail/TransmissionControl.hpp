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

            struct Command final
            {
                std::atomic<bool> Used{false};
                std::atomic<bool> Retryable{false};
                std::atomic<bool> RetryInFlight{false};
                std::atomic<bool> KnownControlFailure{false};
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
                    Owner->Commands[Index].RetryInFlight.store(false, std::memory_order_release);
                    Owner->Activity->EndControlRetry();
                    Retry = false;
                }

                ~Delivery()
                {
                    if (!Owner) return;
                    auto& CommandValue = Owner->Commands[Index];
                    if (!Invoked || !HandlerInvoked)
                    {
                        FinishRetry();
                        Owner->FailUnknown();
                        return;
                    }
                    if (!Returned)
                        Owner->RecordKnownFailure(Index,
                            {Preview::Fault::Code::Blocked});
                    if (!Succeeded)
                    {
                        if (!Owner->Unrecoverable.load(std::memory_order_acquire))
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
                    Owner->ResolveKnownFailure(Index);
                    CommandValue.Reservation->Returned();
                    CommandValue.Reservation.reset();
                    CommandValue.Carrier.store({});
                    CommandValue.Used.store(false, std::memory_order_release);
                    Owner->Storage->Collect();
                    FinishRetry();
                }

                auto operator()() -> void;
                auto OnQuarantine() noexcept -> void
                {
                    if (Owner) Owner->FailUnknown();
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
                ExternalCloseConfirmed.store(true, std::memory_order_release);
                ResolveKnownFailure(CancelCapacity);
                Activity->RecordCloseDelivered();
                Activity->Seal();
                LocalClosed.store(true, std::memory_order_release);
                Finished.store(true, std::memory_order_release);
                if (CloseUsed && !CloseCommand.RetryInFlight.load(std::memory_order_acquire))
                    ReleaseCommand(CancelCapacity);
                for (std::size_t Index = 0; Index < CancelCapacity; ++Index)
                {
                    auto& CommandValue = Commands[Index];
                    if (CommandValue.Used.load(std::memory_order_acquire) &&
                        CommandValue.KnownControlFailure.load(std::memory_order_acquire) &&
                        !CommandValue.RetryInFlight.load(std::memory_order_acquire))
                    {
                        ReleaseCommand(Index);
                    }
                }
                Storage->Collect();
            }

            /** @brief 真实底层关闭后释放控制预约，但保留其历史首因供 Drain 返回。 */
            auto ReleaseCommand(std::size_t Index) noexcept -> void
            {
                auto& CommandValue = Commands[Index];
                ResolveKnownFailure(Index);
                if (CommandValue.Reservation)
                {
                    CommandValue.Reservation->Returned();
                    CommandValue.Reservation.reset();
                }
                CommandValue.Carrier.store({});
                CommandValue.Retryable.store(false, std::memory_order_release);
                CommandValue.Used.store(false, std::memory_order_release);
            }

            auto Execute(std::size_t Index, bool& HandlerInvoked) -> bool;

            auto RecordKnownFailure(
                std::size_t Index,
                Preview::Fault::Failure Error) noexcept -> void
            {
                auto& CommandValue = Commands[Index];
                const bool NewForCommand = !CommandValue.KnownControlFailure.load(
                    std::memory_order_acquire);
                Failure.TrySet(Error);
                Blocked.store(true, std::memory_order_release);
                Activity->RecordControlFailure(Error, NewForCommand);
                if (NewForCommand)
                    CommandValue.KnownControlFailure.store(true, std::memory_order_release);
                Storage->Retain(shared_from_this());
            }

            auto ResolveKnownFailure(std::size_t Index) noexcept -> void
            {
                if (Commands[Index].KnownControlFailure.exchange(
                        false, std::memory_order_acq_rel))
                    Activity->ResolveControlFailure();
                Commands[Index].Retryable.store(false, std::memory_order_release);
            }

            auto FailUnknown(
                Preview::Fault::Failure Error =
                    {Preview::Fault::Code::Blocked}) noexcept -> void
            {
                Failure.TrySet(Error);
                Blocked.store(true, std::memory_order_release);
                Unrecoverable.store(true, std::memory_order_release);
                Activity->Block(Error);
                Storage->Retain(shared_from_this());
            }

            auto RequestRetirement() -> void override
            {
                if (ExternalCloseConfirmed.load(std::memory_order_acquire) ||
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
                        !Commands[Index].KnownControlFailure.load(std::memory_order_acquire))
                        continue;
                    bool Idle = false;
                    if (!Commands[Index].RetryInFlight.compare_exchange_strong(
                            Idle, true, std::memory_order_acq_rel))
                        continue;
                    if (!Commands[Index].Retryable.exchange(false, std::memory_order_acq_rel))
                    {
                        Commands[Index].RetryInFlight.store(false, std::memory_order_release);
                        continue;
                    }
                    Activity->BeginControlRetry();
                    const auto Posted = Reclaimer->Post(
                        Delivery(shared_from_this(), Index, true));
                    if (!Posted) FailUnknown(Posted.error());
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
    }
}
