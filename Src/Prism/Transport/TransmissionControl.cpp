/** @file TransmissionControl.cpp @brief 取消/关闭命令预约与投递实现。 */
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Transport/Detail/TransmissionControl.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <system_error>

namespace Prism::Transport::Detail
{
    /** @brief 关闭回执等待通道只由实际等待者共同持有，owner 仅保留弱引用。 */
    struct TransmissionControlOwner::CloseWaitState final
    {
        explicit CloseWaitState(boost::asio::any_io_executor Executor)
            : Changes(std::move(Executor), 1)
        {
        }

        boost::asio::experimental::concurrent_channel<
            void(boost::system::error_code)> Changes;
    };

    TransmissionControlOwner::TransmissionControlOwner(
        boost::asio::any_io_executor Domain, std::shared_ptr<IoActivity> ActivityOwner)
        : Context(Prism::Executor::ContextOwner::Find(Domain)),
          Storage(Prism::Executor::ContextOwner::Storage(Domain)),
          Reclaimer(std::make_shared<Prism::Executor::ExecutorReclaimer>(
              boost::asio::make_strand(std::move(Domain)))),
          Activity(std::move(ActivityOwner))
    {
    }

    TransmissionControlOwner::Delivery::Delivery(
        std::shared_ptr<TransmissionControlOwner> Value, std::size_t Slot, bool IsRetry)
        : Owner(std::move(Value)), Index(Slot), Retry(IsRetry)
    {
    }

    TransmissionControlOwner::Delivery::Delivery(Delivery&& Other) noexcept
        : Owner(std::move(Other.Owner)), Index(Other.Index), Invoked(Other.Invoked),
          HandlerInvoked(Other.HandlerInvoked), Returned(Other.Returned),
          Succeeded(Other.Succeeded), Retry(Other.Retry)
    {
    }

    auto TransmissionControlOwner::Delivery::FinishRetry() noexcept -> void
    {
        if (!Retry || !Owner) return;
        Owner->Commands[Index].Retry.store(RetryState::Idle, std::memory_order_release);
        Owner->Activity->EndControlRetry();
        Retry = false;
    }

    TransmissionControlOwner::Delivery::~Delivery()
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
                {Prism::Fault::Code::Blocked});
            if (!Recorded) Owner->ReleaseCommand(Index);
        }
        if (!Succeeded)
        {
            // 关闭已成功交付时，cancel 的失败不能反过来否定最终关闭结果；
            // 仅保留该 cancel 预约供显式 Retry，不把 owner 判为不可恢复。
            if (Owner->IsControlClosed(Index))
            {
                if (Index < CancelCapacity &&
                    CommandValue.KnownControlFailure.load(std::memory_order_acquire) ==
                        KnownFailurePhase::Recorded)
                {
                    CommandValue.Retryable.store(true, std::memory_order_release);
                    Owner->Storage->Retain(Owner);
                }
                else
                {
                    Owner->ReleaseCommand(Index);
                }
            }
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
        Owner->ReleaseCommand(Index);
        if (Index == CancelCapacity)
        {
            Owner->Activity->RecordCloseDelivered();
            Owner->MarkInFlightCancelRetriesClosePending();
        }
        Owner->Storage->Collect();
        FinishRetry();
    }

    auto TransmissionControlOwner::Delivery::operator()() -> void
    {
        Invoked = true;
        try
        {
            Succeeded = Owner->Execute(Index, HandlerInvoked, Retry);
            Returned = true;
        }
        catch (...)
        {
            if (HandlerInvoked)
                Owner->RecordKnownFailure(Index, {Prism::Fault::Code::Blocked});
            else
                Owner->FailUnknown();
            if (Index == CancelCapacity)
            {
                auto Failure = Owner->CloseAttemptFailure.Load();
                if (Failure.Succeeded()) Failure = {Prism::Fault::Code::Blocked};
                Owner->CompleteCloseAttempt(Failure);
            }
            throw;
        }
        if (Index == CancelCapacity)
        {
            auto Failure = Owner->CloseAttemptFailure.Load();
            if (!Succeeded && Failure.Succeeded()) Failure = {Prism::Fault::Code::Blocked};
            Owner->CompleteCloseAttempt(Failure);
        }
    }

    auto TransmissionControlOwner::Delivery::OnQuarantine() noexcept -> void
    {
        if (!Owner) return;
        const bool CloseSettled = Retry && Owner->CompleteRetryWithoutOperation(Index);
        Retry = false;
        const bool AlreadyClosed = Owner->IsControlClosed(Index);
        if (!CloseSettled && AlreadyClosed)
            Owner->ReleaseCommand(Index);
        else if (!CloseSettled) Owner->FailUnknown();
        if (Index == CancelCapacity && !CloseSettled && !AlreadyClosed)
            Owner->CompleteCloseAttempt({Prism::Fault::Code::Blocked});
        else if (Index == CancelCapacity)
            Owner->CompleteCloseAttempt();
        Owner.reset();
    }

    TransmissionControlOwner::ExternalCloseDelivery::ExternalCloseDelivery(
        std::shared_ptr<TransmissionControlOwner> Value, bool IsRetry)
        : Owner(std::move(Value)), Retry(IsRetry)
    {
    }

    TransmissionControlOwner::ExternalCloseDelivery::ExternalCloseDelivery(
        ExternalCloseDelivery&& Other) noexcept
        : Owner(std::move(Other.Owner)), Invoked(Other.Invoked), Retry(Other.Retry)
    {
    }

    TransmissionControlOwner::ExternalCloseDelivery::~ExternalCloseDelivery()
    {
        if (!Owner) return;
        if (!Invoked) Owner->FailUnknown();
        Owner->ExternalReceiptRetryInFlight.store(false, std::memory_order_release);
        if (Retry)
            Owner->Activity->EndControlRetry();
    }

    auto TransmissionControlOwner::ExternalCloseDelivery::operator()() noexcept -> void
    {
        Invoked = true;
        Owner->ExternalReceiptPending.store(false, std::memory_order_release);
        Owner->DeliverExternalClose();
    }

    auto TransmissionControlOwner::ExternalCloseDelivery::OnQuarantine() noexcept -> void
    {
        Owner->FailUnknown();
    }

    auto TransmissionControlOwner::ConfirmExternalClose() noexcept -> void
    {
        if (ExternalCloseConfirmed.load(std::memory_order_acquire) ||
            ExternalReceiptPending.exchange(true, std::memory_order_acq_rel)) return;
        if (!Reclaimer->CanDispatch() && !Reclaimer->IsQuarantined())
        {
            RecordKnownFailure(CancelCapacity, {Prism::Fault::Code::Blocked});
            return;
        }
        ExternalReceiptRetryInFlight.store(true, std::memory_order_release);
        Activity->BeginControlRetry();
        const auto Posted = Reclaimer->Post(
            ExternalCloseDelivery(shared_from_this(), true));
        if (!Posted) FailUnknown(Posted.error());
    }

    auto TransmissionControlOwner::Drain()
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Retired = co_await Activity->Drain();
        if (!Retired) co_return std::unexpected(Retired.error());
        const auto Historical = Failure.Load();
        if (Historical.Failed()) co_return std::unexpected(Historical);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto TransmissionControlOwner::AwaitCloseDispatch() -> boost::asio::awaitable<ControlResult>
    {
        // 等待期间保持 owner 与等待状态存活；调用方只传入回执接口。
        auto Self = shared_from_this();
        for (;;)
        {
            const auto Phase = CloseAttempt.load(std::memory_order_acquire);
            if (Phase == CloseAttemptPhase::Idle)
                co_return ControlResult{};
            if (Phase == CloseAttemptPhase::Terminal)
            {
                const auto FailureValue = CloseAttemptFailure.Load();
                if (FailureValue.Failed()) co_return std::unexpected(FailureValue);
                co_return ControlResult{};
            }
            CloseAttemptWaiters.fetch_add(1, std::memory_order_acq_rel);
            boost::system::error_code Error;
            std::shared_ptr<CloseWaitState> Waiter;
            bool CompletedBeforeRegistration = false;
            {
                std::lock_guard Guard(CloseDispatchMutex);
                CompletedBeforeRegistration = CloseAttempt.load(
                    std::memory_order_acquire) == CloseAttemptPhase::Terminal;
                if (!CompletedBeforeRegistration)
                {
                    Waiter = CloseWaiter.lock();
                    if (!Waiter)
                    {
                        Waiter = std::make_shared<CloseWaitState>(
                            Reclaimer->Executor());
                        CloseWaiter = Waiter;
                    }
                }
            }
            if (CompletedBeforeRegistration)
            {
                CloseAttemptWaiters.fetch_sub(1, std::memory_order_acq_rel);
                continue;
            }
            co_await Waiter->Changes.async_receive(
                boost::asio::redirect_error(boost::asio::use_awaitable, Error));
            const auto AfterWait = CloseAttempt.load(std::memory_order_acquire);
            if (AfterWait == CloseAttemptPhase::Terminal)
            {
                if (CloseAttemptWaiters.load(std::memory_order_acquire) > 1)
                    NotifyCloseAttemptWaiter();
                CloseAttemptWaiters.fetch_sub(1, std::memory_order_acq_rel);
                continue;
            }
            CloseAttemptWaiters.fetch_sub(1, std::memory_order_acq_rel);
            if (Error)
            {
                const auto Current = CloseAttempt.load(std::memory_order_acquire);
                if (Current != CloseAttemptPhase::Posting &&
                    Current != CloseAttemptPhase::Accepted)
                    co_return std::unexpected(Prism::Fault::FromNative(
                        static_cast<std::error_code>(Error)));
            }
        }
    }

    auto TransmissionControlOwner::BeginCloseAttempt() noexcept -> bool
    {
        const auto Current = CloseAttempt.load(std::memory_order_acquire);
        if (Current != CloseAttemptPhase::Idle)
            return false;
        auto Expected = CloseAttemptPhase::Idle;
        return CloseAttempt.compare_exchange_strong(
            Expected, CloseAttemptPhase::Posting, std::memory_order_acq_rel);
    }

    auto TransmissionControlOwner::MarkCloseAttemptAccepted() noexcept -> void
    {
        auto Expected = CloseAttemptPhase::Posting;
        (void)CloseAttempt.compare_exchange_strong(
            Expected, CloseAttemptPhase::Accepted, std::memory_order_acq_rel);
    }

    auto TransmissionControlOwner::CompleteCloseAttempt(
        const Prism::Fault::Failure FailureValue) noexcept -> void
    {
        bool Unclaimed = false;
        if (!CloseAttemptCompletionClaimed.compare_exchange_strong(
                Unclaimed, true, std::memory_order_acq_rel)) return;
        if (FailureValue.Failed()) (void)CloseAttemptFailure.TrySet(FailureValue);
        CloseAttempt.store(CloseAttemptPhase::Terminal, std::memory_order_release);
        NotifyCloseAttemptWaiter();
    }

    auto TransmissionControlOwner::NotifyCloseAttemptWaiter() noexcept -> void
    {
        std::lock_guard Guard(CloseDispatchMutex);
        if (const auto Waiter = CloseWaiter.lock())
        {
            Waiter->Changes.close();
            CloseWaiter.reset();
        }
    }

    auto TransmissionControlOwner::DeliverExternalClose() noexcept -> void
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

    auto TransmissionControlOwner::TryClaimCloseRetry(std::size_t Index) noexcept -> bool
    {
        auto& RetryValue = Commands[Index].Retry;
        auto State = RetryValue.load(std::memory_order_acquire);
        while (State != RetryState::ClosePending)
        {
            const auto Target = State == RetryState::Idle ? RetryState::InFlight : RetryState::ClosePending;
            if (RetryValue.compare_exchange_weak(State, Target, std::memory_order_acq_rel))
                return Target == RetryState::InFlight;
        }
        return false;
    }

    auto TransmissionControlOwner::ReleaseCommand(std::size_t Index) noexcept -> void
    {
        auto& CommandValue = Commands[Index];
        CommandValue.ReleaseRequested.store(true, std::memory_order_release);
        if (ResolveKnownFailure(Index)) CompleteCommandRelease(Index);
    }

    auto TransmissionControlOwner::CompleteCommandRelease(std::size_t Index) noexcept -> void
    {
        auto& CommandValue = Commands[Index];
        if (!CommandValue.ReleaseRequested.exchange(false, std::memory_order_acq_rel)) return;
        if (CommandValue.Reservation)
        {
            CommandValue.Reservation->Returned();
            CommandValue.Reservation.reset();
        }
        CommandValue.Carrier.store({});
        CommandValue.Retryable.store(false, std::memory_order_release);
        CommandValue.Used.store(false, std::memory_order_release);
    }

    auto TransmissionControlOwner::CompleteRetryWithoutOperation(std::size_t Index) noexcept -> bool
    {
        auto& CommandValue = Commands[Index];
        auto Expected = RetryState::InFlight;
        if (CommandValue.Retry.compare_exchange_strong(Expected,
                RetryState::Idle, std::memory_order_acq_rel))
        {
            Activity->EndControlRetry();
            Storage->Collect();
            return false;
        }
        const bool CloseWasPending = Expected == RetryState::ClosePending;
        if (CloseWasPending)
        {
            ReleaseCommand(Index);
            CommandValue.Retry.store(RetryState::Idle, std::memory_order_release);
        }
        Activity->EndControlRetry();
        Storage->Collect();
        return CloseWasPending;
    }

    auto TransmissionControlOwner::ReleaseKnownCancelFailuresAfterClose() noexcept -> void
    {
        for (std::size_t Index = 0U; Index < CancelCapacity; ++Index)
        {
            auto& CommandValue = Commands[Index];
            if (!TryClaimCloseRetry(Index)) continue;
            if (CommandValue.Used.load(std::memory_order_acquire) &&
                CommandValue.KnownControlFailure.load(std::memory_order_acquire) != KnownFailurePhase::None)
                ReleaseCommand(Index);
            CommandValue.Retry.store(RetryState::Idle, std::memory_order_release);
        }
    }

    auto TransmissionControlOwner::MarkInFlightCancelRetriesClosePending() noexcept -> void
    {
        for (std::size_t Index = 0U; Index < CancelCapacity; ++Index)
        {
            auto& CommandValue = Commands[Index];
            if (!CommandValue.Used.load(std::memory_order_acquire) ||
                CommandValue.KnownControlFailure.load(std::memory_order_acquire) !=
                    KnownFailurePhase::Recorded)
                continue;
            auto Expected = RetryState::InFlight;
            (void)CommandValue.Retry.compare_exchange_strong(
                Expected, RetryState::ClosePending, std::memory_order_acq_rel);
        }
    }

    auto TransmissionControlOwner::RecordKnownFailure(
        std::size_t Index, Prism::Fault::Failure Error) noexcept -> bool
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
                CommandValue.KnownControlFailure.store(KnownFailurePhase::None, std::memory_order_release);
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
            CommandValue.KnownControlFailure.store(KnownFailurePhase::None, std::memory_order_release);
            CommandValue.Retryable.store(false, std::memory_order_release);
            CompleteCommandRelease(Index);
        }
        Storage->Retain(shared_from_this());
        return true;
    }

    auto TransmissionControlOwner::ResolveKnownFailure(std::size_t Index) noexcept -> bool
    {
        auto& CommandValue = Commands[Index];
        auto Phase = CommandValue.KnownControlFailure.load(std::memory_order_acquire);
        for (;;)
        {
            if (Phase == KnownFailurePhase::None)
            {
                CommandValue.Retryable.store(false, std::memory_order_release);
                return true;
            }
            if (Phase == KnownFailurePhase::ResolveRequested || Phase == KnownFailurePhase::Resolving)
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
                CommandValue.KnownControlFailure.store(KnownFailurePhase::None, std::memory_order_release);
                CommandValue.Retryable.store(false, std::memory_order_release);
                CompleteCommandRelease(Index);
                return true;
            }
        }
    }

    auto TransmissionControlOwner::IsControlClosed(std::size_t) const noexcept -> bool
    {
        return LocalClosed.load(std::memory_order_acquire) ||
            ExternalCloseConfirmed.load(std::memory_order_acquire) ||
            Finished.load(std::memory_order_acquire);
    }

    auto TransmissionControlOwner::FailUnknown(Prism::Fault::Failure Error) noexcept -> void
    {
        (void)Failure.TrySet(Error);
        Blocked.store(true, std::memory_order_release);
        Unrecoverable.store(true, std::memory_order_release);
        Activity->Block(Error);
        Storage->Retain(shared_from_this());
    }

    auto TransmissionControlOwner::RequestRetirement() -> void
    {
        const auto RetireRequested = shared_from_this();
        if (ExternalCloseConfirmed.load(std::memory_order_acquire) ||
            Unrecoverable.load(std::memory_order_acquire) || !Reclaimer->CanDispatch())
            return;
        // 已成功关闭只封止新操作，不解除仍待显式重试的 cancel 命令；
        // 若因 LocalClosed/Finished 提前返回，失败的取消预约会永久保留。
        if (ExternalReceiptPending.load(std::memory_order_acquire))
        {
            bool Idle = false;
            if (ExternalReceiptRetryInFlight.compare_exchange_strong(Idle, true, std::memory_order_acq_rel))
            {
                Activity->BeginControlRetry();
                const auto Posted = Reclaimer->Post(ExternalCloseDelivery(shared_from_this(), true));
                if (!Posted) FailUnknown(Posted.error());
            }
            return;
        }
        for (std::size_t Index = 0; Index <= CancelCapacity; ++Index)
        {
            auto& CommandValue = Commands[Index];
            if (!CommandValue.Used.load() || !CommandValue.Carrier.load()) continue;
            const auto FailurePhase =
                CommandValue.KnownControlFailure.load(std::memory_order_acquire);
            if (FailurePhase != KnownFailurePhase::Recorded) continue;
            Activity->BeginControlRetry();
            auto Expected = RetryState::Idle;
            if (!CommandValue.Retry.compare_exchange_strong(
                    Expected, RetryState::InFlight, std::memory_order_acq_rel))
            {
                Activity->EndControlRetry();
                continue;
            }
            if (!CommandValue.Retryable.exchange(false, std::memory_order_acq_rel))
            {
                CompleteRetryWithoutOperation(Index);
                continue;
            }
            if (Index == CancelCapacity)
            {
                CloseAttemptCompletionClaimed.store(false, std::memory_order_release);
                CloseAttempt.store(CloseAttemptPhase::Idle, std::memory_order_release);
                (void)BeginCloseAttempt();
            }
            const auto Posted = Reclaimer->Post(Delivery(shared_from_this(), Index, true));
            if (!Posted && Index == CancelCapacity)
                CompleteCloseAttempt(Posted.error());
        }
    }

    auto TransmissionControlOwner::IsRetired() const noexcept -> bool
    {
        for (const auto& CommandValue : Commands)
            if (CommandValue.Used.load()) return false;
        return LocalClosed.load(std::memory_order_acquire);
    }

    auto TransmissionControlOwner::IsDispatchUnavailable() const noexcept -> bool
    {
        return Unrecoverable.load(std::memory_order_acquire) ||
            (Blocked.load(std::memory_order_acquire) && !Reclaimer->CanDispatch());
    }

    auto TransmissionControlOwner::Execute(
        std::size_t Index, bool& HandlerInvoked, const bool IsRetry) -> bool
    {
        const auto Carrier = Commands[Index].Carrier.load();
        if (!Carrier)
        {
            FailUnknown();
            if (Index == CancelCapacity)
                (void)CloseAttemptFailure.TrySet({Prism::Fault::Code::Blocked});
            return false;
        }
        const auto CloseSettledRetry = IsRetry &&
            Commands[Index].Retry.load(std::memory_order_acquire) == RetryState::ClosePending;
        if (ExternalCloseConfirmed.load(std::memory_order_acquire) ||
            (Index < CancelCapacity && LocalClosed.load(std::memory_order_acquire) &&
                (!IsRetry || CloseSettledRetry)))
        {
            HandlerInvoked = true;
            return true;
        }
        // 外部物理关闭回执可能先于本次 RequestClose 的历史失败结果到达。
        if (Index == CancelCapacity && Carrier->RequiresExternalCloseReceipt())
            Commands[Index].AwaitingExternalReceipt.store(true, std::memory_order_release);
        HandlerInvoked = true;
        const auto Result = Index == CancelCapacity ? Carrier->OnClose() : Carrier->OnCancel();
        if (!Result)
        {
            if (Index == CancelCapacity)
                (void)CloseAttemptFailure.TrySet(Result.error());
            RecordKnownFailure(Index, Result.error());
            return false;
        }
        if (Index == CancelCapacity)
        {
            if (Carrier->RequiresExternalCloseReceipt())
            {
                Commands[Index].AwaitingExternalReceipt.store(true, std::memory_order_release);
                Storage->Retain(shared_from_this());
                return true;
            }
            LocalClosed.store(true, std::memory_order_release);
            if (Carrier->OwnsClose())
                Finished.store(true);
        }
        return true;
    }

    auto TransmissionControlOwner::Submit(
        std::shared_ptr<Transmission> Carrier, unsigned Flag) -> ControlResult
    {
        if (!Carrier)
        {
            const Fault::Failure Invalid{Fault::Code::InvalidArgument};
            if (Flag == CloseFlag && BeginCloseAttempt())
                CompleteCloseAttempt(Invalid);
            return std::unexpected(Invalid);
        }
        if (Flag == CancelFlag)
        {
            const auto CloseWasAccepted = AcceptedClose.load(std::memory_order_acquire);
            const auto WasClosedLocally = LocalClosed.load(std::memory_order_acquire);
            const auto WasFinished = Finished.load(std::memory_order_acquire);
            if (WasClosedLocally || WasFinished) return {};
            if (Blocked.load(std::memory_order_acquire))
                return std::unexpected(Failure.Load());
            const auto ExistingFailure = Failure.Load();
            if (ExistingFailure.Failed()) return std::unexpected(ExistingFailure);
            if (CloseWasAccepted) return {};
        }
        else if (Finished.load(std::memory_order_acquire) ||
                 (Flag == CloseFlag &&
                  (LocalClosed.load(std::memory_order_acquire) ||
                   ExternalCloseConfirmed.load(std::memory_order_acquire))))
        {
            return {};
        }

        if (Flag == CloseFlag)
            (void)BeginCloseAttempt();

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
            {
                if (!Commands[Index].Used.exchange(true)) break;
            }
            if (Index == CancelCapacity)
            {
                return std::unexpected(
                    Fault::Failure{Fault::Code::ResourceUnavailable});
            }
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
            {
                if (Flag == CloseFlag) CompleteCloseAttempt();
                return {};
            }
            if (Flag == CloseFlag) CompleteCloseAttempt(ReservationFailure);
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
            CompleteCloseAttempt();
            return {};
        }

        // 原执行域停止是尚未交付的已知拒绝；保留同一命令和真实预约供显式重试。
        if (!Reclaimer->CanDispatch() && !Reclaimer->IsQuarantined())
        {
            const Fault::Failure Deferred{Fault::Code::Blocked};
            if (!RecordKnownFailure(Index, Deferred))
            {
                ReleaseCommand(Index);
                if (Flag == CloseFlag) CompleteCloseAttempt();
                return {};
            }
            if (Flag == CloseFlag) CompleteCloseAttempt(Deferred);
            return std::unexpected(Deferred);
        }
        const auto Posted = Reclaimer->Post(Delivery(shared_from_this(), Index));
        if (!Posted)
        {
            FailUnknown(Posted.error());
            if (Flag == CloseFlag) CompleteCloseAttempt(Posted.error());
        }
        else if (Flag == CloseFlag)
        {
            AcceptedClose.store(true, std::memory_order_release);
            Activity->RecordCloseAccepted();
            MarkCloseAttemptAccepted();
        }
        return Posted;
    }
}
