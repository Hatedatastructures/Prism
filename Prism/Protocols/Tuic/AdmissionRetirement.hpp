/** @file AdmissionRetirement.hpp @brief TUIC 原 executor 上的关闭命令、活动排空与 owner 退休。 */
#pragma once
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_state.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/channel_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>
#include <Prism/Protocols/Tuic/Admission.hpp>
namespace Prism::Tuic
{
    inline auto ConnectionAdmission::CloseTransmission(
        const Prism::SharedTransmission &Carrier) noexcept
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!Carrier) return {};
        auto FirstFailure = std::expected<void, Prism::Fault::Failure>{};
        const auto Cancelled = Carrier->Cancel();
        if (!Cancelled) FirstFailure = std::unexpected(Cancelled.error());
        const auto Closed = Carrier->Close();
        if (!Closed && FirstFailure) FirstFailure = std::unexpected(Closed.error());
        return FirstFailure;
    }

    inline auto ConnectionAdmission::DrainTransmission(Prism::SharedTransmission Carrier)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (!Carrier) co_return std::expected<void, Prism::Fault::Failure>{};
        auto FirstFailure = std::expected<void, Prism::Fault::Failure>{};
        const auto Cancelled = Carrier->Cancel();
        if (!Cancelled) FirstFailure = std::unexpected(Cancelled.error());
        const auto Closed = Carrier->Close();
        if (!Closed && FirstFailure) FirstFailure = std::unexpected(Closed.error());
        const auto Activity = Carrier->Activity();
        if (!Activity)
        {
            if (!FirstFailure) co_return std::unexpected(FirstFailure.error());
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        Activity->Seal();
        const auto Drained = co_await Activity->Drain();
        if (!Drained && FirstFailure) FirstFailure = std::unexpected(Drained.error());
        if (!FirstFailure) co_return std::unexpected(FirstFailure.error());
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    inline auto ConnectionAdmission::DrainStream(std::uint64_t Id)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto It = ActiveStreams_.find(Id);
        if (It == ActiveStreams_.end())
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        const auto Inbound = std::static_pointer_cast<Prism::Transmission>(It->second.Inbound);
        const auto Underlying = It->second.Inbound ? It->second.Inbound->Underlying() : Prism::SharedTransmission{};
        const auto Outbound = It->second.Outbound;
        auto FirstFailure = std::expected<void, Prism::Fault::Failure>{};
        const auto InboundResult = co_await DrainTransmission(Inbound);
        if (!InboundResult) FirstFailure = std::unexpected(InboundResult.error());
        const auto UnderlyingResult = co_await DrainTransmission(Underlying);
        if (!UnderlyingResult && FirstFailure) FirstFailure = std::unexpected(UnderlyingResult.error());
        const auto OutboundResult = co_await DrainTransmission(Outbound);
        if (!OutboundResult && FirstFailure) FirstFailure = std::unexpected(OutboundResult.error());
        if (!FirstFailure) co_return std::unexpected(FirstFailure.error());
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    inline auto ConnectionAdmission::ServeStream(
        std::uint64_t Id,
        SharedConn Connection,
        Prism::Account::StreamLease StreamLease)
        -> Net::awaitable<StreamTaskResult>
    {
        StreamTaskResult Outcome;
        try
        {
            const auto Operation = co_await RunStream(
                Id, std::move(Connection), StreamLease);
            if (!Operation) Outcome.OperationFailure = Operation.error();
        }
        catch (const boost::system::system_error &Error)
        {
            const auto ErrorCode = Error.code();
            const auto ChannelCanceled = Net::experimental::error::make_error_code(
                Net::experimental::error::channel_cancelled);
            if (!Closed_ || (ErrorCode != Net::error::operation_aborted &&
                ErrorCode != ChannelCanceled))
            {
                RecordFatal(std::current_exception());
                Outcome.CleanupFailure =
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked};
            }
        }
        catch (...)
        {
            RecordFatal(std::current_exception());
            Outcome.CleanupFailure =
                Prism::Fault::Failure{Prism::Fault::Code::Blocked};
        }
        try
        {
            const auto Drained = co_await DrainStream(Id);
            if (!Drained) Outcome.CleanupFailure = Drained.error();
        }
        catch (...)
        {
            RecordFatal(std::current_exception());
            Outcome.CleanupFailure = Prism::Fault::Failure{Prism::Fault::Code::Blocked};
        }
        if (Outcome.CleanupFailure)
            Outcome.RetainedLease.emplace(std::move(StreamLease));
        co_return Outcome;
    }

    inline auto ConnectionAdmission::ServeDatagrams(
        Prism::Quic::SharedDatagramProvider Provider,
        Prism::SharedTransmission Transport,
        std::shared_ptr<Net::cancellation_signal> Cancellation)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        auto FirstFailure = std::expected<void, Prism::Fault::Failure>{};
        try
        {
            if (!Cancellation)
            {
                RecordFailure({Prism::Fault::Code::Blocked});
                CloseOnExecutor();
                FirstFailure = std::unexpected(Failure_.Load());
            }
            else
            {
                co_await Net::co_spawn(Executor_, RunDatagrams(Transport),
                    Net::bind_cancellation_slot(Cancellation->slot(), Net::use_awaitable));
            }
        }
        catch (const boost::system::system_error &Error)
        {
            const auto ErrorCode = Error.code();
            const auto ChannelCanceled = Net::experimental::error::make_error_code(
                Net::experimental::error::channel_cancelled);
            if (!Closed_ || (ErrorCode != Net::error::operation_aborted &&
                ErrorCode != ChannelCanceled))
            {
                RecordFatal(std::current_exception());
                FirstFailure = std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
        }
        catch (...)
        {
            RecordFatal(std::current_exception());
            FirstFailure = std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        (void)Provider;
        const auto Drained = co_await DrainTransmission(Transport);
        if (!Drained && FirstFailure) FirstFailure = std::unexpected(Drained.error());
        if (!FirstFailure) co_return std::unexpected(FirstFailure.error());
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    inline auto ConnectionAdmission::AdmitAuthentication(
        Prism::SharedTransmission AuthStream,
        InputReservation Input) -> void
    {
        if (Closed_ || AuthenticationStarted_ || Authenticated_ || AuthStream_)
        {
            QueueRejectedTransmission(std::move(AuthStream), std::move(Input));
            return;
        }
        AuthStream_ = std::move(AuthStream);
        StartAuthentication();
    }

    inline auto ConnectionAdmission::AdmitStream(
        Prism::SharedTransmission Stream,
        InputReservation Input) -> void
    {
        if (!Stream) return;
        if (Closed_ || Authenticated_)
        {
            if (Closed_) QueueRejectedTransmission(std::move(Stream), std::move(Input));
            else StartStream(std::move(Stream), std::move(Input));
            return;
        }
        if (PendingStreams_.size() >= Options_.MaxPendingBidiStreams)
        {
            QueueRejectedTransmission(std::move(Stream), std::move(Input));
            return;
        }
        try
        {
            PendingStreams_.push_back(std::move(Stream));
        }
        catch (...)
        {
            RecordFatal(std::current_exception());
            RetainFailedCarrier(std::move(Stream));
        }
    }

    inline auto ConnectionAdmission::AdmitDatagram(
        Prism::Quic::SharedDatagramProvider Provider,
        Prism::SharedTransmission Transport,
        InputReservation Input) -> void
    {
        if (!Provider) return;
        if (Provider == PendingDatagram_ || Provider == ActiveDatagram_) return;
        if (!Transport)
            Transport = std::make_shared<Prism::Quic::DatagramAdapter>(Provider);
        if (Closed_)
        {
            QueueRejectedTransmission(std::move(Transport), std::move(Input));
            return;
        }
        if (PendingDatagram_ || ActiveDatagram_)
        {
            QueueRejectedTransmission(std::move(Transport), std::move(Input));
            return;
        }
        if (!Authenticated_)
        {
            PendingDatagram_ = std::move(Provider);
            PendingDatagramTransport_ = std::move(Transport);
            return;
        }
        StartDatagram(std::move(Provider), std::move(Transport));
    }

    inline auto ConnectionAdmission::QueueRejectedTransmission(
        Prism::SharedTransmission Carrier,
        InputReservation Input) -> void
    {
        if (!Carrier) return;
        auto Self = shared_from_this();
        try
        {
            Net::co_spawn(Executor_, DrainTransmission(Carrier),
                [Self, Carrier, Input = std::move(Input)](
                    std::exception_ptr Error, std::expected<void, Prism::Fault::Failure> Result) mutable
                {
                    Self->FinishRejectedTransmission(RejectedDrainCompletion{
                        Carrier, std::move(Input), std::move(Error), std::move(Result)});
                });
        }
        catch (...)
        {
            const auto Failure = std::current_exception();
            RecordFatal(Failure);
            InputEvent Event;
            Event.Carrier = std::move(Carrier);
            StoreFailedInput(std::move(Event));
        }
    }

    inline auto ConnectionAdmission::QueueRejectedTransmission(Prism::SharedTransmission Carrier) -> void
    {
        if (!Carrier) return;
        auto Input = ReserveInput();
        if (!Input)
        {
            RecordFailure({Prism::Fault::Code::ResourceUnavailable});
            InputEvent Event;
            Event.Carrier = std::move(Carrier);
            StoreFailedInput(std::move(Event));
            Inputs_.Block();
            return;
        }
        QueueRejectedTransmission(std::move(Carrier), std::move(*Input));
    }

    inline auto ConnectionAdmission::FinishRejectedTransmission(
        RejectedDrainCompletion Completion) noexcept -> void
    {
        if (Completion.Error)
        {
            RecordFatal(std::move(Completion.Error));
        }
        else if (!Completion.Result)
        {
            RecordFailure(Completion.Result.error());
            Inputs_.Block();
        }
        else
        {
            return;
        }
        InputEvent Event;
        Event.Carrier = std::move(Completion.Carrier);
        Event.Reservation.emplace(std::move(Completion.Reservation));
        StoreFailedInput(std::move(Event));
    }

    inline auto ConnectionAdmission::DrainPendingCarriers()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        auto FirstFailure = std::expected<void, Prism::Fault::Failure>{};
        const auto AuthResult = co_await DrainTransmission(AuthStream_);
        if (!AuthResult) FirstFailure = std::unexpected(AuthResult.error());
        for (const auto &Stream : PendingStreams_)
        {
            const auto Result = co_await DrainTransmission(Stream);
            if (!Result && FirstFailure) FirstFailure = std::unexpected(Result.error());
        }
        const auto PendingDatagramResult = co_await DrainTransmission(PendingDatagramTransport_);
        if (!PendingDatagramResult && FirstFailure) FirstFailure = std::unexpected(PendingDatagramResult.error());
        const auto ActiveDatagramResult = co_await DrainTransmission(ActiveDatagramTransport_);
        if (!ActiveDatagramResult && FirstFailure) FirstFailure = std::unexpected(ActiveDatagramResult.error());
        if (!ActiveStreams_.empty() || ActiveDatagram_)
        {
            if (FirstFailure) FirstFailure = std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        if (!FirstFailure) co_return std::unexpected(FirstFailure.error());
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    inline auto ConnectionAdmission::TrackRetryableInputDelivery(
        const std::shared_ptr<InputDelivery> &Delivery) noexcept -> bool
    {
        if (Delivery->State_.load(std::memory_order_acquire) !=
            InputDelivery::DeliveryState::Retryable)
            return true;
        auto Index = RetryableInputIndex_.load(std::memory_order_acquire);
        if (!Index)
        {
            try
            {
                auto Candidate = std::make_shared<RetryableInputIndex>();
                auto Empty = std::shared_ptr<RetryableInputIndex>{};
                if (RetryableInputIndex_.compare_exchange_strong(
                        Empty, Candidate, std::memory_order_acq_rel))
                    Index = std::move(Candidate);
                else
                    Index = std::move(Empty);
            }
            catch (...)
            {
                Delivery->MarkRetryIndexMissing();
                return false;
            }
        }
        auto ExpectedSlot = InputDelivery::NoRetrySlot;
        if (!Delivery->RetrySlot_.compare_exchange_strong(
                ExpectedSlot, InputDelivery::RegisteringRetrySlot,
                std::memory_order_acq_rel))
            return ExpectedSlot < MaxRetryableInputDeliveries ||
                ExpectedSlot == InputDelivery::RegisteringRetrySlot;
        if (Delivery->State_.load(std::memory_order_acquire) !=
            InputDelivery::DeliveryState::Retryable)
        {
            Delivery->RetrySlot_.store(InputDelivery::NoRetrySlot, std::memory_order_release);
            return true;
        }

        for (std::size_t SlotIndex = 0; SlotIndex < Index->Slots.size(); ++SlotIndex)
        {
            auto Expected = Index->Slots[SlotIndex].load(std::memory_order_acquire);
            if (!Expected.expired()) continue;
            if (!Index->Slots[SlotIndex].compare_exchange_strong(
                    Expected, std::weak_ptr<InputDelivery>{Delivery},
                    std::memory_order_acq_rel))
                continue;
            auto Registering = InputDelivery::RegisteringRetrySlot;
            if (Delivery->RetrySlot_.compare_exchange_strong(
                    Registering, SlotIndex, std::memory_order_acq_rel))
                return true;
            auto Stored = std::weak_ptr<InputDelivery>{Delivery};
            (void)Index->Slots[SlotIndex].compare_exchange_strong(
                Stored, std::weak_ptr<InputDelivery>{}, std::memory_order_acq_rel);
            return Registering == InputDelivery::NoRetrySlot ||
                Registering < MaxRetryableInputDeliveries;
        }

        Delivery->RetrySlot_.store(InputDelivery::NoRetrySlot, std::memory_order_release);
        Delivery->MarkRetryIndexMissing();
        return false;
    }

    inline auto ConnectionAdmission::RemoveRetryableInputDelivery(
        InputDelivery &Delivery) noexcept -> void
    {
        auto Index = RetryableInputIndex_.load(std::memory_order_acquire);
        if (!Index) return;
        auto SlotIndex = Delivery.RetrySlot_.load(std::memory_order_acquire);
        while (SlotIndex == InputDelivery::RegisteringRetrySlot)
        {
            if (Delivery.RetrySlot_.compare_exchange_weak(
                    SlotIndex, InputDelivery::NoRetrySlot, std::memory_order_acq_rel))
                return;
        }
        if (SlotIndex >= Index->Slots.size()) return;
        if (!Delivery.RetrySlot_.compare_exchange_strong(
                SlotIndex, InputDelivery::NoRetrySlot, std::memory_order_acq_rel))
            return;
        auto Expected = std::weak_ptr<InputDelivery>{Delivery.shared_from_this()};
        (void)Index->Slots[SlotIndex].compare_exchange_strong(
            Expected, std::weak_ptr<InputDelivery>{}, std::memory_order_acq_rel);
    }

    inline auto ConnectionAdmission::RetryRejectedInputDeliveries() noexcept
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (UnindexedRetryCount_.load(std::memory_order_acquire) != 0U)
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::ResourceUnavailable,
                std::make_error_code(std::errc::no_buffer_space)});
        auto Index = RetryableInputIndex_.load(std::memory_order_acquire);
        if (!Index) return {};
        auto FirstFailure = Prism::Fault::Failure{};
        try
        {
            for (auto &Slot : Index->Slots)
            {
                auto Delivery = Slot.load(std::memory_order_acquire).lock();
                if (!Delivery) continue;
                const auto Result = Delivery->RetryRejected();
                if (!Result && FirstFailure.Succeeded()) FirstFailure = Result.error();
            }
        }
        catch (...)
        {
            if (FirstFailure.Succeeded())
                FirstFailure = {Prism::Fault::Code::Blocked};
        }
        if (FirstFailure.Failed()) return std::unexpected(FirstFailure);
        return {};
    }
    inline auto ConnectionAdmission::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (!Reclaimer_->CanDispatch())
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        if (OwnerCloseFailure_) RetryOwnerClose_ = true;
        Inputs_.Seal();
        CloseOnExecutor();
        const auto RetriedInputs = RetryRejectedInputDeliveries();
        if (!RetriedInputs) co_return std::unexpected(RetriedInputs.error());
        auto FirstFailure = std::expected<void, Prism::Fault::Failure>{};
        const auto InputsDrained = co_await Inputs_.Drain();
        if (!InputsDrained)
        {
            RecordFailure(InputsDrained.error());
            FirstFailure = std::unexpected(InputsDrained.error());
        }
        MaybeFinishClose();
        Children_.Seal();
        const auto ChildrenDrained = co_await Children_.Drain();
        if (!ChildrenDrained)
        {
            RecordFailure(ChildrenDrained.error());
            if (FirstFailure) FirstFailure = std::unexpected(ChildrenDrained.error());
        }
        MaybeFinishClose();
        const auto CarriersDrained = co_await DrainPendingCarriers();
        if (!CarriersDrained)
        {
            RecordFailure(CarriersDrained.error());
            if (FirstFailure) FirstFailure = std::unexpected(CarriersDrained.error());
        }
        const auto Failure = Failure_.Load();
        if (Failure.Failed()) co_return std::unexpected(Failure);
        if (OwnerCloseFailure_) co_return std::unexpected(*OwnerCloseFailure_);
        if (!FirstFailure) co_return std::unexpected(FirstFailure.error());
        if (FailedInputCount_.load(std::memory_order_acquire) != 0U)
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        AccountLease_.Release();
        AccountId_ = {};
        Identity_.clear();
        AuthStream_.reset();
        Exporter_ = {};
        PendingStreams_.clear();
        PendingDatagram_.reset();
        PendingDatagramTransport_.reset();
        ActiveDatagram_.reset();
        ActiveDatagramTransport_.reset();
        DatagramInput_.store({}, std::memory_order_release);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    inline void ConnectionAdmission::CloseOnExecutor() noexcept
    {
        CloseQueued_.store(true, std::memory_order_release);
        if (Closed_)
        {
            MaybeFinishClose();
            return;
        }
        Closed_ = true;
        if (DatagramCancellation_)
        {
            DatagramCancellation_->emit(Net::cancellation_type::all);
        }
        const auto AuthClose=CloseTransmission(AuthStream_);
        if(!AuthClose)RecordFailure(AuthClose.error());
        for (const auto &Stream : PendingStreams_)
        {
            const auto Closed=CloseTransmission(Stream);
            if(!Closed)RecordFailure(Closed.error());
        }
        const auto PendingClose=CloseTransmission(PendingDatagramTransport_);
        if(!PendingClose)RecordFailure(PendingClose.error());
        const auto DatagramClose=CloseTransmission(ActiveDatagramTransport_);
        if(!DatagramClose)RecordFailure(DatagramClose.error());
        for (const auto &[Id, Stream] : ActiveStreams_)
        {
            (void)Id;
            if (Stream.Cancellation)
            {
                Stream.Cancellation->emit(Net::cancellation_type::all);
            }
            const auto Inbound=std::static_pointer_cast<Prism::Transmission>(Stream.Inbound);
            const auto InboundClose=CloseTransmission(Inbound);
            if(!InboundClose)RecordFailure(InboundClose.error());
            const auto OutboundClose=CloseTransmission(Stream.Outbound);
            if(!OutboundClose)RecordFailure(OutboundClose.error());
        }
        MaybeFinishClose();
    }

    inline void ConnectionAdmission::MaybeFinishClose() noexcept
    {
        if (!Closed_ || Inputs_.Active() != 0 || Children_.Active() != 0 ||
            !ActiveStreams_.empty() || ActiveDatagram_)
            return;
        const auto CloseResult=RequestOwnerClose();
        if (!CloseResult)return;
        if (NativeClosed_.load(std::memory_order_acquire) && CloseOwnerAccepted_ &&
            Failure_.Load().Succeeded() &&
            FailedInputCount_.load(std::memory_order_acquire) == 0U && AccountLease_)
        {
            AccountLease_.Release();
            AccountId_ = {};
            Identity_.clear();
        }
    }


} // namespace Prism::Tuic
