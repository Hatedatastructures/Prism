/**
 * @file AdmissionInputDelivery.cpp
 * @brief TUIC 已接受输入的交付、重试与隔离状态实现。
 */
#include <Prism/Protocols/Tuic/AdmissionInput.hpp>

#include <Prism/Protocols/Quic/DatagramAdapter.hpp>
#include <Prism/Protocols/Quic/StreamAdapter.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <new>
#include <system_error>
#include <utility>

namespace Prism::Tuic
{
    auto ConnectionAdmission::InputDelivery::InputDeliveryAction::operator()() noexcept -> void
    {
        Delivery->Deliver();
    }

    auto ConnectionAdmission::InputDelivery::InputDeliveryAction::OnQuarantine() noexcept -> void
    {
        Delivery->OnQuarantine();
    }

    ConnectionAdmission::InputDelivery::InputDelivery(
        std::shared_ptr<ConnectionAdmission> Owner,
        InputEvent Event)
        : Owner_(std::move(Owner)), Event_(std::move(Event)), Storage_(Owner_->Storage_),
          Identity_(Owner_->Options_.Metadata.TaskIdentity)
    {
    }

    auto ConnectionAdmission::InputDelivery::SubmitInitial()
        -> std::expected<void, Prism::Fault::Failure>
    {
        return Submit(DeliveryState::Created);
    }

    auto ConnectionAdmission::InputDelivery::RetryRejected()
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (State_.load(std::memory_order_acquire) != DeliveryState::Retryable) return {};
        if (!IsCurrentEvent())
        {
            RetireClosedInput();
            return {};
        }
        if (Event_.Kind != InputKind::Close && Event_.Kind != InputKind::NativeClosed &&
            (Owner_->Closed_ || Owner_->CloseQueued_.load(std::memory_order_acquire) ||
                Owner_->NativeClosed_.load(std::memory_order_acquire)))
        {
            RetireClosedInput();
            return {};
        }
        const auto OwnerFailure = Owner_->Failure_.Load();
        if (OwnerFailure.Failed() && Event_.Kind != InputKind::Close &&
            Event_.Kind != InputKind::NativeClosed)
            return std::unexpected(OwnerFailure);
        return Submit(DeliveryState::Retryable);
    }

    auto ConnectionAdmission::InputDelivery::Deliver() noexcept -> void
    {
        auto Expected = DeliveryState::Queued;
        if (!State_.compare_exchange_strong(
                Expected, DeliveryState::Running, std::memory_order_acq_rel))
            return;
        if (!IsCurrentEvent())
        {
            RetireClosedInput();
            return;
        }
        if (Event_.Kind != InputKind::Close && Event_.Kind != InputKind::NativeClosed &&
            (Owner_->NativeClosed_.load(std::memory_order_acquire) ||
                Owner_->CloseQueued_.load(std::memory_order_acquire)))
        {
            Owner_->CloseOnExecutor();
            RetireClosedInput();
            return;
        }
        const auto OwnerFailure = Owner_->Failure_.Load();
        if (OwnerFailure.Failed() && Event_.Kind != InputKind::Close &&
            Event_.Kind != InputKind::NativeClosed)
        {
            RetireClosedInput();
            return;
        }
        if (!Event_.Reservation)
        {
            Fail({Prism::Fault::Code::Blocked});
            return;
        }
        try
        {
            if (!DeliverEvent()) return;
            Event_.Carrier.reset();
            Event_.StreamProvider.reset();
            Event_.Provider.reset();
            Event_.Exporter = {};
            Event_.Reservation.reset();
            Owner_->MaybeFinishClose();
            State_.store(DeliveryState::Completed, std::memory_order_release);
            Owner_->RemoveRetryableInputDelivery(*this);
            if (Storage_) Storage_->Collect();
        }
        catch (...)
        {
            Owner_->RecordFatal(std::current_exception());
            Fail({Prism::Fault::Code::Blocked});
        }
    }

    auto ConnectionAdmission::InputDelivery::OnQuarantine() noexcept -> void
    {
        auto Expected = DeliveryState::Queued;
        if (!State_.compare_exchange_strong(
                Expected, DeliveryState::Quarantined, std::memory_order_acq_rel))
            return;
        RetainFailure({Prism::Fault::Code::Blocked});
    }

    auto ConnectionAdmission::InputDelivery::RetireClosedInput() noexcept -> void
    {
        [[maybe_unused]] const auto KeepAlive = shared_from_this();
        State_.store(DeliveryState::Completed, std::memory_order_release);
        Owner_->RemoveRetryableInputDelivery(*this);
        auto Carrier = std::move(Event_.Carrier);
        if (!Carrier && Event_.StreamProvider)
        {
            try
            {
                Carrier = std::make_shared<Prism::Quic::StreamAdapter>(
                    Event_.StreamProvider->Executor(), Event_.StreamProvider);
            }
            catch (...)
            {
                Owner_->RecordFatal(std::current_exception());
            }
        }
        else if (!Carrier && Event_.Provider)
        {
            try
            {
                Carrier = std::make_shared<Prism::Quic::DatagramAdapter>(Event_.Provider);
            }
            catch (...)
            {
                Owner_->RecordFatal(std::current_exception());
            }
        }
        Event_.Carrier.reset();
        Event_.StreamProvider.reset();
        Event_.Provider.reset();
        Event_.Exporter = {};
        Event_.Reservation.reset();
        if (Carrier)
            Owner_->RetireCarrier(std::move(Carrier));
        Owner_->MaybeFinishClose();
        if (Storage_) Storage_->Collect();
    }

    auto ConnectionAdmission::InputDelivery::RequestRetirement() -> void
    {
        (void)RetryRejected();
    }

    auto ConnectionAdmission::InputDelivery::IsRetired() const noexcept -> bool
    {
        return State_.load(std::memory_order_acquire) == DeliveryState::Completed;
    }

    auto ConnectionAdmission::InputDelivery::IsDispatchUnavailable() const noexcept -> bool
    {
        const auto State = State_.load(std::memory_order_acquire);
        return State == DeliveryState::Failed || State == DeliveryState::Quarantined ||
            (State == DeliveryState::Retryable && Owner_->Reclaimer_->IsQuarantined());
    }

    auto ConnectionAdmission::InputDelivery::Submit(DeliveryState ExpectedState)
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!IsCurrentEvent())
        {
            RetireClosedInput();
            return {};
        }
        auto Expected = ExpectedState;
        if (!State_.compare_exchange_strong(
                Expected, DeliveryState::Queued, std::memory_order_acq_rel))
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        if (ExpectedState == DeliveryState::Retryable) ClearRetryIndexMissing();
        std::expected<void, Prism::Fault::Failure> Posted;
        try
        {
            Posted = Owner_->Reclaimer_->Post(InputDeliveryAction{shared_from_this()});
        }
        catch (...)
        {
            Posted = std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        if (Posted) return {};
        Expected = DeliveryState::Queued;
        if (State_.compare_exchange_strong(
                Expected, DeliveryState::Retryable, std::memory_order_acq_rel))
        {
            const auto Indexed =
                Owner_->TrackRetryableInputDelivery(shared_from_this());
            if (Storage_) Storage_->Retain(shared_from_this());
            if (!Indexed)
                return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::ResourceUnavailable,
                    std::make_error_code(std::errc::no_buffer_space)});
        }
        return std::unexpected(Posted.error());
    }

    auto ConnectionAdmission::InputDelivery::IsCurrentEvent() const noexcept -> bool
    {
        if (Identity_ != Owner_->Options_.Metadata.TaskIdentity) return false;
        switch (Event_.Kind)
        {
        case InputKind::Close:
            return Owner_->CloseQueued_.load(std::memory_order_acquire);
        case InputKind::NativeClosed:
            return Owner_->NativeClosed_.load(std::memory_order_acquire);
        case InputKind::Exporter:
            return Owner_->ExporterQueued_.load(std::memory_order_acquire);
        case InputKind::Datagram:
            return Owner_->DatagramInput_.load(std::memory_order_acquire) == Event_.Provider;
        case InputKind::Authentication:
        case InputKind::Stream:
            return true;
        }
        return false;
    }

    auto ConnectionAdmission::InputDelivery::DeliverEvent() -> bool
    {
        switch (Event_.Kind)
        {
        case InputKind::Authentication:
            if (Event_.StreamProvider && !Event_.Carrier)
                Event_.Carrier = std::make_shared<Prism::Quic::StreamAdapter>(
                    Event_.StreamProvider->Executor(), Event_.StreamProvider);
            Owner_->AdmitAuthentication(Event_.Carrier, std::move(*Event_.Reservation));
            break;
        case InputKind::Exporter:
            if (!Owner_->Closed_ && !Owner_->ExporterReady_)
            {
                Owner_->ExporterReady_ = true;
                Owner_->Exporter_ = std::move(Event_.Exporter);
                Owner_->StartAuthentication();
            }
            break;
        case InputKind::Stream:
            if (Event_.StreamProvider && !Event_.Carrier)
                Event_.Carrier = std::make_shared<Prism::Quic::StreamAdapter>(
                    Event_.StreamProvider->Executor(), Event_.StreamProvider);
            Owner_->AdmitStream(Event_.Carrier, std::move(*Event_.Reservation));
            break;
        case InputKind::Datagram:
            if (Event_.Provider && Event_.Provider->IsClosed())
            {
                if (!Event_.Carrier)
                    Event_.Carrier = std::make_shared<Prism::Quic::DatagramAdapter>(Event_.Provider);
                Owner_->QueueRejectedTransmission(
                    Event_.Carrier, std::move(*Event_.Reservation));
            }
            else
                Owner_->AdmitDatagram(
                    Event_.Provider, Event_.Carrier, std::move(*Event_.Reservation));
            break;
        case InputKind::Close:
            Owner_->CloseOnExecutor();
            break;
        case InputKind::NativeClosed:
            // Native close is a terminal acknowledgement, not another local close edge.
            if (!Owner_->Closed_)
                Owner_->CloseOnExecutor();
            else
                Owner_->MaybeFinishClose();
            break;
        }
        return true;
    }

    auto ConnectionAdmission::InputDelivery::Fail(Prism::Fault::Failure Reason) noexcept -> void
    {
        State_.store(DeliveryState::Failed, std::memory_order_release);
        RetainFailure(Reason);
    }

    auto ConnectionAdmission::InputDelivery::RetainFailure(
        Prism::Fault::Failure Reason) noexcept -> void
    {
        if (Reason.Succeeded()) Reason = {Prism::Fault::Code::Blocked};
        Owner_->RecordFailure(Reason);
        const auto HasEvent = Event_.Carrier || Event_.StreamProvider || Event_.Provider ||
            static_cast<bool>(Event_.Reservation);
        if (HasEvent) Owner_->StoreFailedInput(std::move(Event_));
        State_.store(DeliveryState::Completed, std::memory_order_release);
        Owner_->RemoveRetryableInputDelivery(*this);
        Owner_->MaybeFinishClose();
        if (Storage_) Storage_->Collect();
    }

    auto ConnectionAdmission::InputDelivery::MarkRetryIndexMissing() noexcept -> void
    {
        bool Missing = false;
        if (RetryIndexMissing_.compare_exchange_strong(
                Missing, true, std::memory_order_acq_rel))
            Owner_->UnindexedRetryCount_.fetch_add(1U, std::memory_order_acq_rel);
        if (State_.load(std::memory_order_acquire) != DeliveryState::Retryable)
            ClearRetryIndexMissing();
    }

    auto ConnectionAdmission::InputDelivery::ClearRetryIndexMissing() noexcept -> void
    {
        if (RetryIndexMissing_.exchange(false, std::memory_order_acq_rel))
            Owner_->UnindexedRetryCount_.fetch_sub(1U, std::memory_order_acq_rel);
    }
}
