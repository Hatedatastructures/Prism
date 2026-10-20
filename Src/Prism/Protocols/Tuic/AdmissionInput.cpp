/**
 * @file AdmissionInput.cpp
 * @brief TUIC admission 输入预约与事件分发实现。
 */
#include <Prism/Protocols/Tuic/Admission.hpp>
#include <Prism/Protocols/Tuic/AdmissionInput.hpp>

#include <Prism/Protocols/Quic/DatagramAdapter.hpp>
#include <Prism/Protocols/Quic/StreamAdapter.hpp>

#include <boost/asio/post.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <new>
#include <optional>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Tuic
{
    ConnectionAdmission::InputReservation::InputReservation(
        Prism::Lifecycle::DrainBarrier &Barrier,
        std::atomic<std::size_t> *Count)
        : Barrier_(std::in_place, Barrier), Count_(Count)
    {
    }

    ConnectionAdmission::InputReservation::InputReservation(InputReservation &&Other) noexcept
        : Barrier_(std::move(Other.Barrier_)), Count_(std::exchange(Other.Count_, nullptr))
    {
    }

    auto ConnectionAdmission::InputReservation::operator=(InputReservation &&Other) noexcept
        -> InputReservation &
    {
        if (this != &Other)
        {
            Reset();
            if (Other.Barrier_)
            {
                Barrier_.emplace(std::move(*Other.Barrier_));
                Other.Barrier_.reset();
            }
            Count_ = std::exchange(Other.Count_, nullptr);
        }
        return *this;
    }

    ConnectionAdmission::InputReservation::~InputReservation() noexcept
    {
        Reset();
    }

    auto ConnectionAdmission::InputReservation::Reset() noexcept -> void
    {
        Barrier_.reset();
        if (Count_)
        {
            Count_->fetch_sub(1U, std::memory_order_acq_rel);
            Count_ = nullptr;
        }
    }

    auto ConnectionAdmission::ReserveInput() noexcept
        -> std::optional<InputReservation>
    {
        auto Count = PendingInputCount_.load(std::memory_order_acquire);
        while (Count < MaxPendingInputs)
        {
            if (PendingInputCount_.compare_exchange_weak(
                    Count, Count + 1U, std::memory_order_acq_rel))
            {
                if (Inputs_.Enter()) return InputReservation{Inputs_, &PendingInputCount_};
                PendingInputCount_.fetch_sub(1U, std::memory_order_acq_rel);
                return std::nullopt;
            }
        }
        return std::nullopt;
    }

    auto ConnectionAdmission::DispatchInput(InputEvent Event)
        -> std::expected<void, Prism::Fault::Failure>
    {
        const auto ExistingFailure = Failure_.Load();
        if (ExistingFailure.Failed() && Event.Kind != InputKind::Close &&
            Event.Kind != InputKind::NativeClosed)
            return std::unexpected(ExistingFailure);
        if (Event.Kind == InputKind::Close || Event.Kind == InputKind::NativeClosed)
        {
            if (Event.Kind == InputKind::Close &&
                CloseQueued_.exchange(true, std::memory_order_acq_rel)) return {};
            if (!Inputs_.Enter())
            {
                if (Inputs_.IsSealed()) return {};
                auto Failure = Failure_.Load();
                if (!Failure.Failed())
                {
                    Failure = {Prism::Fault::Code::Blocked};
                    RecordFailure(Failure);
                    Inputs_.Block();
                    Failure = Failure_.Load();
                }
                return std::unexpected(Failure);
            }
            Event.Reservation.emplace(Inputs_, nullptr);
        }
        else
        {
            auto Reservation = ReserveInput();
            if (!Reservation)
            {
                auto Failure = Failure_.Load();
                if (!Failure.Failed())
                {
                    auto Code = Prism::Fault::Code::ResourceUnavailable;
                    if (Inputs_.IsSealed()) Code = Prism::Fault::Code::Canceled;
                    Failure = {Code};
                    RecordFailure(Failure);
                    Inputs_.Block();
                    Failure = Failure_.Load();
                }
                return std::unexpected(Failure);
            }
            Event.Reservation.emplace(std::move(*Reservation));
        }

        try
        {
            auto Delivery = std::make_shared<InputDelivery>(shared_from_this(), std::move(Event));
            Storage_->Retain(Delivery);
            return Delivery->SubmitInitial();
        }
        catch (const std::bad_alloc &)
        {
            const Prism::Fault::Failure Failure{
                Prism::Fault::Code::ResourceUnavailable,
                std::make_error_code(std::errc::not_enough_memory)};
            RecordFailure(Failure);
            StoreFailedInput(std::move(Event));
            Inputs_.Block();
            return std::unexpected(Failure_.Load());
        }
        catch (...)
        {
            const auto Exception = std::current_exception();
            RecordFatal(Exception);
            StoreFailedInput(std::move(Event));
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
    }

    auto ConnectionAdmission::OnUnidirectional(
        Prism::Quic::SharedStreamProvider AuthStream)
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!AuthStream) return {};
        InputEvent Event;
        Event.Kind = InputKind::Authentication;
        Event.StreamProvider = std::move(AuthStream);
        return DispatchInput(std::move(Event));
    }

    auto ConnectionAdmission::OnExporter(KeyingMaterialExporter Exporter)
        -> std::expected<void, Prism::Fault::Failure>
    {
        const auto ExistingFailure = Failure_.Load();
        if (ExistingFailure.Failed()) return std::unexpected(ExistingFailure);
        if (ExporterQueued_.exchange(true, std::memory_order_acq_rel)) return {};
        InputEvent Event;
        Event.Kind = InputKind::Exporter;
        Event.Exporter = std::move(Exporter);
        return DispatchInput(std::move(Event));
    }

    auto ConnectionAdmission::OnBidirectional(
        Prism::Quic::SharedStreamProvider Stream)
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!Stream) return {};
        InputEvent Event;
        Event.Kind = InputKind::Stream;
        Event.StreamProvider = std::move(Stream);
        return DispatchInput(std::move(Event));
    }

    auto ConnectionAdmission::OnDatagram(
        Prism::Quic::SharedDatagramProvider Provider)
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!Provider) return {};
        const auto ExistingFailure = Failure_.Load();
        if (ExistingFailure.Failed()) return std::unexpected(ExistingFailure);
        auto Existing = DatagramInput_.load(std::memory_order_acquire);
        if (Existing == Provider) return {};
        if (Existing || !DatagramInput_.compare_exchange_strong(
                Existing, Provider, std::memory_order_acq_rel))
        {
            if (Existing == Provider) return {};
            const Prism::Fault::Failure Failure{Prism::Fault::Code::ResourceUnavailable};
            RecordFailure(Failure);
            Inputs_.Block();
            return std::unexpected(Failure_.Load());
        }
        InputEvent Event;
        Event.Kind = InputKind::Datagram;
        Event.Provider = std::move(Provider);
        return DispatchInput(std::move(Event));
    }

    auto ConnectionAdmission::Close() -> void
    {
        InputEvent Event;
        Event.Kind = InputKind::Close;
        (void)DispatchInput(std::move(Event));
    }

    auto ConnectionAdmission::OnClosed() -> void
    {
        NativeClosed_.store(true, std::memory_order_release);
        if (NativeClosedQueued_.exchange(true, std::memory_order_acq_rel))
        {
            auto Self = shared_from_this();
            try
            {
                Net::post(Executor_, [Self]
                {
                    const auto Retried = Self->RetryRejectedInputDeliveries();
                    if (!Retried) Self->RecordFailure(Retried.error());
                });
            }
            catch (...)
            {
                RecordFatal(std::current_exception());
            }
            return;
        }
        InputEvent Event;
        Event.Kind = InputKind::NativeClosed;
        (void)DispatchInput(std::move(Event));
    }

    auto ConnectionAdmission::RecordFailure(Prism::Fault::Failure Failure) noexcept -> void
    {
        if (Failure.Succeeded()) Failure = {Prism::Fault::Code::Blocked};
        if (Failure_.TrySet(Failure))
        {
            if (Executor_.running_in_this_thread())
            {
                const auto CloseResult = RequestOwnerClose();
                if (!CloseResult) return;
            }
            else
            {
                Close();
            }
        }
    }

    auto ConnectionAdmission::RequestOwnerClose() noexcept
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (CloseOwnerAccepted_) return {};
        if (OwnerCloseFailure_)
        {
            if (!RetryOwnerClose_) return std::unexpected(*OwnerCloseFailure_);
            RetryOwnerClose_ = false;
        }
        if (!Options_.CloseOwner)
        {
            CloseOwnerAccepted_ = true;
            OwnerCloseFailure_.reset();
            return {};
        }
        try
        {
            const auto Result = Options_.CloseOwner();
            if (!Result)
            {
                if (!OwnerCloseFailure_) OwnerCloseFailure_ = Result.error();
                return std::unexpected(*OwnerCloseFailure_);
            }
            CloseOwnerAccepted_ = true;
            OwnerCloseFailure_.reset();
            return {};
        }
        catch (...)
        {
            if (Fatal_) Fatal_->Publish(std::current_exception());
            const Prism::Fault::Failure Failure{Prism::Fault::Code::Blocked};
            if (!OwnerCloseFailure_) OwnerCloseFailure_ = Failure;
            return std::unexpected(*OwnerCloseFailure_);
        }
    }

    auto ConnectionAdmission::StoreFailedInput(InputEvent Event) noexcept -> void
    {
        const auto Index = FailedInputCount_.fetch_add(1U, std::memory_order_acq_rel);
        if (Index >= FailedInputCapacity_)
        {
            RecordFailure({Prism::Fault::Code::ResourceUnavailable,
                std::make_error_code(std::errc::no_buffer_space)});
            Inputs_.Block();
            return;
        }
        FailedInputs_[Index] = std::move(Event);
    }

    auto ConnectionAdmission::RetainFailedInput(InputEvent Event) noexcept -> void
    {
        RecordFailure({Prism::Fault::Code::Blocked});
        StoreFailedInput(std::move(Event));
        Inputs_.Block();
    }

    auto ConnectionAdmission::RecordFatal(std::exception_ptr Error) noexcept -> void
    {
        if (Fatal_) Fatal_->Publish(std::move(Error));
        RecordFailure({Prism::Fault::Code::Blocked});
        Inputs_.Block();
        Children_.Block();
    }

    auto ConnectionAdmission::RetainFailedCarrier(
        Prism::SharedTransmission Carrier) noexcept -> void
    {
        if (!Carrier) return;
        InputEvent Event;
        Event.Carrier = std::move(Carrier);
        RetainFailedInput(std::move(Event));
    }

}
