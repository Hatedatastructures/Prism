/** @file AdmissionRetirement.cpp @brief 入站预约票据的关闭、排空与重试实现。 */
#include "Detail/AdmissionRetirementState.hpp"
#include <Prism/Contract/Io/CarrierActivity.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <exception>
#include <utility>

namespace Prism::Contract
{
    AdmissionRetirementState::AdmissionRetirementState(
        Prism::SharedTransmission Inbound,
        AdmissionRetirementEnvironment Environment)
        : Inbound_(std::move(Inbound)), Context_(std::move(Environment.Context)),
          Storage_(std::move(Environment.Storage)), Reclaimer_(std::move(Environment.Reclaimer))
    {
    }

    auto AdmissionRetirementState::Attach(ProtocolDataPlane Plane) noexcept -> void
    {
        if (!Plane_)
        {
            Plane_.emplace(std::move(Plane));
        }
    }

    auto AdmissionRetirementState::ClaimMuxRootCreate() noexcept -> bool
    {
        if (Retired_.load(std::memory_order_acquire) || Plane_) return false;
        bool Available = false;
        return MuxRootClaimed_.compare_exchange_strong(
            Available, true, std::memory_order_acq_rel, std::memory_order_acquire);
    }

    auto AdmissionRetirementState::CanAttachMuxRootParentStreamLease() const noexcept -> bool
    {
        return !Retired_.load(std::memory_order_acquire) &&
            !MuxRootClaimed_.load(std::memory_order_acquire) && !Plane_;
    }

    auto AdmissionRetirementState::AttachMuxRootPlane(ProtocolDataPlane &&Plane) noexcept -> void
    {
        if (!Plane_) Plane_.emplace(std::move(Plane));
    }

    auto AdmissionRetirementState::AttachMuxRootGenerationLease(
        Prism::Foundation::GenerationUseLease &&Lease) noexcept -> void
    {
        RootGenerationLease_ = std::move(Lease);
    }

    auto AdmissionRetirementState::MuxRootTransport() const noexcept
        -> Prism::SharedTransmission
    {
        if (!Plane_) return {};
        return Plane_->Transport();
    }

    auto AdmissionRetirementState::AttachMuxRootSession(
        std::shared_ptr<MuxSession> Session) noexcept -> void
    {
        if (Plane_)
            if (auto *Mux = Plane_->Mux()) Mux->Session = std::move(Session);
    }

    auto AdmissionRetirementState::TakeMuxRootPlane() noexcept -> ProtocolDataPlane
    {
        ProtocolDataPlane Result;
        if (Plane_)
        {
            Result = std::move(*Plane_);
            Plane_.reset();
        }
        return Result;
    }

    auto AdmissionRetirementState::TakeMuxRootGenerationLease() noexcept
        -> Prism::Foundation::GenerationUseLease
    {
        return std::move(RootGenerationLease_);
    }

    auto AdmissionRetirementState::TransferMuxRoot() noexcept -> void
    {
        Transfer();
    }

    auto AdmissionRetirementState::RetainMuxRoot() noexcept -> void
    {
        Storage_->Retain(shared_from_this());
        RequestRetirement();
    }

    auto AdmissionRetirementState::Track(const Prism::SharedTransmission& Transport)
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!Transport)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        if (Transport == Inbound_) return {};
        for (std::size_t Index = 0; Index < TrackedCount_; ++Index)
            if (Tracked_[Index].Transport == Transport) return {};
        if (TrackedCount_ == Tracked_.size())
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        Tracked_[TrackedCount_++].Transport = Transport;
        return {};
    }

    auto AdmissionRetirementState::Transfer() noexcept -> void
    {
        Plane_.reset();
        RootGenerationLease_ = {};
        Inbound_.reset();
        Tracked_.fill({});
        TrackedCount_ = 0;
        ResetAttempts();
        Retired_.store(true, std::memory_order_release);
        Context_.reset();
    }

    auto AdmissionRetirementState::Retire(Prism::Fault::Failure Primary)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        bool Idle = false;
        if (!Running_.compare_exchange_strong(Idle, true, std::memory_order_acq_rel))
        {
            PreserveAdmissionFailure(Primary,
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            Storage_->Retain(shared_from_this());
            RequestRetirement();
            co_return Primary;
        }

        AdmissionRetirementResult Result;
        try
        {
            Result = co_await RetireResources(shared_from_this());
        }
        catch (...)
        {
            Result.Complete = false;
            Result.Error = AdmissionFailureFromException(std::current_exception());
        }
        Running_.store(false, std::memory_order_release);
        PreserveAdmissionFailure(Primary, Result.Error);
        if (Result.Complete)
        {
            Complete();
        }
        else
        {
            Storage_->Retain(shared_from_this());
            if ((RetrySchedule_.load(std::memory_order_acquire) & RetryScheduledFlag) == 0U)
            {
                RequestRetirement();
            }
        }
        co_return Primary;
    }

    auto AdmissionRetirementState::RequestRetirement() -> void
    {
        if (Retired_.load(std::memory_order_acquire))
        {
            return;
        }
        auto State = RetrySchedule_.load(std::memory_order_acquire);
        for (;;)
        {
            if (Retired_.load(std::memory_order_acquire)) return;
            const bool AlreadyScheduled = (State & RetryScheduledFlag) != 0U;
            const bool AttemptInFlight = Running_.load(std::memory_order_acquire);
            const auto Desired = (AlreadyScheduled || AttemptInFlight)
                ? static_cast<std::uint8_t>(State | RetryScheduledFlag | RetryRequestedFlag)
                : RetryScheduledFlag;
            if (Desired == State) return;
            if (RetrySchedule_.compare_exchange_weak(State, Desired,
                    std::memory_order_acq_rel, std::memory_order_acquire))
            {
                if (!AlreadyScheduled) PostRetryCommand();
                return;
            }
        }
    }

    auto AdmissionRetirementState::IsRetired() const noexcept -> bool
    {
        return Retired_.load(std::memory_order_acquire);
    }

    auto AdmissionRetirementState::IsDispatchUnavailable() const noexcept -> bool
    {
        return !Reclaimer_ || !Reclaimer_->CanDispatch();
    }

    auto AdmissionRetirementState::PostRetryCommand() noexcept -> void
    {
        const auto Self = shared_from_this();
        const auto Posted = Reclaimer_->Post(RetryCommand{Self});
        if (!Posted)
        {
            RetrySchedule_.store(0U, std::memory_order_release);
            Storage_->Retain(Self);
        }
    }

    auto AdmissionRetirementState::FinishScheduledRetry() noexcept -> void
    {
        auto State = RetrySchedule_.load(std::memory_order_acquire);
        for (;;)
        {
            const bool Retry = !Retired_.load(std::memory_order_acquire) &&
                (State & RetryRequestedFlag) != 0U;
            const auto Desired = Retry ? RetryScheduledFlag : std::uint8_t{0U};
            if (RetrySchedule_.compare_exchange_weak(State, Desired,
                    std::memory_order_acq_rel, std::memory_order_acquire))
            {
                if (Retry) PostRetryCommand();
                return;
            }
        }
    }

    auto AdmissionRetirementState::RetryCommand::operator()() noexcept -> void
    {
        Owner->StartRetry();
    }

    auto AdmissionRetirementState::RetryCompletion::operator()(
        std::exception_ptr Exception,
        std::expected<void, Prism::Fault::Failure> Result) noexcept -> void
    {
        if (Exception)
        {
            Owner->Storage_->Retain(Owner);
        }
        else if (!Result)
        {
            Owner->Storage_->Retain(Owner);
        }
        Owner->FinishScheduledRetry();
    }

    auto AdmissionRetirementState::RetireResources(
        std::shared_ptr<AdmissionRetirementState> Owner)
        -> Net::awaitable<AdmissionRetirementResult>
    {
        co_await Net::dispatch(Owner->Reclaimer_->Executor(), Net::use_awaitable);
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());

        AdmissionRetirementResult Result;
        Prism::SharedTransmission Root;
        if (Owner->Plane_)
        {
            Root = Owner->Plane_->Transport();
            auto RootResult = co_await RetireRoot(Owner);
            MergeAdmissionRetirementResult(Result, RootResult);
        }
        for (std::size_t Index = Owner->TrackedCount_; Index > 0; --Index)
        {
            auto &Tracked = Owner->Tracked_[Index - 1U];
            if (!Tracked.Transport || Tracked.Transport == Root ||
                Tracked.Transport == Owner->Inbound_) continue;
            const auto TrackedResult = co_await RetireAdmissionTransport(
                Tracked.Transport, Tracked.CancelAttempted, Tracked.CloseAttempted);
            MergeAdmissionRetirementResult(Result, TrackedResult);
        }
        if (Owner->Inbound_ && Owner->Inbound_ != Root)
        {
            auto InboundResult = co_await RetireAdmissionTransport(Owner->Inbound_,
                Owner->InboundCancelAttempted_, Owner->InboundCloseAttempted_);
            MergeAdmissionRetirementResult(Result, InboundResult);
        }
        co_return Result;
    }

    auto AdmissionRetirementState::RetireRoot(
        std::shared_ptr<AdmissionRetirementState> Owner)
        -> Net::awaitable<AdmissionRetirementResult>
    {
        auto& Plane = *Owner->Plane_;
        if (auto* Datagram = Plane.Datagram(); Datagram && Datagram->Session)
        {
            auto Result = co_await RetireDatagram(Owner, Datagram->Session);
            const auto Drain = co_await DrainAdmissionTransport(Plane.Transport());
            MergeAdmissionRetirementResult(Result, Drain);
            co_return Result;
        }
        if (auto* Mux = Plane.Mux(); Mux && Mux->Session)
        {
            auto Result = co_await RetireMux(Owner, Mux->Session);
            if (!Result.Complete) co_return Result;
            const auto Transport = co_await RetireAdmissionTransport(Plane.Transport(),
                Owner->RootTransportCancelAttempted_, Owner->RootTransportCloseAttempted_);
            MergeAdmissionRetirementResult(Result, Transport);
            co_return Result;
        }
        co_return co_await RetireAdmissionTransport(Plane.Transport(),
            Owner->RootTransportCancelAttempted_, Owner->RootTransportCloseAttempted_);
    }

    auto AdmissionRetirementState::RetireDatagram(
        const std::shared_ptr<AdmissionRetirementState> &Owner,
        const std::shared_ptr<DatagramSession>& Session)
        -> Net::awaitable<AdmissionRetirementResult>
    {
        AdmissionRetirementResult Result;
        if (!Owner->RootCancelAttempted_)
        {
            Owner->RootCancelAttempted_ = true;
            try { Session->Cancel(); }
            catch (...)
            {
                PreserveAdmissionFailure(Result.Error,
                    AdmissionFailureFromException(std::current_exception()));
            }
        }
        if (!Owner->RootCloseAttempted_)
        {
            Owner->RootCloseAttempted_ = true;
            try { Session->Close(); }
            catch (...)
            {
                PreserveAdmissionFailure(Result.Error,
                    AdmissionFailureFromException(std::current_exception()));
            }
        }
        Result.Complete = true;
        std::shared_ptr<Prism::Contract::CarrierActivity> Activity;
        try
        {
            Activity = Session->Activity();
            if (!Activity)
            {
                Result.Complete = false;
                PreserveAdmissionFailure(Result.Error,
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                co_return Result;
            }
            Activity->Seal();
            const auto Drain = co_await Activity->Drain();
            if (!Drain) PreserveAdmissionFailure(Result.Error, Drain.error());
            if (!Activity->IsRetired())
            {
                Result.Complete = false;
                PreserveAdmissionFailure(Result.Error,
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
        }
        catch (...)
        {
            PreserveAdmissionFailure(Result.Error,
                AdmissionFailureFromException(std::current_exception()));
        }
        Result.Complete = Activity && Activity->IsRetired();
        co_return Result;
    }

    auto AdmissionRetirementState::RetireMux(
        const std::shared_ptr<AdmissionRetirementState> &Owner,
        const std::shared_ptr<MuxSession>& Session)
        -> Net::awaitable<AdmissionRetirementResult>
    {
        AdmissionRetirementResult Result;
        if (!Owner->RootCancelAttempted_)
        {
            Owner->RootCancelAttempted_ = true;
            try { Session->Cancel(); }
            catch (...)
            {
                PreserveAdmissionFailure(Result.Error,
                    AdmissionFailureFromException(std::current_exception()));
            }
        }
        if (!Owner->RootCloseAttempted_)
        {
            Owner->RootCloseAttempted_ = true;
            try { Session->Close(); }
            catch (...)
            {
                PreserveAdmissionFailure(Result.Error,
                    AdmissionFailureFromException(std::current_exception()));
            }
        }
        Result.Complete = true;
        std::shared_ptr<Prism::Contract::CarrierActivity> Activity;
        try
        {
            Activity = Session->Activity();
            if (!Activity)
            {
                Result.Complete = false;
                PreserveAdmissionFailure(Result.Error,
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                co_return Result;
            }
            Activity->Seal();
            const auto Drain = co_await Activity->Drain();
            if (!Drain) PreserveAdmissionFailure(Result.Error, Drain.error());
        }
        catch (...)
        {
            PreserveAdmissionFailure(Result.Error,
                AdmissionFailureFromException(std::current_exception()));
        }
        if (!Activity || !Activity->IsRetired() || !Session->IsRetired())
        {
            Result.Complete = false;
            PreserveAdmissionFailure(Result.Error,
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        co_return Result;
    }

    auto AdmissionRetirementState::ResetAttempts() noexcept -> void
    {
        InboundCancelAttempted_ = false;
        InboundCloseAttempted_ = false;
        RootCancelAttempted_ = false;
        RootCloseAttempted_ = false;
        RootTransportCancelAttempted_ = false;
        RootTransportCloseAttempted_ = false;
        for (auto &Resource : Tracked_)
        {
            Resource.CancelAttempted = false;
            Resource.CloseAttempted = false;
        }
    }

    auto AdmissionRetirementState::Complete() noexcept -> void
    {
        Plane_.reset();
        RootGenerationLease_ = {};
        ReleaseMuxRootParentStreamLease();
        Inbound_.reset();
        Tracked_.fill({});
        TrackedCount_ = 0;
        ResetAttempts();
        Retired_.store(true, std::memory_order_release);
        Context_.reset();
    }

    auto AdmissionRetirementState::StartRetry() noexcept -> void
    {
        if (Retired_.load(std::memory_order_acquire))
        {
            FinishScheduledRetry();
            return;
        }
        const auto Self = shared_from_this();
        try
        {
            Net::co_spawn(Reclaimer_->Executor(), RetryOnExecutor(Self),
                RetryCompletion{Self});
        }
        catch (...)
        {
            RetrySchedule_.store(0U, std::memory_order_release);
            Storage_->Retain(Self);
        }
    }

    auto AdmissionRetirementState::RetryOnExecutor(
        std::shared_ptr<AdmissionRetirementState> Owner)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        bool Idle = false;
        if (!Owner->Running_.compare_exchange_strong(
                Idle, true, std::memory_order_acq_rel))
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        AdmissionRetirementResult Result;
        try
        {
            Result = co_await RetireResources(Owner);
        }
        catch (...)
        {
            Result.Complete = false;
            Result.Error = AdmissionFailureFromException(std::current_exception());
        }
        Owner->Running_.store(false, std::memory_order_release);
        if (Result.Complete) Owner->Complete();
        else Owner->Storage_->Retain(Owner);
        if (Result.Error.Failed()) co_return std::unexpected(Result.Error);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }
}
