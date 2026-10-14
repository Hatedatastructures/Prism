/** @file AdmissionRetirement.hpp @brief admission ticket 的预预约关闭与 drain owner。 */
#pragma once
#include <Preview/Contract/Ingress/DataPlane.hpp>
#include <Preview/Contract/Ingress/MuxRootCreateRequest.hpp>
#include <Preview/Contract/Ingress/AdmissionTransportRetirement.hpp>
#include <Preview/Foundation/Executor/ClosingStorage.hpp>
#include <Preview/Foundation/Executor/ContextOwner.hpp>
#include <Preview/Foundation/Executor/ExecutorReclaimer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <array>
#include <atomic>
#include <cstddef>
#include <exception>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>
namespace Preview::Contract
{
    struct AdmissionRetirementEnvironment final
    {
        std::shared_ptr<Preview::Executor::ContextOwner> Context;
        std::shared_ptr<Preview::Executor::ClosingStorage> Storage;
        std::shared_ptr<Preview::Executor::ExecutorReclaimer> Reclaimer;
    };

    class AdmissionRetirementState final
        : public Preview::Executor::ClosingResource,
          public MuxRootCreateOwner,
          public std::enable_shared_from_this<AdmissionRetirementState>
    {
        friend class InboundAdmission;

        struct TrackedResource final
        {
            Preview::SharedTransmission Transport;
            bool CancelAttempted{false};
            bool CloseAttempted{false};
        };

    public:
        AdmissionRetirementState(
            Preview::SharedTransmission Inbound,
            AdmissionRetirementEnvironment Environment)
            : Inbound_(std::move(Inbound)), Context_(std::move(Environment.Context)),
              Storage_(std::move(Environment.Storage)), Reclaimer_(std::move(Environment.Reclaimer))
        {
        }

    private:
            auto Attach(ProtocolDataPlane Plane) noexcept -> void
            {
                if (!Plane_)
                {
                    Plane_.emplace(std::move(Plane));
                }
            }

            [[nodiscard]] auto ClaimMuxRootCreate() noexcept -> bool override
            {
                if (Retired_.load(std::memory_order_acquire) || Plane_) return false;
                bool Available = false;
                return MuxRootClaimed_.compare_exchange_strong(
                    Available, true, std::memory_order_acq_rel, std::memory_order_acquire);
            }

            [[nodiscard]] auto CanAttachMuxRootParentStreamLease() const noexcept
                -> bool override
            {
                return !Retired_.load(std::memory_order_acquire) &&
                    !MuxRootClaimed_.load(std::memory_order_acquire) && !Plane_;
            }

            auto AttachMuxRootPlane(ProtocolDataPlane &&Plane) noexcept -> void override
            {
                if (!Plane_) Plane_.emplace(std::move(Plane));
            }

            auto AttachMuxRootGenerationLease(
                Preview::Foundation::GenerationUseLease &&Lease) noexcept -> void override
            {
                RootGenerationLease_ = std::move(Lease);
            }

            [[nodiscard]] auto MuxRootTransport() const noexcept
                -> Preview::SharedTransmission override
            {
                if (!Plane_) return {};
                return Plane_->Transport();
            }

            auto AttachMuxRootSession(std::shared_ptr<MuxSession> Session) noexcept -> void override
            {
                if (Plane_)
                    if (auto *Mux = Plane_->Mux()) Mux->Session = std::move(Session);
            }

            [[nodiscard]] auto TakeMuxRootPlane() noexcept -> ProtocolDataPlane override
            {
                ProtocolDataPlane Result;
                if (Plane_)
                {
                    Result = std::move(*Plane_);
                    Plane_.reset();
                }
                return Result;
            }

            [[nodiscard]] auto TakeMuxRootGenerationLease() noexcept
                -> Preview::Foundation::GenerationUseLease override
            {
                return std::move(RootGenerationLease_);
            }

            auto TransferMuxRoot() noexcept -> void override { Transfer(); }

            auto RetainMuxRoot() noexcept -> void override
            {
                Storage_->Retain(shared_from_this());
                RequestRetirement();
            }

            [[nodiscard]] auto Track(const Preview::SharedTransmission& Transport)
                -> std::expected<void, Preview::Fault::Failure>
            {
                if (!Transport)
                    return std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
                if (Transport == Inbound_) return {};
                for (std::size_t Index = 0; Index < TrackedCount_; ++Index)
                    if (Tracked_[Index].Transport == Transport) return {};
                if (TrackedCount_ == Tracked_.size())
                    return std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::ResourceUnavailable});
                Tracked_[TrackedCount_++].Transport = Transport;
                return {};
            }

            auto Transfer() noexcept -> void
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

            [[nodiscard]] auto Retire(Preview::Fault::Failure Primary)
                -> Net::awaitable<Preview::Fault::Failure>
            {
                bool Idle = false;
                if (!Running_.compare_exchange_strong(Idle, true, std::memory_order_acq_rel))
                {
                    PreserveAdmissionFailure(Primary,
                        Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                    Storage_->Retain(shared_from_this());
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
                    RequestRetirement();
                }
                co_return Primary;
            }

            auto RequestRetirement() -> void override
            {
                if (Retired_.load(std::memory_order_acquire) ||
                    Scheduled_.exchange(true, std::memory_order_acq_rel))
                {
                    return;
                }
                const auto Self = shared_from_this();
                const auto Posted = Reclaimer_->Post(RetryCommand{Self});
                if (!Posted)
                {
                    Scheduled_.store(false, std::memory_order_release);
                    Storage_->Retain(Self);
                }
            }

            [[nodiscard]] auto IsRetired() const noexcept -> bool override
            {
                return Retired_.load(std::memory_order_acquire);
            }

            [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
            {
                return !Reclaimer_ || !Reclaimer_->CanDispatch();
            }

        private:
            struct RetryCommand final
            {
                std::shared_ptr<AdmissionRetirementState> Owner;
                auto operator()() noexcept -> void { Owner->StartRetry(); }
            };

            struct RetryCompletion final
            {
                std::shared_ptr<AdmissionRetirementState> Owner;
                auto operator()(std::exception_ptr Exception,
                    std::expected<void, Preview::Fault::Failure> Result) noexcept -> void
                {
                    Owner->Scheduled_.store(false, std::memory_order_release);
                    if (Exception)
                    {
                        Owner->Storage_->Retain(Owner);
                    }
                    else if (!Result)
                    {
                        Owner->Storage_->Retain(Owner);
                    }
                }
            };

            [[nodiscard]] static auto RetireResources(std::shared_ptr<AdmissionRetirementState> Owner)
                -> Net::awaitable<AdmissionRetirementResult>
            {
                co_await Net::dispatch(Owner->Reclaimer_->Executor(), Net::use_awaitable);
                co_await Net::this_coro::throw_if_cancelled(false);
                co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());

                AdmissionRetirementResult Result;
                Preview::SharedTransmission Root;
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

            [[nodiscard]] static auto RetireRoot(std::shared_ptr<AdmissionRetirementState> Owner)
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

            [[nodiscard]] static auto RetireDatagram(
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
                std::shared_ptr<Preview::Contract::CarrierActivity> Activity;
                try
                {
                    Activity = Session->Activity();
                    if (!Activity)
                    {
                        Result.Complete = false;
                        PreserveAdmissionFailure(Result.Error,
                            Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                        co_return Result;
                    }
                    Activity->Seal();
                    const auto Drain = co_await Activity->Drain();
                    if (!Drain) PreserveAdmissionFailure(Result.Error, Drain.error());
                    if (!Activity->IsRetired())
                    {
                        Result.Complete = false;
                        PreserveAdmissionFailure(Result.Error,
                            Preview::Fault::Failure{Preview::Fault::Code::Blocked});
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

            [[nodiscard]] static auto RetireMux(
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
                std::shared_ptr<Preview::Contract::CarrierActivity> Activity;
                try
                {
                    Activity = Session->Activity();
                    if (!Activity)
                    {
                        Result.Complete = false;
                        PreserveAdmissionFailure(Result.Error,
                            Preview::Fault::Failure{Preview::Fault::Code::Blocked});
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
                        Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                }
                co_return Result;
            }

            auto ResetAttempts() noexcept -> void
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

            auto Complete() noexcept -> void
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

            auto StartRetry() noexcept -> void
            {
                if (Retired_.load(std::memory_order_acquire))
                {
                    Scheduled_.store(false, std::memory_order_release);
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
                    Scheduled_.store(false, std::memory_order_release);
                    Storage_->Retain(Self);
                }
            }

            [[nodiscard]] static auto RetryOnExecutor(std::shared_ptr<AdmissionRetirementState> Owner)
                -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
            {
                bool Idle = false;
                if (!Owner->Running_.compare_exchange_strong(
                        Idle, true, std::memory_order_acq_rel))
                {
                    co_return std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::Blocked});
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
                co_return std::expected<void, Preview::Fault::Failure>{};
            }

            Preview::SharedTransmission Inbound_;
            std::array<TrackedResource, 8> Tracked_{};
            std::size_t TrackedCount_{0};
            std::shared_ptr<Preview::Executor::ContextOwner> Context_;
            std::shared_ptr<Preview::Executor::ClosingStorage> Storage_;
            std::shared_ptr<Preview::Executor::ExecutorReclaimer> Reclaimer_;
            std::optional<ProtocolDataPlane> Plane_;
            Preview::Foundation::GenerationUseLease RootGenerationLease_;
            std::atomic<bool> Running_{false};
            std::atomic<bool> Scheduled_{false};
            std::atomic<bool> Retired_{false};
            std::atomic<bool> MuxRootClaimed_{false};
            bool InboundCancelAttempted_{false};
            bool InboundCloseAttempted_{false};
            bool RootCancelAttempted_{false};
            bool RootCloseAttempted_{false};
            /// 协议任务退休后，admission 再独立确认根传输关闭；重试不重发控制。
            bool RootTransportCancelAttempted_{false};
            bool RootTransportCloseAttempted_{false};
        };
}
