/**
 * @file ProviderBindingLifecycle.hpp
 * @brief Trojan、VLESS 与 VMess provider binding 的准入和聚合退休 owner。
 */
#pragma once

#include <Preview/Protocols/Common/ProviderSessionRetirement.hpp>
#include <Preview/Protocols/Common/ProtocolActivity.hpp>
#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <Preview/Protocols/Mux/RootBinding.hpp>

#include <boost/asio/this_coro.hpp>

#include <algorithm>
#include <atomic>
#include <expected>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace Preview::Protocols
{
    /**
     * @brief 各 configured provider 共用的准入 gate、活动票据目录与 mux root owner。
     * @details Material 仅在所有 accepts、protocol roots、载体与 generation leases 真实
     *          退休后清空；未完成 ticket 留在同一 L1 ClosingStorage，不用业务错误猜测
     *          完成；Binding::Drain 只汇报真实 Drain 错误与尚未完成的退栈，普通接入拒绝
     *          由该次 Accept 返回，不当成绑定关闭错误。
     */
    template<class BindingMaterial>
    class ProviderBindingLifecycle final
    {
    public:
        using Ticket = ProviderSessionRetirement<BindingMaterial>;

        class AcceptAttempt final
        {
        public:
            AcceptAttempt(AcceptAttempt&& Other) noexcept
                : Ticket_(std::exchange(Other.Ticket_, {})),
                  Reservation_(std::move(Other.Reservation_))
            {
                Other.Reservation_.reset();
            }
            AcceptAttempt(const AcceptAttempt&) = delete;
            auto operator=(AcceptAttempt&&) noexcept -> AcceptAttempt& = delete;
            auto operator=(const AcceptAttempt&) -> AcceptAttempt& = delete;
            ~AcceptAttempt() noexcept
            {
                if (!Reservation_)
                {
                    return;
                }
                Ticket_->RequestClose();
                Ticket_->FinishAccept();
                Reservation_->Complete();
                Reservation_.reset();
                Ticket_->RetainAndRetry();
                Ticket_->CompleteAcceptAttempt();
            }

            [[nodiscard]] auto Owner() const noexcept -> std::shared_ptr<Ticket> { return Ticket_; }
            auto FinishProtocol() noexcept -> void
            {
                if (Ticket_)
                {
                    Ticket_->FinishAccept();
                }
            }
            auto Complete() noexcept -> void
            {
                if (Reservation_)
                {
                    FinishProtocol();
                    Reservation_->Complete();
                    Reservation_.reset();
                    Ticket_->CompleteAcceptAttempt();
                }
            }

        private:
            friend class ProviderBindingLifecycle;
            AcceptAttempt(std::shared_ptr<Ticket> Value,
                Preview::Protocols::ProtocolActivity::Reservation Reservation)
                : Ticket_(std::move(Value)), Reservation_(std::move(Reservation)) {}
            std::shared_ptr<Ticket> Ticket_;
            std::optional<Preview::Protocols::ProtocolActivity::Reservation> Reservation_;
        };

        explicit ProviderBindingLifecycle(std::shared_ptr<const BindingMaterial> MaterialValue)
            : Material_(MaterialValue), Generation_(MaterialValue->Generation),
              UseState_(MaterialValue->GenerationUseState),
              Admissions_(std::make_shared<ProtocolActivity>(MaterialValue->Executor)),
              RouteBindings_(std::make_shared<ProtocolActivity>(MaterialValue->Executor))
        {
        }

        ProviderBindingLifecycle(const ProviderBindingLifecycle&) = delete;
        auto operator=(const ProviderBindingLifecycle&) -> ProviderBindingLifecycle& = delete;

        ~ProviderBindingLifecycle() noexcept { Close(); }

        [[nodiscard]] auto Material() const noexcept -> std::shared_ptr<const BindingMaterial>
        {
            return Material_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto UseState() const noexcept
            -> std::shared_ptr<Preview::Foundation::GenerationUseState>
        {
            return UseState_;
        }

        [[nodiscard]] auto Begin(Preview::SharedTransmission Inbound)
            -> std::expected<AcceptAttempt, Preview::Fault::Failure>
        {
            if (!Inbound || Closed_.load(std::memory_order_acquire))
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }
            auto Reservation = Admissions_->TryBegin();
            if (!Reservation)
            {
                return std::unexpected(Reservation.error());
            }
            auto MaterialValue = Material();
            if (!MaterialValue || !UseState_)
            {
                Reservation->Complete();
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }
            std::shared_ptr<Ticket> Session;
            try
            {
                Session = std::make_shared<Ticket>(Inbound, MaterialValue,
                    Preview::Foundation::GenerationUseLease{});
                Append(Session);
            }
            catch (...)
            {
                const auto Failure = Preview::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception());
                if (Session)
                {
                    Session->RecordFailure(Failure);
                    Session->RequestClose();
                    Session->FinishAccept();
                    Reservation->Complete();
                    Session->RetainAndRetry();
                    Session->CompleteAcceptAttempt();
                }
                else Reservation->Complete();
                return std::unexpected(Failure);
            }
            auto UseLease = UseState_->Acquire();
            if (!UseLease)
            {
                Session->RecordFailure(UseLease.error());
                Session->RequestClose();
                Session->FinishAccept();
                Reservation->Complete();
                Session->RetainAndRetry();
                Session->CompleteAcceptAttempt();
                return std::unexpected(UseLease.error());
            }
            Session->SetUseLease(std::move(*UseLease));
            if (Closed_.load(std::memory_order_acquire))
            {
                const auto Failure = Preview::Fault::Failure{Preview::Fault::Code::Canceled};
                Session->RecordFailure(Failure);
                Session->RequestClose();
                Session->FinishAccept();
                Reservation->Complete();
                Session->RetainAndRetry();
                Session->CompleteAcceptAttempt();
                return std::unexpected(Failure);
            }
            return AcceptAttempt(std::move(Session), std::move(*Reservation));
        }

        /** @brief 只在监听前把候选选中的同一 RootBinding 登记为真实 owner。 */
        [[nodiscard]] auto AddMux(const std::shared_ptr<Preview::Mux::RootBinding>& Mux) -> bool
        {
            if (!Mux || Mux->IsRetired())
            {
                return false;
            }
            auto Reservation = RouteBindings_->TryBegin();
            if (!Reservation)
            {
                Mux->Close();
                return false;
            }
            for (;;)
            {
                auto Current = Muxes_.load(std::memory_order_acquire);
                if (std::find(Current->begin(), Current->end(), Mux) != Current->end())
                {
                    Reservation->Complete();
                    return !Closed_.load(std::memory_order_acquire);
                }
                auto Next = std::make_shared<MuxList>(*Current);
                Next->push_back(Mux);
                if (!Muxes_.compare_exchange_weak(Current,
                        std::const_pointer_cast<const MuxList>(Next),
                        std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    continue;
                }
                const auto IsClosed = Closed_.load(std::memory_order_acquire);
                if (IsClosed) Mux->Close();
                Reservation->Complete();
                return !IsClosed;
            }
        }

        /** @brief 封止新 Accept 并关闭每个已登记根和票据。 */
        auto Close() noexcept -> void
        {
            if (Closed_.exchange(true, std::memory_order_acq_rel))
            {
                return;
            }
            Admissions_->Seal();
            RouteBindings_->Seal();
            const auto Tickets = Tickets_.load(std::memory_order_acquire);
            for (const auto& TicketValue : *Tickets)
            {
                TicketValue->RequestClose();
                if (!TicketValue->IsRetired())
                {
                    TicketValue->RetainForOwnerRetry();
                    TicketValue->RequestOwnerRetirement();
                }
            }
            const auto Muxes = Muxes_.load(std::memory_order_acquire);
            for (const auto& Mux : *Muxes)
            {
                Mux->Close();
            }
        }

        /** @brief 等待接入退栈，再排空全部 session 与 mux；首个完整错误独立返回。 */
        [[nodiscard]] auto Drain() -> Net::awaitable<ProviderRetirementResult>
        {
            bool Idle = false;
            if (!Draining_.compare_exchange_strong(Idle, true, std::memory_order_acq_rel))
            {
                co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            DrainGuard Guard{Draining_};
            Close();
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            auto First = ProviderRetirementResult{};
            auto Persistent = ProviderRetirementResult{};
            const auto Historical = DrainFailure_.Load();
            if (Historical.Failed())
            {
                First = std::unexpected(Historical);
                Persistent = First;
            }
            const auto Admissions = co_await Admissions_->Drain();
            PreserveExpected(First, Admissions);
            PreserveExpected(Persistent, Admissions);
            const auto Routes = co_await RouteBindings_->Drain();
            PreserveExpected(First, Routes);
            PreserveExpected(Persistent, Routes);
            bool RetryableTicketCancellation = false;
            bool RetryableMuxCancellation = false;
            const auto Tickets = Tickets_.load(std::memory_order_acquire);
            for (const auto& TicketValue : *Tickets)
            {
                const auto Result = co_await TicketValue->Drain();
                if (!Result)
                {
                    if (Result.error().Code == Preview::Fault::Code::Canceled)
                    {
                        // 本轮结果可能先于自动重试的物理回执返回。
                        RetryableTicketCancellation = true;
                        const auto Durable = TicketValue->DrainFailure();
                        if (Durable.Failed())
                        {
                            PreserveExpected(Persistent,
                                ProviderRetirementResult{std::unexpected(Durable)});
                        }
                    }
                    else
                    {
                        PreserveExpected(Persistent, Result);
                    }
                }
                PreserveExpected(First, Result);
            }
            const auto MuxSnapshot = Muxes_.load(std::memory_order_acquire);
            for (const auto& Mux : *MuxSnapshot)
            {
                const auto Result = co_await Mux->Drain();
                PreserveExpected(First, Result);
                if (!Result && Result.error().Code == Preview::Fault::Code::Canceled)
                {
                    RetryableMuxCancellation = true;
                    const auto Durable = Mux->DrainFailure();
                    if (Durable.Failed())
                    {
                        PreserveExpected(Persistent,
                            ProviderRetirementResult{std::unexpected(Durable)});
                    }
                }
                else
                {
                    PreserveExpected(Persistent, Result);
                }
            }
            const bool PhysicallyRetired = IsPhysicallyRetired();
            for (const auto& TicketValue : *Tickets)
            {
                const auto Durable = TicketValue->DrainFailure();
                if (Durable.Failed())
                {
                    PreserveExpected(Persistent,
                        ProviderRetirementResult{std::unexpected(Durable)});
                }
            }
            for (const auto& Mux : *MuxSnapshot)
            {
                const auto Durable = Mux->DrainFailure();
                if (Durable.Failed())
                {
                    PreserveExpected(Persistent,
                        ProviderRetirementResult{std::unexpected(Durable)});
                }
            }
            if (PhysicallyRetired)
            {
                if ((RetryableTicketCancellation || RetryableMuxCancellation) &&
                    Persistent && !First &&
                    First.error().Code == Preview::Fault::Code::Canceled)
                {
                    First = ProviderRetirementResult{};
                }
                Material_.store({}, std::memory_order_release);
                Generation_.reset();
                UseState_.reset();
                Muxes_.store(std::make_shared<const MuxList>(), std::memory_order_release);
                Tickets_.store(std::make_shared<const TicketList>(), std::memory_order_release);
            }
            else
            {
                if (First)
                {
                    First = std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                    PreserveExpected(Persistent, First);
                }
            }
            if (!Persistent)
            {
                DrainFailure_.TrySet(Persistent.error());
                First = Persistent;
            }
            if (!First)
            {
                co_return std::unexpected(First.error());
            }
            co_return ProviderRetirementResult{};
        }

        /** @brief 只由真实 accept/root/carrier 物理回执组成，不检查历史 Drain 结果。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool
        {
            return Closed_.load(std::memory_order_acquire) &&
                Admissions_->IsRetired() && RouteBindings_->IsRetired() &&
                !Material_.load(std::memory_order_acquire) &&
                IsPhysicallyRetired();
        }

        /** @brief 已记录的持久关闭错误；可重试 attempt cancellation 不写入此值。 */
        [[nodiscard]] auto DrainFailure() const noexcept -> Preview::Fault::Failure
        {
            return DrainFailure_.Load();
        }

    private:
        using TicketList = std::vector<std::shared_ptr<Ticket>>;
        using MuxList = std::vector<std::shared_ptr<Preview::Mux::RootBinding>>;

        struct DrainGuard final
        {
            std::atomic<bool>& State;
            ~DrainGuard() noexcept { State.store(false, std::memory_order_release); }
        };

        auto Append(const std::shared_ptr<Ticket>& TicketValue) -> void
        {
            for (;;)
            {
                auto Current = Tickets_.load(std::memory_order_acquire);
                auto Next = std::make_shared<TicketList>();
                Next->reserve(Current->size() + 1U);
                for (const auto& Existing : *Current)
                {
                    if (Existing->IsRetired())
                    {
                        const auto Failure = Existing->DrainFailure();
                        if (Failure.Failed()) DrainFailure_.TrySet(Failure);
                    }
                    else Next->push_back(Existing);
                }
                Next->push_back(TicketValue);
                if (Tickets_.compare_exchange_weak(Current,
                        std::const_pointer_cast<const TicketList>(Next),
                        std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    return;
                }
            }
        }

        [[nodiscard]] auto IsPhysicallyRetired() const noexcept -> bool
        {
            for (const auto& TicketValue : *Tickets_.load(std::memory_order_acquire))
            {
                if (!TicketValue->IsRetired())
                {
                    return false;
                }
            }
            for (const auto& Mux : *Muxes_.load(std::memory_order_acquire))
            {
                if (!Mux->IsRetired())
                {
                    return false;
                }
            }
            return true;
        }

        static auto PreserveExpected(ProviderRetirementResult& Primary,
            const ProviderRetirementResult& Secondary) noexcept -> void
        {
            if (Primary && !Secondary)
            {
                Primary = std::unexpected(Secondary.error());
            }
        }

        std::atomic<std::shared_ptr<const BindingMaterial>> Material_;
        Preview::Foundation::GenerationPin Generation_;
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState_;
        std::shared_ptr<ProtocolActivity> Admissions_;
        std::shared_ptr<ProtocolActivity> RouteBindings_;
        Preview::Fault::FailureState DrainFailure_;
        std::atomic<std::shared_ptr<const TicketList>> Tickets_{
            std::make_shared<const TicketList>()};
        std::atomic<std::shared_ptr<const MuxList>> Muxes_{
            std::make_shared<const MuxList>()};
        std::atomic<bool> Closed_{false};
        std::atomic<bool> Draining_{false};
    };

    template<class Attempt>
    [[nodiscard]] auto RejectProviderAccept(
        Preview::Contract::InboundAdmission& Admission,
        Attempt& AttemptValue,
        Preview::Fault::Failure Failure)
        -> Net::awaitable<Preview::Contract::AcceptOutcome>
    {
        const auto Ticket = AttemptValue.Owner();
        Ticket->RecordFailure(Failure);
        auto Rejected = co_await Admission.Reject(Failure);
        auto Primary = Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument};
        if (!Rejected) Primary = Rejected.error();
        const auto SessionFailure = Ticket->SessionFailure();
        if (SessionFailure.Failed()) Primary = SessionFailure;
        Ticket->RecordFailure(Primary);
        AttemptValue.FinishProtocol();
        const auto Drain = co_await Ticket->Drain();
        if (!Drain) Ticket->RecordDrainFailure(Drain.error());
        AttemptValue.Complete();
        co_return std::unexpected(Primary);
    }

    struct RejectedProviderPlane final
    {
        Preview::Contract::ProtocolDataPlane Plane;
        Preview::Fault::Failure Failure;
    };

    template<class Attempt>
    [[nodiscard]] auto RejectProviderPlane(
        Preview::Contract::InboundAdmission& Admission,
        Attempt& AttemptValue,
        RejectedProviderPlane Request)
        -> Net::awaitable<Preview::Contract::AcceptOutcome>
    {
        const auto Ticket = AttemptValue.Owner();
        Ticket->RecordFailure(Request.Failure);
        auto Rejected = co_await Admission.Reject(std::move(Request.Plane), Request.Failure);
        auto Primary = Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument};
        if (!Rejected) Primary = Rejected.error();
        const auto SessionFailure = Ticket->SessionFailure();
        if (SessionFailure.Failed()) Primary = SessionFailure;
        Ticket->RecordFailure(Primary);
        AttemptValue.FinishProtocol();
        const auto Drain = co_await Ticket->Drain();
        if (!Drain) Ticket->RecordDrainFailure(Drain.error());
        AttemptValue.Complete();
        co_return std::unexpected(Primary);
    }

    template<class Attempt>
    [[nodiscard]] auto AdmitProviderPlane(
        Preview::Contract::InboundAdmission& Admission,
        Attempt& AttemptValue,
        Preview::Contract::ProtocolDataPlane Plane)
        -> Net::awaitable<Preview::Contract::AcceptOutcome>
    {
        const auto Ticket = AttemptValue.Owner();
        const auto Published = Ticket->Publish(Plane);
        if (!Published)
        {
            co_return co_await RejectProviderPlane(Admission, AttemptValue,
                RejectedProviderPlane{std::move(Plane), Published.error()});
        }
        auto Outcome = co_await Admission.Admit(std::move(Plane));
        if (!Outcome)
        {
            Ticket->RecordFailure(Outcome.error());
            AttemptValue.FinishProtocol();
            const auto Drain = co_await Ticket->Drain();
            if (!Drain) Ticket->RecordDrainFailure(Drain.error());
            AttemptValue.Complete();
            co_return std::unexpected(Outcome.error());
        }
        AttemptValue.Complete();
        co_return std::move(Outcome);
    }
}
