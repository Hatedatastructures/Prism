/** @file QuicAdmissionBudget.cpp @brief QUIC admission reservation 与计数实现。 */
#include <Prism/Boundary/Quic/QuicAdmissionBudget.hpp>

#include <memory>
#include <utility>

namespace Prism::Boundary
{
    struct QuicAdmissionBudget::State final
    {
        explicit State(QuicAdmissionBudgetLimits LimitsValue)
            : Limits(LimitsValue)
        {
        }

        QuicAdmissionBudgetLimits Limits;
        std::atomic<std::size_t> ActiveConnections{0};
        std::atomic<std::size_t> AcceptedPackets{0};
    };

    QuicAdmissionBudget::Reservation::Reservation(
        std::shared_ptr<QuicAdmissionBudget::State> StateValue)
        : State_(std::move(StateValue))
    {
    }

    QuicAdmissionBudget::Reservation::~Reservation()
    {
        auto Expected = ReservationState::Pending;
        if (ReservationState_.compare_exchange_strong(
                Expected,
                ReservationState::Released,
                std::memory_order_acq_rel,
                std::memory_order_acquire))
        {
            State_->ActiveConnections.fetch_sub(1, std::memory_order_acq_rel);
        }
    }

    auto QuicAdmissionBudget::Reservation::RetainOwner() noexcept -> bool
    {
        auto Expected = ReservationState::Pending;
        return ReservationState_.compare_exchange_strong(
            Expected,
            ReservationState::Owned,
            std::memory_order_acq_rel,
            std::memory_order_acquire);
    }

    auto QuicAdmissionBudget::Reservation::Complete() noexcept -> void
    {
        const auto Previous = ReservationState_.exchange(
            ReservationState::Released, std::memory_order_acq_rel);
        if (Previous != ReservationState::Released)
        {
            State_->ActiveConnections.fetch_sub(1, std::memory_order_acq_rel);
        }
    }

    auto QuicAdmissionBudget::Reservation::CanAcceptPacket() const noexcept -> bool
    {
        return Packets_ < State_->Limits.MaxPacketsPerConnection;
    }

    auto QuicAdmissionBudget::Reservation::RecordAcceptedPacket() noexcept -> void
    {
        ++Packets_;
        State_->AcceptedPackets.fetch_add(1, std::memory_order_relaxed);
    }

    auto QuicAdmissionBudget::Reservation::Count() noexcept -> void
    {
        ReservationState_.store(ReservationState::Pending, std::memory_order_release);
    }

    QuicAdmissionBudget::QuicAdmissionBudget(QuicAdmissionBudgetLimits Limits)
        : State_(std::make_shared<State>(Limits))
    {
    }

    auto QuicAdmissionBudget::TryReserve() -> std::shared_ptr<Reservation>
    {
        auto Current = State_->ActiveConnections.load(std::memory_order_relaxed);
        while (Current < State_->Limits.MaxConnections)
        {
            auto Value = std::shared_ptr<Reservation>(new Reservation(State_));
            if (State_->ActiveConnections.compare_exchange_weak(
                    Current,
                    Current + 1U,
                    std::memory_order_acq_rel,
                    std::memory_order_relaxed))
            {
                Value->Count();
                return Value;
            }
        }
        return {};
    }

    auto QuicAdmissionBudget::ActiveConnections() const noexcept -> std::size_t
    {
        return State_->ActiveConnections.load(std::memory_order_acquire);
    }

    auto QuicAdmissionBudget::AcceptedPackets() const noexcept -> std::size_t
    {
        return State_->AcceptedPackets.load(std::memory_order_relaxed);
    }

    auto QuicAdmissionBudget::Limits() const noexcept -> QuicAdmissionBudgetLimits
    {
        return State_->Limits;
    }
}
