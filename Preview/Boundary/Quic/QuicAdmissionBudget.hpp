/**
 * @file QuicAdmissionBudget.hpp
 * @brief Boundary 共享 QUIC 连接与每连接数据报预算。
 * @details 连接数跨所有入口原子计数；owner 转交后只允许真实关闭回执返还容量。
 */
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

namespace Preview::Boundary
{

    /** @brief 未知 CID admission 的 typed 结果。 */
    enum class QuicAdmissionDisposition : std::uint8_t
    {
        NotHandled,
        Accepted,
        CapacityExceeded,
        Rejected,
    };

    /** @brief QUIC admission 的冷路径上限。 */
    struct QuicAdmissionBudgetLimits final
    {
        std::size_t MaxConnections{4096};
        std::size_t MaxPacketsPerConnection{65536};
    };

    /** @brief 共享计数活动 QUIC owner 的 admission 预算。 */
    class QuicAdmissionBudget final
    {
        struct State final
        {
            explicit State(QuicAdmissionBudgetLimits LimitsValue)
                : Limits(LimitsValue)
            {
            }

            QuicAdmissionBudgetLimits Limits;
            std::atomic<std::size_t> ActiveConnections{0};
            std::atomic<std::size_t> AcceptedPackets{0};
        };

    public:
        /** @brief 一个 unique owner 的共享连接槽和每连接包计数。 */
        class Reservation final
        {
        public:
            Reservation(const Reservation&) = delete;
            auto operator=(const Reservation&) -> Reservation& = delete;
            ~Reservation()
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

            /** @brief 将预约转交给真实 Native owner，禁止析构代替关闭回执。 */
            [[nodiscard]] auto RetainOwner() noexcept -> bool
            {
                auto Expected = ReservationState::Pending;
                return ReservationState_.compare_exchange_strong(
                    Expected,
                    ReservationState::Owned,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire);
            }

            /** @brief 仅在真实 OnClosed 或确认无 Native owner 时返还容量。 */
            auto Complete() noexcept -> void
            {
                const auto Previous = ReservationState_.exchange(
                    ReservationState::Released, std::memory_order_acq_rel);
                if (Previous != ReservationState::Released)
                {
                    State_->ActiveConnections.fetch_sub(1, std::memory_order_acq_rel);
                }
            }

            /** @brief 检查该 owner 是否仍可接收下一包。 */
            [[nodiscard]] auto CanAcceptPacket() const noexcept -> bool
            {
                return Packets_ < State_->Limits.MaxPacketsPerConnection;
            }

            /** @brief 记录已由协议 owner 接受的数据报。 */
            auto RecordAcceptedPacket() noexcept -> void
            {
                ++Packets_;
                State_->AcceptedPackets.fetch_add(1, std::memory_order_relaxed);
            }

        private:
            friend class QuicAdmissionBudget;

            enum class ReservationState : std::uint8_t
            {
                Uncounted,
                Pending,
                Owned,
                Released,
            };

            explicit Reservation(std::shared_ptr<State> StateValue)
                : State_(std::move(StateValue))
            {
            }

            auto Count() noexcept -> void
            {
                ReservationState_.store(ReservationState::Pending, std::memory_order_release);
            }

            std::shared_ptr<State> State_;
            std::atomic<ReservationState> ReservationState_{ReservationState::Uncounted};
            std::size_t Packets_{0};
        };

        explicit QuicAdmissionBudget(QuicAdmissionBudgetLimits Limits = {})
            : State_(std::make_shared<State>(Limits))
        {
        }

        /** @brief 未达上限时原子建立一个 owner 槽；满额返回空值。 */
        [[nodiscard]] auto TryReserve() -> std::shared_ptr<Reservation>
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

        /** @brief 返回跨 Gateway 与 Registry 共享的真实活动 owner 数。 */
        [[nodiscard]] auto ActiveConnections() const noexcept -> std::size_t
        {
            return State_->ActiveConnections.load(std::memory_order_acquire);
        }

        /** @brief 返回跨入口累计接纳的数据报数。 */
        [[nodiscard]] auto AcceptedPackets() const noexcept -> std::size_t
        {
            return State_->AcceptedPackets.load(std::memory_order_relaxed);
        }

        /** @brief 返回创建时冻结的上限。 */
        [[nodiscard]] auto Limits() const noexcept -> QuicAdmissionBudgetLimits
        {
            return State_->Limits;
        }

    private:
        std::shared_ptr<State> State_;
    };

} // namespace Preview::Boundary
