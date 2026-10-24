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

namespace Prism::Boundary
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
        struct State;

    public:
        /** @brief 一个 unique owner 的共享连接槽和每连接包计数。 */
        class Reservation final
        {
        public:
            Reservation(const Reservation&) = delete;
            auto operator=(const Reservation&) -> Reservation& = delete;
            ~Reservation();

            /** @brief 将预约转交给真实 Native owner，禁止析构代替关闭回执。 */
            [[nodiscard]] auto RetainOwner() noexcept -> bool;

            /** @brief 仅在真实 OnClosed 或确认无 Native owner 时返还容量。 */
            auto Complete() noexcept -> void;

            /** @brief 检查该 owner 是否仍可接收下一包。 */
            [[nodiscard]] auto CanAcceptPacket() const noexcept -> bool;

            /** @brief 记录已由协议 owner 接受的数据报。 */
            auto RecordAcceptedPacket() noexcept -> void;

        private:
            friend class QuicAdmissionBudget;

            enum class ReservationState : std::uint8_t
            {
                Uncounted,
                Pending,
                Owned,
                Released,
            };

            explicit Reservation(std::shared_ptr<State> StateValue);
            auto Count() noexcept -> void;

            std::shared_ptr<State> State_;
            std::atomic<ReservationState> ReservationState_{ReservationState::Uncounted};
            std::size_t Packets_{0};
        };

        explicit QuicAdmissionBudget(QuicAdmissionBudgetLimits Limits = {});

        /** @brief 未达上限时原子建立一个 owner 槽；满额返回空值。 */
        [[nodiscard]] auto TryReserve() -> std::shared_ptr<Reservation>;

        /** @brief 返回跨 Gateway 与 Registry 共享的真实活动 owner 数。 */
        [[nodiscard]] auto ActiveConnections() const noexcept -> std::size_t;

        /** @brief 返回跨入口累计接纳的数据报数。 */
        [[nodiscard]] auto AcceptedPackets() const noexcept -> std::size_t;

        /** @brief 返回创建时冻结的上限。 */
        [[nodiscard]] auto Limits() const noexcept -> QuicAdmissionBudgetLimits;

    private:
        std::shared_ptr<State> State_;
    };

} // namespace Prism::Boundary
