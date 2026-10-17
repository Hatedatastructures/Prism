/** @file UsageCredit.hpp
 * @brief 单个已持久预约的无锁信用状态，部分成功只把对应字节转入实际用量。
 */
#pragma once
#include <Preview/Account/UsageModels.hpp>
#include <Preview/Contract/Account/PayloadBudget.hpp>
#include <atomic>
#include <expected>
#include <utility>

namespace Preview::Account::Detail
{
    /** @brief Remaining/InFlight/Consumed 共占 63 位，单块不超过 1MiB；关闭位禁止新增 I/O。 */
    class UsageCredit final : public Contract::PayloadSettlement,
        public std::enable_shared_from_this<UsageCredit>
    {
        static constexpr unsigned Width{21};
        static constexpr std::uint64_t Mask{(std::uint64_t{1} << Width) - 1U};
        static constexpr std::uint64_t Closed{std::uint64_t{1} << 63U};
    public:
        explicit UsageCredit(UsageReservation Reservation) : Reservation_(std::move(Reservation)), State_(Reservation_.Bytes) {}
        [[nodiscard]] auto Reservation() const noexcept -> const UsageReservation& { return Reservation_; }
        [[nodiscard]] auto TryAcquire(const Contract::PayloadRequest& Request)
            -> std::expected<Contract::PayloadPermit, Fault::Failure>
        {
            auto State = State_.load(std::memory_order_acquire);
            for (;;)
            {
                const auto Count = (std::min)(Request.Bytes, State & Mask);
                if ((State & Closed) || Count == 0 || (Request.Datagram && Count < Request.Bytes))
                    return std::unexpected(Fault::Failure{Fault::Code::WouldBlock});
                const auto Next = State - Count + (Count << Width);
                if (State_.compare_exchange_weak(State, Next, std::memory_order_acq_rel, std::memory_order_acquire))
                    return Contract::PayloadPermit{Count, shared_from_this()};
            }
        }
        auto Complete(const std::uint64_t Granted, const std::uint64_t Transferred) noexcept -> void override
        {
            auto State = State_.load(std::memory_order_acquire);
            for (;;)
            {
                const auto Next = State - (Granted << Width) + (Granted - Transferred) + (Transferred << (Width * 2));
                if (State_.compare_exchange_weak(State, Next, std::memory_order_acq_rel, std::memory_order_acquire)) return;
            }
        }
        auto Close() noexcept -> void { State_.fetch_or(Closed, std::memory_order_acq_rel); }
        [[nodiscard]] auto Idle() const noexcept -> bool
        { return ((State_.load(std::memory_order_acquire) >> Width) & Mask) == 0; }
        [[nodiscard]] auto Consumed() const noexcept -> std::uint64_t
        { return (State_.load(std::memory_order_acquire) >> (Width * 2)) & Mask; }
        [[nodiscard]] auto Available() const noexcept -> std::uint64_t
        { return State_.load(std::memory_order_acquire) & Mask; }
    private:
        const UsageReservation Reservation_;
        std::atomic<std::uint64_t> State_;
    };
}
