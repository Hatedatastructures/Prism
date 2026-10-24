/** @file Rate.hpp
 * @brief 冻结策略视图与唯一共享速率账本的正式前门。
 */
#pragma once
#include <Prism/Account/Failure.hpp>
#include <Prism/Account/RateTypes.hpp>

#include <array>
#include <cstdint>
#include <expected>
#include <memory>

namespace Prism::Account
{
    namespace Detail
    {
        class RateLedger;
        struct RateView;

        /** @brief 一次未提交消费预约；持有各活动视图并在 Commit 或析构时归还账本门。 */
        class RateReservation final
        {
        public:
            RateReservation() = default;
            RateReservation(const RateReservation&) = delete;
            auto operator=(const RateReservation&) -> RateReservation& = delete;
            RateReservation(RateReservation&& Other) noexcept;
            ~RateReservation();
            auto Commit() noexcept -> void;
        private:
            friend class RateLedger;
            std::shared_ptr<RateLedger> Owner_;
            std::array<std::shared_ptr<RateView>, 8U> Views_;
            RateRequest Request_;
            bool Committed_{false};
        };
    }

    /** @brief policy view 不拥有 I/O；所有消费在同一 ledger 预约内线性化。 */
    class RateLimiter final
    {
    public:
        struct CreateRequest final
        {
            RatePolicy Policy;
            std::shared_ptr<Detail::RateLedger> Ledger;
            std::shared_ptr<const RateLimiter> Previous;
        };
        /** @brief 冷构造；已有账户必须传唯一 ledger，不创建第二账本。 */
        explicit RateLimiter(CreateRequest Request);
        RateLimiter(const RateLimiter&) = delete;
        auto operator=(const RateLimiter&) -> RateLimiter& = delete;
        /** @brief 热取得未记账预约；只同步使用，不跨 co_await，失败返回精确原因。 */
        [[nodiscard]] auto TryReserve(RateRequest Request) const noexcept
            -> std::expected<Detail::RateReservation, Fault::Failure>;
        /** @brief 消费实际单位；竞争 ResourceUnavailable，与达到速率限额 WouldBlock 区分。 */
        [[nodiscard]] auto TryConsume(RateRequest Request) const noexcept -> std::expected<void, Fault::Failure>;
        /** @brief 冷准备新策略视图，复用同一 ledger 和未到期使用量。 */
        [[nodiscard]] auto Reconfigure(RatePolicy Policy) const
            -> std::expected<std::shared_ptr<const RateLimiter>, Fault::Failure>;
        [[nodiscard]] auto Failure() const noexcept -> Fault::Failure;
        [[nodiscard]] auto TotalUnits() const noexcept -> std::uint64_t;
    private:
        RateLimiter(CreateRequest Request, const std::shared_ptr<Detail::RateView>& Previous);
        std::shared_ptr<Detail::RateLedger> Ledger_;
        std::shared_ptr<Detail::RateView> View_;
        Fault::Failure Failure_{};
    };
}
