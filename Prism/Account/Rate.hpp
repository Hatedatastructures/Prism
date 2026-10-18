/** @file Rate.hpp
 * @brief 冻结策略视图与唯一共享速率账本的正式前门。
 */
#pragma once
#include <Prism/Account/RateTypes.hpp>
#include <Prism/Account/Detail/RateLedger.hpp>
#include <memory>
#include <expected>

namespace Prism::Account
{
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
        explicit RateLimiter(CreateRequest Request)
            : Ledger_(std::move(Request.Ledger))
        {
            if (!Ledger_) { Ledger_ = std::make_shared<Detail::RateLedger>(WorkerShardedRatePolicy::MaxWorkerCount); }
            std::shared_ptr<Detail::RateView> Previous;
            if (Request.Previous)
            {
                if (Request.Previous->Ledger_ != Ledger_)
                {
                    Failure_ = {Fault::Code::InvalidArgument};
                    return;
                }
                Previous = Request.Previous->View_;
            }
            auto Created = Ledger_->Prepare(std::move(Request.Policy), Previous);
            if (!Created) { Failure_ = Created.error(); return; }
            View_ = std::move(*Created);
        }
        RateLimiter(const RateLimiter&) = delete;
        auto operator=(const RateLimiter&) -> RateLimiter& = delete;
        /** @brief 热取得未记账预约；只同步使用，不跨 co_await，失败返回精确原因。 */
        [[nodiscard]] auto TryReserve(RateRequest Request) const noexcept
            -> std::expected<Detail::RateReservation, Fault::Failure>
        {
            if (Failure_.Failed()) { return std::unexpected(Failure_); }
            return Ledger_->TryReserve(View_, Request);
        }
        /** @brief 消费实际单位；竞争 ResourceUnavailable，与达到速率限额 WouldBlock 区分。 */
        [[nodiscard]] auto TryConsume(RateRequest Request) const noexcept -> std::expected<void, Fault::Failure>
        {
            auto Reserved = TryReserve(Request);
            if (!Reserved) { return std::unexpected(Reserved.error()); }
            Reserved->Commit();
            return {};
        }
        /** @brief 冷准备新策略视图，复用同一 ledger 和未到期使用量。 */
        [[nodiscard]] auto Reconfigure(RatePolicy Policy) const
            -> std::expected<std::shared_ptr<const RateLimiter>, Fault::Failure>
        {
            if (!View_) { return std::unexpected(Failure_); }
            CreateRequest Request{std::move(Policy), Ledger_, {}};
            auto Created = std::shared_ptr<RateLimiter>(new RateLimiter(std::move(Request), View_));
            if (Created->Failure_.Failed()) { return std::unexpected(Created->Failure_); }
            return std::shared_ptr<const RateLimiter>(std::move(Created));
        }
        [[nodiscard]] auto Failure() const noexcept -> Fault::Failure { return Failure_; }
        [[nodiscard]] auto TotalUnits() const noexcept -> std::uint64_t { return Ledger_->TotalUnits(); }
    private:
        RateLimiter(CreateRequest Request, const std::shared_ptr<Detail::RateView>& Previous)
            : Ledger_(std::move(Request.Ledger))
        {
            auto Created = Ledger_->Prepare(std::move(Request.Policy), Previous);
            if (!Created) { Failure_ = Created.error(); return; }
            View_ = std::move(*Created);
        }
        std::shared_ptr<Detail::RateLedger> Ledger_;
        std::shared_ptr<Detail::RateView> View_;
        Fault::Failure Failure_{};
    };
}
