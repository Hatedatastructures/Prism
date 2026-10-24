/** @file Rate.cpp
 * @brief 账户速率策略入口实现。
 */
#include <Prism/Account/Rate.hpp>
#include <Prism/Account/Detail/RateLedger.hpp>
#include <Prism/Account/RateTypes.hpp>

#include <cstdint>
#include <expected>
#include <limits>
#include <memory>
#include <utility>

namespace Prism::Account
{
    auto WorkerShardedRatePolicy::PerWorkerLimit() const noexcept -> std::uint64_t
    {
        if (WorkerCount == 0U || GlobalLimitPerWindow == 0U) { return 0U; }
        return GlobalLimitPerWindow / WorkerCount +
            static_cast<std::uint64_t>(GlobalLimitPerWindow % WorkerCount != 0U);
    }

    auto WorkerShardedRatePolicy::MaxOvershoot() const noexcept -> std::uint64_t
    {
        const auto Limit = PerWorkerLimit();
        if (Limit == 0U || WorkerCount == 0U) { return 0U; }
        if (Limit > std::numeric_limits<std::uint64_t>::max() / WorkerCount) { return UINT64_MAX; }
        return Limit * WorkerCount - GlobalLimitPerWindow;
    }

    RateLimiter::RateLimiter(CreateRequest Request)
        : Ledger_(std::move(Request.Ledger))
    {
        if (!Ledger_)
        {
            Ledger_ = std::make_shared<Detail::RateLedger>(WorkerShardedRatePolicy::MaxWorkerCount);
        }
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

    RateLimiter::RateLimiter(CreateRequest Request,
        const std::shared_ptr<Detail::RateView>& Previous)
        : Ledger_(std::move(Request.Ledger))
    {
        auto Created = Ledger_->Prepare(std::move(Request.Policy), Previous);
        if (!Created) { Failure_ = Created.error(); return; }
        View_ = std::move(*Created);
    }

    auto RateLimiter::TryReserve(const RateRequest Request) const noexcept
        -> std::expected<Detail::RateReservation, Fault::Failure>
    {
        if (Failure_.Failed()) { return std::unexpected(Failure_); }
        return Ledger_->TryReserve(View_, Request);
    }

    auto RateLimiter::TryConsume(const RateRequest Request) const noexcept
        -> std::expected<void, Fault::Failure>
    {
        auto Reserved = TryReserve(Request);
        if (!Reserved) { return std::unexpected(Reserved.error()); }
        Reserved->Commit();
        return {};
    }

    auto RateLimiter::Reconfigure(RatePolicy Policy) const
        -> std::expected<std::shared_ptr<const RateLimiter>, Fault::Failure>
    {
        if (!View_) { return std::unexpected(Failure_); }
        CreateRequest Request{std::move(Policy), Ledger_, {}};
        auto Created = std::shared_ptr<RateLimiter>(new RateLimiter(std::move(Request), View_));
        if (Created->Failure_.Failed()) { return std::unexpected(Created->Failure_); }
        return std::shared_ptr<const RateLimiter>(std::move(Created));
    }

    auto RateLimiter::TotalUnits() const noexcept -> std::uint64_t
    {
        return Ledger_->TotalUnits();
    }

    auto RateLimiter::Failure() const noexcept -> Fault::Failure
    {
        return Failure_;
    }
}
