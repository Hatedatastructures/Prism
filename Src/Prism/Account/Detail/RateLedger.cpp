/** @file RateLedger.cpp
 * @brief 账户速率账本的策略视图与预约实现。
 */
#include <Prism/Account/Detail/RateLedger.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <utility>
#include <variant>

namespace Prism::Account::Detail
{
        RateView::RateView(RatePolicy Value, const std::uint32_t Count) : Policy(std::move(Value)), Workers(Count) {}

        RateLedger::RateLedger(const std::uint32_t WorkerCount) : WorkerCount_(WorkerCount) {}

        auto RateLedger::Prepare(RatePolicy Policy, const std::shared_ptr<RateView>& Previous)
            -> std::expected<std::shared_ptr<RateView>, Failure>
        {
            if (WorkerCount_ == 0U || WorkerCount_ > WorkerShardedRatePolicy::MaxWorkerCount)
            { return std::unexpected(Failure{Code::InvalidArgument}); }
            auto Result = std::make_shared<RateView>(std::move(Policy), WorkerCount_);
            const auto Valid = Configure(*Result);
            if (Valid.Failed()) { return std::unexpected(Valid); }
            if (Gate_.test_and_set(std::memory_order_acquire)) { return std::unexpected(MakeFailure(FailureReason::Busy)); }
            struct Release final
            {
                RateLedger& Owner;
                ~Release() { Owner.Release(); }
            } Guard{*this};
            std::size_t Slot = Views_.size();
            for (std::size_t Index = 0U; Index < Views_.size(); ++Index)
            {
                if (Views_[Index].expired()) { Slot = Index; break; }
            }
            if (Slot == Views_.size()) { return std::unexpected(MakeFailure(FailureReason::PolicyViews)); }
            const auto Window = LastNow_ / Result->WindowMilliseconds;
            Result->Global.Window = Window;
            for (auto& Bucket : Result->Workers) { Bucket.Window = Window; }
            if (Previous)
            {
                if (LastNow_ / Previous->WindowMilliseconds == Previous->Global.Window)
                {
                    Result->Global.Used = Previous->Global.Used;
                }
                for (std::size_t Index = 0U; Index < Result->Workers.size(); ++Index)
                {
                    if (LastNow_ / Previous->WindowMilliseconds == Previous->Workers[Index].Window)
                    {
                        Result->Workers[Index].Used = Previous->Workers[Index].Used;
                    }
                }
            }
            else
            {
                for (const auto& WeakView : Views_)
                {
                    const auto ExistingView = WeakView.lock();
                    if (!ExistingView) { continue; }
                    const auto CurrentWindow = LastNow_ / ExistingView->WindowMilliseconds;
                    if (CurrentWindow == ExistingView->Global.Window &&
                        ExistingView->Global.Used > Result->Global.Used)
                    { Result->Global.Used = ExistingView->Global.Used; }
                    for (std::size_t Index = 0U; Index < Result->Workers.size(); ++Index)
                    {
                        const auto& ExistingBucket = ExistingView->Workers[Index];
                        if (CurrentWindow == ExistingBucket.Window && ExistingBucket.Used > Result->Workers[Index].Used)
                        { Result->Workers[Index].Used = ExistingBucket.Used; }
                    }
                }
            }
            Views_[Slot] = Result;
            return Result;
        }

        auto RateLedger::TryReserve(const std::shared_ptr<RateView>& View, RateRequest Request) noexcept
            -> std::expected<RateReservation, Failure>
        {
            if (!View || Request.WorkerId >= WorkerCount_) { return std::unexpected(Failure{Code::InvalidArgument}); }
            if (View->WorkerSharded && Request.WorkerId >= View->WorkerCount)
            { return std::unexpected(Failure{Code::InvalidArgument}); }
            auto Self = weak_from_this().lock();
            if (!Self) { return std::unexpected(Failure{Code::InvalidArgument}); }
            if (Gate_.test_and_set(std::memory_order_acquire)) { return std::unexpected(MakeFailure(FailureReason::Busy)); }
            RateReservation Result;
            Result.Owner_ = std::move(Self);
            if (Request.Now == 0U)
            {
                if (View->Limit != 0U) { return std::unexpected(Failure{Code::InvalidArgument}); }
                Request.Now = LastNow_;
                if (Request.Now == 0U) { Request.Now = 1U; }
            }
            if (Request.Now < LastNow_) { return std::unexpected(Failure{Code::InvalidArgument}); }
            LastNow_ = Request.Now;
            Result.Request_ = Request;
            for (std::size_t Index = 0U; Index < Views_.size(); ++Index)
            {
                auto Current = Views_[Index].lock();
                if (!Current) { continue; }
                const auto Window = Request.Now / Current->WindowMilliseconds;
                Advance(Current->Global, Window);
                Advance(Current->Workers[Request.WorkerId], Window);
                if (Current->Global.Used > UINT64_MAX - Request.Units ||
                    Current->Workers[Request.WorkerId].Used > UINT64_MAX - Request.Units)
                {
                    return std::unexpected(Failure{Code::ResourceUnavailable});
                }
                Result.Views_[Index] = std::move(Current);
            }
            auto Used = View->Global.Used;
            if (View->WorkerSharded)
            {
                if (Request.WorkerId >= View->WorkerCount) { return std::unexpected(Failure{Code::InvalidArgument}); }
                Used = View->Workers[Request.WorkerId].Used;
            }
            if (!std::holds_alternative<UnlimitedRatePolicy>(View->Policy) &&
                (Used > View->Limit || Request.Units > View->Limit - Used))
            {
                return std::unexpected(MakeFailure(FailureReason::RateLimited));
            }
            if (TotalUnits_.load(std::memory_order_relaxed) > UINT64_MAX - Request.Units)
            {
                return std::unexpected(Failure{Code::ResourceUnavailable});
            }
            return Result;
        }

        auto RateLedger::TotalUnits() const noexcept -> std::uint64_t { return TotalUnits_.load(std::memory_order_relaxed); }

        auto RateLedger::WorkerCount() const noexcept -> std::uint32_t { return WorkerCount_; }

        auto RateLedger::Advance(RateBucket& Bucket, const std::uint64_t Window) noexcept -> void
        {
            if (Window > Bucket.Window) { Bucket.Window = Window; Bucket.Used = 0U; }
        }

        auto RateLedger::Configure(RateView& View) const noexcept -> Failure
        {
            if (WorkerCount_ == 0U || WorkerCount_ > WorkerShardedRatePolicy::MaxWorkerCount)
            {
                return {Code::InvalidArgument};
            }
            if (const auto* Strict = std::get_if<StrictGlobalRatePolicy>(&View.Policy))
            {
                View.WindowMilliseconds = Strict->WindowMilliseconds;
                View.Limit = Strict->LimitPerWindow;
            }
            else if (const auto* Worker = std::get_if<WorkerShardedRatePolicy>(&View.Policy))
            {
                if (Worker->WorkerCount == 0U || Worker->WorkerCount > WorkerCount_ ||
                    Worker->WorkerCount > WorkerShardedRatePolicy::MaxWorkerCount) { return {Code::InvalidArgument}; }
                View.WorkerSharded = true;
                View.WorkerCount = Worker->WorkerCount;
                View.WindowMilliseconds = Worker->WindowMilliseconds;
                View.Limit = Worker->PerWorkerLimit();
            }
            if (View.WindowMilliseconds == 0U || View.Limit > UINT32_MAX) { return {Code::InvalidArgument}; }
            return {};
        }

        auto RateLedger::Release() noexcept -> void { Gate_.clear(std::memory_order_release); Gate_.notify_all(); }

    RateReservation::RateReservation(RateReservation&& Other) noexcept
        : Owner_(std::move(Other.Owner_)), Views_(std::move(Other.Views_)), Request_(Other.Request_),
          Committed_(Other.Committed_) {}

    RateReservation::~RateReservation() { if (Owner_) { Owner_->Release(); } }

    auto RateReservation::Commit() noexcept -> void
    {
        if (!Owner_ || Committed_) { return; }
        for (const auto& View : Views_)
        {
            if (View) { View->Global.Used += Request_.Units; View->Workers[Request_.WorkerId].Used += Request_.Units; }
        }
        Owner_->TotalUnits_.fetch_add(Request_.Units, std::memory_order_relaxed);
        Committed_ = true;
    }
}
