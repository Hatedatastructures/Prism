/** @file BandwidthBucket.hpp
 * @brief 跨 Worker 账户方向令牌桶；有限零速率等待策略变化，不重置更新时的剩余令牌。
 */
#pragma once
#include <Prism/Account/Failure.hpp>
#include <Prism/Contract/Account/PayloadBudget.hpp>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <optional>

namespace Prism::Account::Detail
{
    struct BandwidthDecision final
    {
        std::uint64_t Bytes{0};
        std::chrono::milliseconds Wait{0};
    };

    /** @brief 同步非阻塞操作，竞争返回 Busy；等待归调用协程，不在 gate 内挂起。 */
    class BandwidthBucket final
    {
    public:
        [[nodiscard]] auto TryTake(const std::optional<std::uint64_t> Limit,
            const Contract::PayloadRequest& Request) noexcept
            -> std::expected<BandwidthDecision, Fault::Failure>
        {
            if (Gate_.test_and_set(std::memory_order_acquire))
                return std::unexpected(MakeFailure(FailureReason::Busy));
            struct Release final
            {
                std::atomic_flag& Gate;
                ~Release() { Gate.clear(std::memory_order_release); }
            } Guard{Gate_};
            const auto Now = std::chrono::steady_clock::now();
            Refill(Now);
            if (Limit != Limit_ || !Initialized_)
            {
                const auto Capacity = static_cast<long double>((std::max)(Limit.value_or(0), std::uint64_t{65535}));
                if (!Initialized_) Tokens_ = Capacity;
                else Tokens_ = (std::min)(Tokens_, Capacity);
                Limit_ = Limit;
                Initialized_ = true;
            }
            if (!Limit) return BandwidthDecision{Request.Bytes, std::chrono::milliseconds{0}};
            if (*Limit == 0) return BandwidthDecision{0, std::chrono::milliseconds{1000}};
            const auto Available = static_cast<std::uint64_t>((std::min)(Tokens_,
                static_cast<long double>(Request.Bytes)));
            if (Available != 0 && (!Request.Datagram || Available == Request.Bytes))
            {
                Tokens_ -= static_cast<long double>(Available);
                return BandwidthDecision{Available, std::chrono::milliseconds{0}};
            }
            auto Needed = static_cast<long double>(Request.Datagram ? Request.Bytes : 1U) - Tokens_;
            const auto Milliseconds = std::ceil(Needed * 1000.0L / static_cast<long double>(*Limit));
            return BandwidthDecision{0, std::chrono::milliseconds{
                static_cast<std::int64_t>((std::clamp)(Milliseconds, 1.0L, 1000.0L))}};
        }

        /** @brief 未成功写出的方向信用归还到同一桶；上限不允许跨失败制造额外突发。 */
        auto Refund(const std::uint64_t Bytes) noexcept -> void
        {
            if (Bytes == 0 || Gate_.test_and_set(std::memory_order_acquire)) return;
            if (Limit_) Tokens_ = (std::min)(Tokens_ + static_cast<long double>(Bytes),
                static_cast<long double>((std::max)(*Limit_, std::uint64_t{65535})));
            Gate_.clear(std::memory_order_release);
        }
    private:
        auto Refill(const std::chrono::steady_clock::time_point Now) noexcept -> void
        {
            if (Initialized_ && Limit_)
            {
                const auto Elapsed = std::chrono::duration<long double>(Now - Updated_).count();
                const auto Capacity = static_cast<long double>((std::max)(*Limit_, std::uint64_t{65535}));
                Tokens_ = (std::min)(Capacity, Tokens_ + Elapsed * static_cast<long double>(*Limit_));
            }
            Updated_ = Now;
        }
        std::atomic_flag Gate_ = ATOMIC_FLAG_INIT;
        std::optional<std::uint64_t> Limit_;
        long double Tokens_{0};
        std::chrono::steady_clock::time_point Updated_{};
        bool Initialized_{false};
    };
}
