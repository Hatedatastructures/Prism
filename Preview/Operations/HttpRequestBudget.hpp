/**
 * @file HttpRequestBudget.hpp
 * @brief Operations HTTP request input budget and owning lease。
 * @details 每个请求在读取头部或正文前预留完整的有界输入额度。
 */

#pragma once

#include <Preview/Operations/Http/Limits.hpp>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <memory>
#include <utility>

namespace Preview::Operations::HttpConnection
{

    /** @brief 固定总额度的请求字节预算。 */
    class RequestByteBudget final
    {
    public:
        [[nodiscard]] auto TryReserve(const std::size_t Bytes) noexcept -> bool
        {
            auto Used = Used_.load(std::memory_order_acquire);
            while (Bytes <= MaxInFlightRequestBytes - std::min(Used, MaxInFlightRequestBytes))
            {
                if (Used_.compare_exchange_weak(Used, Used + Bytes,
                        std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    return true;
                }
            }
            return false;
        }

        auto Release(const std::size_t Bytes) noexcept -> void
        {
            Used_.fetch_sub(Bytes, std::memory_order_acq_rel);
        }

    private:
        std::atomic<std::size_t> Used_{0U};
    };

    /** @brief 单个请求拥有的额度租约，离开作用域时归还预留字节。 */
    class RequestByteLease final
    {
    public:
        RequestByteLease() = default;
        RequestByteLease(std::shared_ptr<RequestByteBudget> BudgetValue, const std::size_t BytesValue)
            : Budget_(std::move(BudgetValue)), Bytes_(BytesValue)
        {
        }
        RequestByteLease(const RequestByteLease &) = delete;
        auto operator=(const RequestByteLease &) -> RequestByteLease & = delete;
        RequestByteLease(RequestByteLease &&Other) noexcept
            : Budget_(std::move(Other.Budget_)), Bytes_(std::exchange(Other.Bytes_, 0U))
        {
        }
        auto operator=(RequestByteLease &&Other) noexcept -> RequestByteLease &
        {
            if (this != &Other)
            {
                Reset();
                Budget_ = std::move(Other.Budget_);
                Bytes_ = std::exchange(Other.Bytes_, 0U);
            }
            return *this;
        }
        ~RequestByteLease() noexcept { Reset(); }

    private:
        auto Reset() noexcept -> void
        {
            if (Budget_ && Bytes_ != 0U)
            {
                Budget_->Release(Bytes_);
                Bytes_ = 0U;
            }
        }

        std::shared_ptr<RequestByteBudget> Budget_;
        std::size_t Bytes_{0U};
    };

}
