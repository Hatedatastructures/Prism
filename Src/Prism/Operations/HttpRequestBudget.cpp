/** @file HttpRequestBudget.cpp @brief HTTP 请求字节预算与租约实现。 */
#include <Prism/Operations/HttpRequestBudget.hpp>

#include <algorithm>
#include <utility>

namespace Prism::Operations::HttpConnection
{
    auto RequestByteBudget::TryReserve(const std::size_t Bytes) noexcept -> bool
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

    auto RequestByteBudget::Release(const std::size_t Bytes) noexcept -> void
    {
        Used_.fetch_sub(Bytes, std::memory_order_acq_rel);
    }

    RequestByteLease::RequestByteLease(
        std::shared_ptr<RequestByteBudget> BudgetValue,
        const std::size_t BytesValue)
        : Budget_(std::move(BudgetValue)), Bytes_(BytesValue)
    {
    }

    RequestByteLease::RequestByteLease(RequestByteLease &&Other) noexcept
        : Budget_(std::move(Other.Budget_)), Bytes_(std::exchange(Other.Bytes_, 0U))
    {
    }

    auto RequestByteLease::operator=(RequestByteLease &&Other) noexcept -> RequestByteLease &
    {
        if (this != &Other)
        {
            Reset();
            Budget_ = std::move(Other.Budget_);
            Bytes_ = std::exchange(Other.Bytes_, 0U);
        }
        return *this;
    }

    RequestByteLease::~RequestByteLease() noexcept
    {
        Reset();
    }

    auto RequestByteLease::Reset() noexcept -> void
    {
        if (Budget_ && Bytes_ != 0U)
        {
            Budget_->Release(Bytes_);
            Bytes_ = 0U;
        }
    }
}
