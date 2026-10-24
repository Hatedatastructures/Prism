/**
 * @file HttpRequestBudget.hpp
 * @brief Operations HTTP request input budget and owning lease。
 * @details 每个请求在读取头部或正文前预留完整的有界输入额度。
 */

#pragma once

#include <Prism/Operations/Http/Limits.hpp>

#include <atomic>
#include <cstddef>
#include <memory>

namespace Prism::Operations::HttpConnection
{

    /** @brief 固定总额度的请求字节预算。 */
    class RequestByteBudget final
    {
    public:
        [[nodiscard]] auto TryReserve(const std::size_t Bytes) noexcept -> bool;

        auto Release(const std::size_t Bytes) noexcept -> void;

    private:
        std::atomic<std::size_t> Used_{0U};
    };

    /** @brief 单个请求拥有的额度租约，离开作用域时归还预留字节。 */
    class RequestByteLease final
    {
    public:
        RequestByteLease() = default;
        RequestByteLease(std::shared_ptr<RequestByteBudget> BudgetValue, const std::size_t BytesValue);
        RequestByteLease(const RequestByteLease &) = delete;
        auto operator=(const RequestByteLease &) -> RequestByteLease & = delete;
        RequestByteLease(RequestByteLease &&Other) noexcept;
        auto operator=(RequestByteLease &&Other) noexcept -> RequestByteLease &;
        ~RequestByteLease() noexcept;

    private:
        auto Reset() noexcept -> void;

        std::shared_ptr<RequestByteBudget> Budget_;
        std::size_t Bytes_{0U};
    };

}
