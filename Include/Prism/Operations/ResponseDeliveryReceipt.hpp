/**
 * @file ResponseDeliveryReceipt.hpp
 * @brief 管理请求响应完整写出后的 typed 回执。
 * @details 创建者借 executor 生命周期拥有回执状态；同一回执可由 handler 等待、
 *          由连接 owner 在写完或失败后完成。deadline 只限制等待，不取消 socket。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <exception>
#include <expected>
#include <memory>

namespace Prism::Operations
{

    namespace Net = boost::asio;

    /**
     * @brief 某个 HTTP 响应的单次送达回执。
     * @details 所有状态只在内部 strand 上访问。写入者拥有 socket 并报告完整写入或
     *          原生失败；等待者不持有连接，超时不会伪造送达，也不改变业务结果。
     */
    class ResponseDeliveryReceipt final
    {
        struct State;

    public:
        using Outcome = std::expected<void, Prism::Fault::Failure>;
        using Completion = std::expected<bool, Prism::Fault::Failure>;
        using Deadline = std::chrono::steady_clock::time_point;

        /** @brief 在请求 connection executor 上创建一份尚未完成的响应回执。 */
        [[nodiscard]] static auto Create(Net::any_io_executor Executor)
            -> ResponseDeliveryReceipt;

        /**
         * @brief 等待连接 owner 报告完整响应写入或失败。
         * @param Limit 同一停机操作使用的绝对 deadline；超时返回 Timeout，不推断送达。
         */
        [[nodiscard]] auto WaitAsync(const Deadline Limit) const -> Net::awaitable<Outcome>;

        /**
         * @brief 连接 owner 报告一次真实写入结果。
         * @param Result 完整写入的 success，或保留原生 category/value 的写入失败。
         * @return true 表示回报被接收；重复/迟到为 false，timer 操作失败返回原生错误。
         */
        [[nodiscard]] auto CompleteAsync(Outcome Result) const -> Net::awaitable<Completion>;

    private:
        [[nodiscard]] static auto FailureFromException(const std::exception_ptr Exception) noexcept
            -> Prism::Fault::Failure;

        [[nodiscard]] static auto WaitOnStrand(
            const std::shared_ptr<State> &StateValue,
            const Deadline Limit) -> Net::awaitable<Outcome>;

        [[nodiscard]] static auto CompleteOnStrand(
            const std::shared_ptr<State> &StateValue,
            Outcome Result) -> Net::awaitable<Completion>;

        [[nodiscard]] static auto TimeoutFailure() noexcept -> Prism::Fault::Failure;
        explicit ResponseDeliveryReceipt(std::shared_ptr<State> StateValue);

        std::shared_ptr<State> State_;
    };

} // namespace Prism::Operations
