/** @file AttemptDeadline.hpp @brief DNS 单次上游尝试的绝对 deadline 值。 */
#pragma once

#include <chrono>

namespace Prism::Network::Dns::Detail
{
    /**
     * @brief 单次上游尝试共享的绝对截止时刻。
     * @details 端点解析、建连、收发和 DoH 分块操作共用一个值，不在阶段边界重置预算。
     */
    class AttemptDeadline final
    {
    public:
        using Clock = std::chrono::steady_clock;

        /** @brief 从相对预算创建绝对截止时刻；非正值表示立即到期。 */
        [[nodiscard]] static auto FromBudget(std::chrono::milliseconds Budget)
            -> AttemptDeadline
        {
            return AttemptDeadline(Clock::now() + Budget);
        }

        /** @brief 返回绝对截止时刻。 */
        [[nodiscard]] auto At() const noexcept -> Clock::time_point
        {
            return At_;
        }

        /** @brief 检查预算是否已经耗尽。 */
        [[nodiscard]] auto Expired() const noexcept -> bool
        {
            return Clock::now() >= At_;
        }

    private:
        explicit AttemptDeadline(const Clock::time_point At) noexcept : At_(At) {}

        Clock::time_point At_;
    };
} // namespace Prism::Network::Dns::Detail
