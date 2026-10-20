/** @file TransferSequence.hpp
 * @brief 为账户持久预约生成不回绕的进程内请求序号。
 */
#pragma once

#include <atomic>
#include <cstdint>
#include <limits>
#include <optional>

namespace Prism::Account::Detail
{
    /** @brief 序号到达最大值后持续拒绝，不产生可重复请求键。 */
    [[nodiscard]] inline auto TryTakeRequestSequence(std::atomic<std::uint64_t>& Sequence) noexcept
        -> std::optional<std::uint64_t>
    {
        auto Candidate = Sequence.load(std::memory_order_relaxed);
        while (Candidate != std::numeric_limits<std::uint64_t>::max())
        {
            if (Sequence.compare_exchange_weak(Candidate, Candidate + 1U,
                std::memory_order_relaxed, std::memory_order_relaxed))
            {
                return Candidate;
            }
        }
        return std::nullopt;
    }
}
