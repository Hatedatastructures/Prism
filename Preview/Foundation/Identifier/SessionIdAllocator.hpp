/**
 * @file SessionIdAllocator.hpp
 * @brief 应用进程内共享的 SessionId 单调分配器。
 * @details TCP listener 与 Boundary QUIC connection 共用一条分配序列，
 *          避免不同入口生成重复的统计 Session scope；耗尽后返回空 ID。
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <limits>

#include <Preview/Foundation/Identifier/Id.hpp>

namespace Preview::Foundation::Identifier
{

    /** @brief 预留不复用的进程级 SessionId；耗尽时返回空 ID。 */
    [[nodiscard]] inline auto ReserveSessionId() noexcept -> Preview::SessionId
    {
        static std::atomic<std::uint64_t> Next{1};
        auto Candidate = Next.load(std::memory_order_relaxed);
        while (Candidate != 0U)
        {
            auto Following = std::uint64_t{0};
            if (Candidate != std::numeric_limits<std::uint64_t>::max())
            {
                Following = Candidate + 1U;
            }
            if (Next.compare_exchange_weak(Candidate, Following,
                                           std::memory_order_relaxed,
                                           std::memory_order_relaxed))
            {
                return Preview::SessionId{Candidate};
            }
        }
        return {};
    }

} // namespace Preview::Foundation::Identifier