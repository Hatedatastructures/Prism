/** @file SessionIdAllocator.cpp
 * @brief 进程内 SessionId 单调分配实现。
 */
#include <Prism/Foundation/Identifier/SessionIdAllocator.hpp>

#include <atomic>
#include <cstdint>
#include <limits>

namespace Prism::Foundation::Identifier
{
    auto ReserveSessionId() noexcept -> Prism::SessionId
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
                return Prism::SessionId{Candidate};
            }
        }
        return {};
    }
}
