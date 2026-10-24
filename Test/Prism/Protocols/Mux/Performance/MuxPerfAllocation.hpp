#pragma once

/**
 * @file MuxPerfAllocation.hpp
 * @brief Mux 性能测试窗口内的进程分配统计覆盖。
 * @details 这些定义由普通 Mux 基准和真实 Root 矩阵共同消费；统计状态与窗口封装
 *          为 inline；全局分配替换由每个可执行文件唯一的 CPP 定义。
 */

#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <limits>
#include <new>

#ifdef _WIN32
#include <malloc.h>
#endif

namespace PrismMuxPerfAllocation
{
    inline std::atomic<bool> Active{false};
    inline std::atomic<std::size_t> OrdinaryCalls{0};
    inline std::atomic<std::size_t> OrdinaryBytes{0};
    inline std::atomic<std::size_t> AlignedCalls{0};
    inline std::atomic<std::size_t> AlignedBytes{0};

    inline auto Record(const std::size_t Size, const bool Aligned) noexcept -> void
    {
        if (!Active.load(std::memory_order_relaxed))
        {
            return;
        }
        if (Aligned)
        {
            AlignedCalls.fetch_add(1U, std::memory_order_relaxed);
            AlignedBytes.fetch_add(Size, std::memory_order_relaxed);
        }
        else
        {
            OrdinaryCalls.fetch_add(1U, std::memory_order_relaxed);
            OrdinaryBytes.fetch_add(Size, std::memory_order_relaxed);
        }
    }

    inline auto Allocate(const std::size_t Size, const std::size_t Alignment) -> void *
    {
        const auto ActualSize = Size == 0U ? 1U : Size;
        if (Alignment == 0U)
        {
            return std::malloc(ActualSize);
        }
        const auto Remainder = ActualSize % Alignment;
        if (ActualSize > (std::numeric_limits<std::size_t>::max)() -
                             (Remainder == 0U ? 0U : Alignment - Remainder))
        {
            return nullptr;
        }
#ifdef _WIN32
        return ::_aligned_malloc(ActualSize, Alignment);
#else
        return std::aligned_alloc(Alignment, ActualSize +
                                                 (Remainder == 0U ? 0U : Alignment - Remainder));
#endif
    }

    inline auto FreeAligned(void *Value) noexcept -> void
    {
#ifdef _WIN32
        ::_aligned_free(Value);
#else
        std::free(Value);
#endif
    }

    struct Scope final
    {
        Scope() noexcept
        {
            OrdinaryCalls.store(0U, std::memory_order_relaxed);
            OrdinaryBytes.store(0U, std::memory_order_relaxed);
            AlignedCalls.store(0U, std::memory_order_relaxed);
            AlignedBytes.store(0U, std::memory_order_relaxed);
            Active.store(true, std::memory_order_release);
        }

        ~Scope()
        {
            Active.store(false, std::memory_order_release);
        }
    };
}

