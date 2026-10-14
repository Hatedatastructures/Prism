/**
 * @file ConfigurationValidationCompareAllocation.hpp
 * @brief 配置校验对照工具的进程级分配统计所有者。
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <atomic>

namespace Preview::Application::Configuration::Perf::Allocation
{

    struct Stats final
    {
        std::uint64_t Count{0};
        std::uint64_t Bytes{0};
        std::uint64_t AlignedCount{0};
        std::uint64_t AlignedBytes{0};
    };

    inline std::atomic<bool> Tracking{false};
    inline std::atomic<std::uint64_t> AllocationCount{0};
    inline std::atomic<std::uint64_t> AllocationBytes{0};
    inline std::atomic<std::uint64_t> AlignedAllocationCount{0};
    inline std::atomic<std::uint64_t> AlignedAllocationBytes{0};

    inline auto Reset() noexcept -> void
    {
        AllocationCount.store(0, std::memory_order_relaxed);
        AllocationBytes.store(0, std::memory_order_relaxed);
        AlignedAllocationCount.store(0, std::memory_order_relaxed);
        AlignedAllocationBytes.store(0, std::memory_order_relaxed);
    }

    inline auto Read() noexcept -> Stats
    {
        return Stats{
            AllocationCount.load(std::memory_order_relaxed),
            AllocationBytes.load(std::memory_order_relaxed),
            AlignedAllocationCount.load(std::memory_order_relaxed),
            AlignedAllocationBytes.load(std::memory_order_relaxed)};
    }

    class Window final
    {
    public:
        Window()
        {
            Reset();
            Tracking.store(true, std::memory_order_release);
        }

        Window(const Window &) = delete;
        auto operator=(const Window &) -> Window & = delete;
        ~Window()
        {
            Tracking.store(false, std::memory_order_release);
        }

        auto Stop() -> Stats
        {
            Tracking.store(false, std::memory_order_release);
            return Read();
        }
    };

} // namespace Preview::Application::Configuration::Perf::Allocation
