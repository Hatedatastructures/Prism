/**
 * @file counter.hpp
 * @brief 缓存行对齐原子计数器原语
 * @details 提供零分配、无锁的原子计数器，每个实例独占 64 字节
 * 缓存行，防止 false sharing。所有操作使用 memory_order_relaxed。
 */
#pragma once

#include <atomic>
#include <cstdint>


namespace psm::stats
{

    /**
     * @class alignas(64) counter
     * @brief 独占缓存行的原子计数器
     * @details 适用于高并发递增场景（如流量统计、连接计数）。
     * increment/decrement 是单条 fetch_add/fetch_sub 指令，
     * 开销约 1ns（同核）到 6ns（跨核）。
     */
    class alignas(64) counter final
    {
    public:
        /**
         * @brief 构造函数
         * @details 初始化计数器为零值。对齐到 64 字节缓存行边界。
         */
        explicit counter() = default;

        /**
         * @brief 原子递增
         * @param n 递增量，默认为 1
         */
        void increment(std::uint64_t n = 1) noexcept
        {
            value_.fetch_add(n, std::memory_order_relaxed);
        }

        /**
         * @brief 原子递减
         * @param n 递减量，默认为 1
         */
        void decrement(std::uint64_t n = 1) noexcept
        {
            value_.fetch_sub(n, std::memory_order_relaxed);
        }

        /**
         * @brief 原子读取当前值
         * @return 当前计数值
         */
        [[nodiscard]] auto load() const noexcept
            -> std::uint64_t
        {
            return value_.load(std::memory_order_relaxed);
        }

        /**
         * @brief 原子交换并返回旧值
         * @param desired 要设置的新值
         * @return 交换前的旧值
         */
        [[nodiscard]] auto exchange(std::uint64_t desired) noexcept
            -> std::uint64_t
        {
            return value_.exchange(desired, std::memory_order_relaxed);
        }

    private:
        std::atomic<std::uint64_t> value_{0};
    };
} // namespace psm::stats
