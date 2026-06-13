/**
 * @file memory.hpp
 * @brief 内存分配统计追踪器
 * @details 提供全局 PMR 池的分配统计监控，跟踪总分配字节、
 * 当前活跃字节和分配次数。所有计数器使用 std::atomic 保证
 * 线程安全，memory_order_relaxed 保证高性能。
 */
#pragma once

#include <prism/account/stats/snapshot.hpp>

#include <atomic>
#include <cstdint>


namespace psm::stats
{

    /**
     * @class alignas(64) memory_tracker
     * @brief 全局内存分配统计追踪器
     * @details 通过 instrumented memory resource 包装全局 PMR 池，
     * 在每次分配/释放时更新原子计数器。适用于监控面板和
     * 日志输出，开销约 2-3ns/次操作。
     * @note 所有操作均为原子操作，线程安全
     */
    class alignas(64) memory_tracker final
    {
    public:
        /**
         * @brief 获取全局单例
         * @return memory_tracker 引用
         */
        [[nodiscard]] static auto instance()
            -> memory_tracker &
        {
            static memory_tracker inst;
            return inst;
        }

        /**
         * @brief 记录一次内存分配
         * @param bytes 分配的字节数
         * @details 在 instrumented memory resource 的 do_allocate() 中调用
         */
        void on_allocate(std::uint64_t bytes) noexcept
        {
            total_allocated_.fetch_add(bytes, std::memory_order_relaxed);
            current_usage_.fetch_add(bytes, std::memory_order_relaxed);
            allocation_count_.fetch_add(1, std::memory_order_relaxed);
        }

        /**
         * @brief 记录一次内存释放
         * @param bytes 释放的字节数
         * @details 在 instrumented memory resource 的 do_deallocate() 中调用
         */
        void on_deallocate(std::uint64_t bytes) noexcept
        {
            total_deallocated_.fetch_add(bytes, std::memory_order_relaxed);
            current_usage_.fetch_sub(bytes, std::memory_order_relaxed);
        }

        /**
         * @brief 获取内存统计快照
         * @return 包含分配/释放/活跃/次数的快照
         * @note 快照为松散一致，不保证跨字段的原子性
         */
        [[nodiscard]] auto snapshot() const noexcept
            -> memory_snapshot
        {
            return memory_snapshot{
                .total_allocated = total_allocated_.load(std::memory_order_relaxed),
                .total_deallocated = total_deallocated_.load(std::memory_order_relaxed),
                .current_usage = current_usage_.load(std::memory_order_relaxed),
                .allocation_count = allocation_count_.load(std::memory_order_relaxed)
            };
        }

        /**
         * @brief 读取累计分配字节
         * @return 累计分配字节数
         */
        [[nodiscard]] auto total_allocated() const noexcept
            -> std::uint64_t
        {
            return total_allocated_.load(std::memory_order_relaxed);
        }

        /**
         * @brief 读取当前活跃字节
         * @return 当前活跃字节数
         */
        [[nodiscard]] auto current_usage() const noexcept
            -> std::uint64_t
        {
            return current_usage_.load(std::memory_order_relaxed);
        }

        /**
         * @brief 读取分配次数
         * @return 累计分配次数
         */
        [[nodiscard]] auto allocation_count() const noexcept
            -> std::uint64_t
        {
            return allocation_count_.load(std::memory_order_relaxed);
        }

    private:
        std::atomic<std::uint64_t> total_allocated_{0};      ///< 累计分配字节
        std::atomic<std::uint64_t> total_deallocated_{0};     ///< 累计释放字节
        std::atomic<std::uint64_t> current_usage_{0};         ///< 当前活跃字节
        std::atomic<std::uint64_t> allocation_count_{0};      ///< 分配次数
    };
} // namespace psm::stats
