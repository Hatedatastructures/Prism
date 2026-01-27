#pragma once

#include <memory_resource>
#include <atomic>
#include <cstddef>

namespace ngx::stress
{
    /**
     * @brief 计数内存资源
     *
     * 用于统计内存分配和释放的次数以及字节数。
     * 该类继承自 `std::pmr::memory_resource`，作为一个装饰器，
     * 将实际的分配请求转发给上游资源，并记录统计信息。
     */
    class counting_resource final : public std::pmr::memory_resource
    {
    public:
        /**
         * @brief 构造函数
         *
         * @param upstream 上游内存资源指针。如果为 nullptr，则使用默认内存资源。
         */
        explicit counting_resource(std::pmr::memory_resource *upstream) noexcept
            : upstream_(upstream ? upstream : std::pmr::get_default_resource())
        {
        }

        /**
         * @brief 重置所有计数器
         */
        void reset() noexcept
        {
            alloc_calls_.store(0, std::memory_order_relaxed);
            dealloc_calls_.store(0, std::memory_order_relaxed);
            bytes_allocated_.store(0, std::memory_order_relaxed);
            bytes_deallocated_.store(0, std::memory_order_relaxed);
            bytes_in_use_.store(0, std::memory_order_relaxed);
            peak_bytes_in_use_.store(0, std::memory_order_relaxed);
        }

        /**
         * @brief 获取分配调用次数
         * @return std::uint64_t 分配次数
         */
        [[nodiscard]] std::uint64_t alloc_calls() const noexcept { return alloc_calls_.load(std::memory_order_relaxed); }

        /**
         * @brief 获取释放调用次数
         * @return std::uint64_t 释放次数
         */
        [[nodiscard]] std::uint64_t dealloc_calls() const noexcept { return dealloc_calls_.load(std::memory_order_relaxed); }

        /**
         * @brief 获取总分配字节数
         * @return std::uint64_t 总分配字节数
         */
        [[nodiscard]] std::uint64_t bytes_allocated() const noexcept { return bytes_allocated_.load(std::memory_order_relaxed); }

        /**
         * @brief 获取总释放字节数
         * @return std::uint64_t 总释放字节数
         */
        [[nodiscard]] std::uint64_t bytes_deallocated() const noexcept { return bytes_deallocated_.load(std::memory_order_relaxed); }

        /**
         * @brief 获取当前正在使用的字节数
         * @return std::uint64_t 当前使用字节数
         */
        [[nodiscard]] std::uint64_t bytes_in_use() const noexcept { return bytes_in_use_.load(std::memory_order_relaxed); }

        /**
         * @brief 获取峰值使用字节数
         * @return std::uint64_t 峰值使用字节数
         */
        [[nodiscard]] std::uint64_t peak_bytes_in_use() const noexcept { return peak_bytes_in_use_.load(std::memory_order_relaxed); }

        /**
         * @brief 获取上游内存资源
         * @return std::pmr::memory_resource* 上游内存资源指针
         */
        [[nodiscard]] std::pmr::memory_resource *upstream() const noexcept { return upstream_; }

    private:
        /**
         * @brief 执行分配
         *
         * @param bytes 分配字节数
         * @param alignment 对齐要求
         * @return void* 分配的内存指针
         */
        void *do_allocate(std::size_t bytes, std::size_t alignment) override
        {
            alloc_calls_.fetch_add(1, std::memory_order_relaxed);
            bytes_allocated_.fetch_add(bytes, std::memory_order_relaxed);

            const auto in_use = bytes_in_use_.fetch_add(bytes, std::memory_order_relaxed) + bytes;
            auto peak = peak_bytes_in_use_.load(std::memory_order_relaxed);
            while (in_use > peak && !peak_bytes_in_use_.compare_exchange_weak(peak, in_use, std::memory_order_relaxed))
            {
            }

            return upstream_->allocate(bytes, alignment);
        }

        /**
         * @brief 执行释放
         *
         * @param p 内存指针
         * @param bytes 释放字节数
         * @param alignment 对齐要求
         */
        void do_deallocate(void *p, std::size_t bytes, std::size_t alignment) override
        {
            dealloc_calls_.fetch_add(1, std::memory_order_relaxed);
            bytes_deallocated_.fetch_add(bytes, std::memory_order_relaxed);
            bytes_in_use_.fetch_sub(bytes, std::memory_order_relaxed);
            upstream_->deallocate(p, bytes, alignment);
        }

        /**
         * @brief 比较是否相等
         *
         * @param other 另一个内存资源
         * @return true 相等
         * @return false 不相等
         */
        bool do_is_equal(const std::pmr::memory_resource &other) const noexcept override
        {
            return this == &other;
        }

        std::pmr::memory_resource *upstream_;
        std::atomic<std::uint64_t> alloc_calls_{0};
        std::atomic<std::uint64_t> dealloc_calls_{0};
        std::atomic<std::uint64_t> bytes_allocated_{0};
        std::atomic<std::uint64_t> bytes_deallocated_{0};
        std::atomic<std::uint64_t> bytes_in_use_{0};
        std::atomic<std::uint64_t> peak_bytes_in_use_{0};
    };
}

