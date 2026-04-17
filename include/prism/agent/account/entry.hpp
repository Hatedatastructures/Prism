/**
 * @file entry.hpp
 * @brief 账户条目状态与租约管理
 * @details 定义账户状态结构和租约 RAII 封装，用于跟踪
 * 单个账户的连接数、上下行流量等运行时指标。租约对象
 * 通过引用计数自动管理活跃连接数，确保连接释放时正确
 * 递减计数器。
 */

#pragma once

#include <atomic>
#include <memory>
#include <cstdint>

namespace psm::agent::account
{
    /**
     * @struct entry
     * @brief 账户运行时状态
     * @details 存储单个账户的连接限制和实时统计信息，
     * 所有统计字段使用原子操作保证线程安全。该结构体
     * 由 directory 统一管理生命周期，通过 shared_ptr
     * 在多连接间共享。
     * @note max_connections 为 0 表示不限制连接数
     * @warning 原子字段的内存序为 relaxed，仅适用于
     * 近似统计场景
     */
    struct entry
    {
        std::uint32_t max_connections{0};           // 最大连接数
        std::atomic_uint64_t uplink_bytes{0};       // 上行流量
        std::atomic_uint64_t downlink_bytes{0};     // 下行流量
        std::atomic_uint32_t active_connections{0}; // 活跃连接数
    }; // struct entry

    /**
     * @class lease
     * @brief 账户连接租约
     * @details RAII 封装，持有 entry 的共享所有权并在
     * 构造时递增活跃连接数，析构时自动递减。用于确保
     * 连接异常退出时不会泄漏连接计数。租约不可拷贝，
     * 仅支持移动语义。
     * @note 调用方需确保在构造租约前已递增活跃连接数
     * @warning 移动后的源租约不再有效，访问其方法行为未定义
     */
    class lease
    {
    public:
        lease() = default;

        /**
         * @brief 从账户条目构造租约
         * @details 接管账户状态指针的所有权，不自动递增连接数。
         * @param state 账户状态指针，调用方需确保已在
         * 构造前递增活跃连接数
         */
        explicit lease(std::shared_ptr<entry> state) noexcept
            : state_(std::move(state))
        {
        }

        /**
         * @brief 移动构造租约
         * @details 转移源租约的所有权，移动后源对象为空。
         * @param other 源租约对象，移动后置空
         */
        lease(lease &&other) noexcept
            : state_(std::move(other.state_))
        {
        }

        /**
         * @brief 移动赋值租约
         * @details 先释放当前持有的租约，再转移源租约所有权。
         * @param other 源租约对象
         * @return 当前租约引用
         * @note 赋值前会释放当前持有的租约
         */
        auto operator=(lease &&other) noexcept -> lease &
        {
            if (this == &other)
            {
                return *this;
            }

            release();
            state_ = std::move(other.state_);
            return *this;
        }

        lease(const lease &) = delete;
        auto operator=(const lease &) -> lease & = delete;

        /**
         * @brief 析构租约并释放连接计数
         * @details 调用 release() 递减活跃连接数并释放状态指针。
         */
        ~lease()
        {
            release();
        }

        /**
         * @brief 获取底层账户状态指针
         * @details 返回内部 shared_ptr 管理的裸指针。
         * @return 账户条目裸指针，租约为空时返回 nullptr
         */
        [[nodiscard]] auto get() const noexcept -> entry *
        {
            return state_.get();
        }

        /**
         * @brief 检查租约是否有效
         * @details 通过检查内部 shared_ptr 是否非空判断有效性。
         * @return 持有有效账户状态时返回 true
         */
        [[nodiscard]] explicit operator bool() const noexcept
        {
            return static_cast<bool>(state_);
        }

    private:
        /**
         * @brief 释放租约并递减活跃连接数
         * @details 使用 relaxed 内存序递减活跃连接数，然后
         * 重置 shared_ptr。空租约调用此方法为空操作。
         */
        void release() noexcept
        {
            if (!state_)
            {
                return;
            }

            state_->active_connections.fetch_sub(1, std::memory_order_relaxed);
            state_.reset();
        }

        std::shared_ptr<entry> state_; // 账户状态指针
    }; // class lease

    /**
     * @brief 累加上行流量
     * @details 使用 relaxed 内存序原子递增上行流量计数器。
     * @param state 账户状态指针，可为空
     * @param bytes 待累加的字节数
     * @note 空指针时直接返回，不执行任何操作
     */
    inline void accumulate_uplink(entry *state, const std::uint64_t bytes) noexcept
    {
        if (!state)
        {
            return;
        }

        state->uplink_bytes.fetch_add(bytes, std::memory_order_relaxed);
    }

    /**
     * @brief 累加下行流量
     * @details 使用 relaxed 内存序原子递增下行流量计数器。
     * @param state 账户状态指针，可为空
     * @param bytes 待累加的字节数
     * @note 空指针时直接返回，不执行任何操作
     */
    inline void accumulate_downlink(entry *state, const std::uint64_t bytes) noexcept
    {
        if (!state)
        {
            return;
        }

        state->downlink_bytes.fetch_add(bytes, std::memory_order_relaxed);
    }
} // namespace psm::agent::account
