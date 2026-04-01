/**
 * @file entry.hpp
 * @brief 账户条目状态与租约管理
 * @details 定义账户状态结构和租约 RAII 封装，用于跟踪单个账户的连接数、
 * 上下行流量等运行时指标。租约对象通过引用计数自动管理活跃连接数，
 * 确保连接释放时正确递减计数器。
 */

#pragma once

#include <atomic>
#include <memory>
#include <cstdint>

/**
 * @namespace psm::agent::account
 * @brief 账户管理模块
 * @details 提供账户状态跟踪、连接数限制、流量统计等核心能力，
 * 为代理层提供基于凭证的账户隔离和资源管控。
 */
namespace psm::agent::account
{
    /**
     * @struct entry
     * @brief 账户运行时状态
     * @details 存储单个账户的连接限制和实时统计信息，所有统计字段
     * 使用原子操作保证线程安全。该结构体由 directory 统一管理生命周期，
     * 通过 shared_ptr 在多连接间共享。
     */
    struct entry
    {
        std::uint32_t max_connections{0};           // 最大连接数
        std::atomic_uint64_t uplink_bytes{0};       // 上行流量
        std::atomic_uint64_t downlink_bytes{0};     // 下行流量
        std::atomic_uint32_t active_connections{0}; // 活跃连接数
    };

    /**
     * @class lease
     * @brief 账户连接租约
     * @details RAII 封装，持有 entry 的共享所有权并在构造时递增活跃连接数，
     * 析构时自动递减。用于确保连接异常退出时不会泄漏连接计数。
     * 租约不可拷贝，仅支持移动语义。
     */
    class lease
    {
    public:
        lease() = default;

        /**
         * @brief 从账户条目构造租约
         * @param state 账户状态指针，调用方需确保已在构造前递增活跃连接数
         */
        explicit lease(std::shared_ptr<entry> state) noexcept
            : state_(std::move(state))
        {
        }

        /**
         * @brief 移动构造租约
         * @param other 源租约对象，移动后置空
         */
        lease(lease &&other) noexcept
            : state_(std::move(other.state_))
        {
        }

        /**
         * @brief 移动赋值租约
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
         */
        ~lease()
        {
            release();
        }

        /**
         * @brief 获取底层账户状态指针
         * @return 账户条目裸指针，租约为空时返回 nullptr
         */
        [[nodiscard]] auto get() const noexcept -> entry *
        {
            return state_.get();
        }

        /**
         * @brief 检查租约是否有效
         * @return 持有有效账户状态时返回 true
         */
        [[nodiscard]] explicit operator bool() const noexcept
        {
            return static_cast<bool>(state_);
        }

    private:
        /**
         * @brief 释放租约并递减活跃连接数
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

        std::shared_ptr<entry> state_; // 账户状态指针，持有 entry 的共享所有权
    };

    /**
     * @brief 累加上行流量
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
