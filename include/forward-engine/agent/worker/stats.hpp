/**
 * @file stats.hpp
 * @brief Worker 负载统计模块。
 * @details 本文件提供单个 worker 线程的运行状态统计功能。统计
 * 数据包括活跃会话数、待处理连接数和事件循环延迟三项核心指标。
 * 这些指标被负载均衡器用于决策新连接应该分发到哪个 worker，
 * 实现基于实际负载的动态调度。
 */

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>

#include <boost/asio.hpp>

#include <forward-engine/agent/front/balancer.hpp>

/**
 * @namespace ngx::agent::worker::stats
 * @brief Worker 负载统计功能。
 * @details 该命名空间封装了 worker 线程运行状态的采集和查询功能。
 * 通过原子操作保证多线程环境下的数据一致性，支持高并发读写。
 * 统计结果以快照形式提供给负载均衡器，避免长时间持有锁。
 */
namespace ngx::agent::worker::stats
{
    namespace net = boost::asio;

    /**
     * @class state
     * @brief 单个 worker 的运行负载统计状态。
     * @details 该类维护三项核心指标：活跃会话数表示当前正在处理的
     * 连接数量，待处理连接数表示已投递但尚未开始处理的连接数量，
     * 事件循环延迟反映 worker 的处理压力。延迟测量采用 EMA 平滑
     * 算法，过滤短期抖动，提供稳定的负载评估依据。所有计数器均
     * 使用原子操作，支持无锁并发访问。
     * @note 活跃会话计数器使用 shared_ptr 包装，允许会话关闭回调
     * 仅捕获计数器而非整个 state 对象，延长 state 的生命周期。
     * @warning observe 协程必须在 worker 的事件循环中运行，否则
     * 延迟测量将不准确。
     */
    class state
    {
    public:
        /**
         * @brief 创建空的统计状态。
         * @details 初始化所有计数器为零，分配共享的活跃会话计数器。
         * 计数器使用 shared_ptr 包装，支持跨线程共享访问。
         */
        state();

        /**
         * @brief 会话开始时调用。
         * @details 递增活跃会话计数器，使用 relaxed 内存序即可，
         * 因为负载均衡器仅需要近似值进行决策。
         */
        void session_open() noexcept;

        /**
         * @brief 会话结束时调用。
         * @details 递减活跃会话计数器，与 session_open 配对使用。
         */
        void session_close() noexcept;

        /**
         * @brief 有新 socket 等待投递时调用。
         * @details 递增待处理连接计数器，表示连接已从主线程投递
         * 到 worker 但尚未开始处理。
         */
        void handoff_push() noexcept;

        /**
         * @brief 等待投递的 socket 被消费后调用。
         * @details 递减待处理连接计数器，与 handoff_push 配对使用。
         */
        void handoff_pop() noexcept;

        /**
         * @brief 获取活跃会话计数器。
         * @details 返回共享指针包装的计数器，允许会话关闭回调仅
         * 捕获计数器本身，避免持有整个 state 对象导致生命周期问题。
         * @return 活跃会话计数器的共享指针。
         */
        [[nodiscard]] auto session_counter() const noexcept
            -> const std::shared_ptr<std::atomic<std::uint32_t>> &;

        /**
         * @brief 读取当前负载快照。
         * @details 原子地读取三项指标并打包成快照结构体返回。
         * 快照是瞬时值，不保证三项指标的一致性，但足以支持
         * 负载均衡决策。
         * @return 包含活跃会话数、待处理连接数和延迟的快照。
         */
        [[nodiscard]] auto snapshot() const noexcept
            -> front::worker_load_snapshot;

        /**
         * @brief 周期性采样事件循环延迟。
         * @details 该协程在 worker 事件循环中持续运行，每 250 毫秒
         * 测量一次调度延迟。测量过程分为三个阶段：首先是预热阶段，
         * 采集 16 个样本估算系统调度抖动基线；然后进入正常采样，
         * 从原始延迟中扣除基线抖动；最后使用 EMA 平滑算法处理
         * 结果，过滤 1ms 以内的小抖动，避免单次尖峰影响负载评估。
         * 延迟值上限为 20ms，防止单次异常值污染统计数据。
         * @param ioc 当前 worker 的 io_context。
         * @return 协程任务，持续运行直到事件循环停止。
         */
        auto observe(net::io_context &ioc)
            -> net::awaitable<void>;

    private:
        // 当前活跃会话数，使用共享指针包装以支持跨线程访问。
        std::shared_ptr<std::atomic<std::uint32_t>> active_sessions_;
        // 等待投递到 worker 的 socket 数。
        std::atomic<std::uint32_t> pending_handoffs_{0};
        // 平滑后的事件循环延迟，单位微秒。
        std::atomic<std::uint64_t> event_loop_lag_us_{0};
    };
}
