/**
 * @file runtime.hpp
 * @brief 运行状态与负载统计
 * @details 提供 worker 级负载监控和全局运行状态。
 * worker_load 从原有 stats::state 迁移，逻辑零改动。
 */
#pragma once

#include <prism/stats/snapshot.hpp>

#include <boost/asio.hpp>

#include <atomic>
#include <chrono>
#include <memory>


namespace psm::stats::runtime
{

    namespace net = boost::asio;

    /**
     * @class worker_load
     * @brief 单个 worker 的运行负载统计
     * @details 从原有 psm::stats::state 迁移，接口和算法完全不变。
     * 活跃会话计数器使用 shared_ptr 包装，允许会话关闭回调
     * 仅捕获计数器而非整个对象。
     * @note observe() 协程在 worker 的 io_context 上运行，每 250ms 采样一次
     */
    class worker_load final
    {
    public:
        explicit worker_load();

        /**
         * @brief 活跃会话 +1
         * @details 在 launch::start() 中调用
         */
        void session_open() noexcept;

        /**
         * @brief 活跃会话 -1
         * @details 在 launch::dispatch() 的 on_closed 回调中调用
         */
        void session_close() noexcept;

        /**
         * @brief 分发队列入队 +1
         * @details 在 launch::dispatch() 入队时调用
         */
        void handoff_push() noexcept;

        /**
         * @brief 分发队列出队 -1
         * @details 在 launch::dispatch() 出队时调用
         */
        void handoff_pop() noexcept;

        /**
         * @brief 获取活跃会话计数器的共享指针
         * @return 共享指针，允许会话关闭回调安全持有
         */
        [[nodiscard]] auto session_counter() const noexcept
            -> const std::shared_ptr<std::atomic<std::uint32_t>> &;

        /**
         * @brief 获取当前负载快照
         * @return 包含活跃会话数、待分发数、事件循环延迟的快照
         */
        [[nodiscard]] auto snapshot() const noexcept
            -> worker_snapshot;

        /**
         * @brief 启动事件循环延迟监测协程
         * @param io_context 要监测的 io_context
         * @return 异步操作，随 io_context 生命周期运行
         * @details 每 250ms 采样一次实际等待时间，经 EMA 平滑后
         * 存入 lag_us_。前 16 次采样为预热，用于
         * 建立抖动基线，之后的有效延迟需超过 1ms 才计入。
         */
        [[nodiscard]] auto observe(net::io_context &ioc)
            -> net::awaitable<void>;

    private:
        std::shared_ptr<std::atomic<std::uint32_t>> active_sessions_;  ///< 活跃会话计数器（共享给 on_closed 回调）
        std::atomic<std::uint32_t> pending_handoffs_{0};               ///< 待分发连接数
        std::atomic<std::uint64_t> lag_us_{0};                     ///< 事件循环延迟（微秒，EMA 平滑后）
    };

    /**
     * @class system_state
     * @brief 全局运行状态单例
     * @details 记录进程启动时间和 worker 数量。通过 instance() 获取
     * 全局唯一实例，main.cpp 中调用 mark_started() 一次初始化。
     * @note 线程安全：所有操作均为原子操作
     */
    class system_state final
    {
    public:
        /**
         * @brief 获取全局单例
         * @return system_state 引用
         */
        [[nodiscard]] static auto instance()
            -> system_state &;

        /**
         * @brief 标记系统已启动（仅调用一次）
         * @param worker_count 工作线程数量
         * @note 重复调用为空操作
         */
        void mark_started(std::uint32_t worker_count) noexcept;

        /**
         * @brief 获取运行状态快照
         * @return 包含运行时间和 worker 数量的快照
         */
        [[nodiscard]] auto snapshot() const noexcept
            -> runtime_snapshot;

    private:
        std::atomic<bool> started_{false};                              ///< 是否已启动
        std::chrono::steady_clock::time_point start_time_{};           ///< 启动时间点
        std::uint32_t worker_count_{0};                                 ///< 工作线程数量
    };
} // namespace psm::stats::runtime
