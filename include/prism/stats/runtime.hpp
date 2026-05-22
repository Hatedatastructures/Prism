/**
 * @file runtime.hpp
 * @brief 运行状态与负载统计
 * @details 提供 worker 级负载监控和全局运行状态。
 * worker_load 从原有 stats::state 迁移，逻辑零改动。
 */
#pragma once

#include <atomic>
#include <chrono>
#include <memory>

#include <boost/asio.hpp>

#include <prism/stats/snapshot.hpp>

namespace psm::stats::runtime
{
    namespace net = boost::asio;

    /**
     * @class worker_load
     * @brief 单个 worker 的运行负载统计
     * @details 从原有 psm::stats::state 迁移，接口和算法完全不变。
     * 活跃会话计数器使用 shared_ptr 包装，允许会话关闭回调
     * 仅捕获计数器而非整个对象。
     */
    class worker_load
    {
    public:
        worker_load();
        void session_open() noexcept;
        void session_close() noexcept;
        void handoff_push() noexcept;
        void handoff_pop() noexcept;

        [[nodiscard]] auto session_counter() const noexcept
            -> const std::shared_ptr<std::atomic<std::uint32_t>> &;

        [[nodiscard]] auto snapshot() const noexcept -> worker_load_snapshot;

        auto observe(net::io_context &ioc) -> net::awaitable<void>;

    private:
        std::shared_ptr<std::atomic<std::uint32_t>> active_sessions_;
        std::atomic<std::uint32_t> pending_handoffs_{0};
        std::atomic<std::uint64_t> event_loop_lag_us_{0};
    };

    /**
     * @class system_state
     * @brief 全局运行状态单例
     * @details 记录进程启动时间和 worker 数量。
     * main.cpp 中调用 mark_started() 一次。
     */
    class system_state
    {
    public:
        static auto instance() -> system_state &;

        void mark_started(std::uint32_t worker_count) noexcept;

        [[nodiscard]] auto snapshot() const noexcept -> runtime_snapshot;

    private:
        std::atomic<bool> started_{false};
        std::chrono::steady_clock::time_point start_time_{};
        std::uint32_t worker_count_{0};
    };
} // namespace psm::stats::runtime
