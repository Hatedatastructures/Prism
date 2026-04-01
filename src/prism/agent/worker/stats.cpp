#include <prism/agent/worker/stats.hpp>

namespace psm::agent::worker::stats
{
    state::state()
        : active_sessions_(std::make_shared<std::atomic<std::uint32_t>>(0U))
    {
    }

    void state::session_open() noexcept
    {
        active_sessions_->fetch_add(1U, std::memory_order_relaxed);
    }

    void state::session_close() noexcept
    {
        active_sessions_->fetch_sub(1U, std::memory_order_relaxed);
    }

    void state::handoff_push() noexcept
    {
        pending_handoffs_.fetch_add(1U, std::memory_order_relaxed);
    }

    void state::handoff_pop() noexcept
    {
        pending_handoffs_.fetch_sub(1U, std::memory_order_relaxed);
    }

    auto state::session_counter() const noexcept
        -> const std::shared_ptr<std::atomic<std::uint32_t>> &
    {
        return active_sessions_;
    }

    auto state::snapshot() const noexcept
        -> front::worker_load_snapshot
    {
        return {
            active_sessions_->load(std::memory_order_relaxed),
            pending_handoffs_.load(std::memory_order_relaxed),
            event_loop_lag_us_.load(std::memory_order_relaxed)};
    }

    auto state::observe(net::io_context &ioc)
        -> net::awaitable<void>
    {
        net::steady_timer timer(ioc);

        // 期望触发时间点，用于计算实际延迟
        auto expected_time = std::chrono::steady_clock::now();

        // 抖动基线，用于过滤系统调度抖动
        std::uint64_t jitter_baseline_us = 0;

        // 平滑后的延迟值，采用指数移动平均
        std::uint64_t smoothed_lag_us = 0;

        // 预热采样计数，前 16 次用于建立抖动基线
        std::uint32_t warmup_samples = 0;

        for (;;)
        {
            // 每 250ms 触发一次定时器，用于检测事件循环延迟
            expected_time += std::chrono::milliseconds(250);
            timer.expires_at(expected_time);

            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                co_return;
            }

            // 计算实际触发时间与期望时间的偏差
            const auto current_time = std::chrono::steady_clock::now();
            const auto difference = std::chrono::duration_cast<std::chrono::microseconds>(current_time - expected_time).count();
            const auto lag_time = current_time > expected_time ? difference : 0;
            const auto raw_lag_us = lag_time > 0 ? static_cast<std::uint64_t>(lag_time) : 0ULL;

            // 将延迟上限截断到 20ms，避免异常值干扰
            const auto capped_lag_us = raw_lag_us > 20000ULL ? 20000ULL : raw_lag_us;

            // 预热阶段：收集前 16 个样本建立抖动基线
            if (warmup_samples < 16U)
            {
                jitter_baseline_us = (jitter_baseline_us * warmup_samples + capped_lag_us) / (warmup_samples + 1U);
                ++warmup_samples;
                event_loop_lag_us_.store(0ULL, std::memory_order_relaxed);
                continue;
            }

            // 从原始延迟中扣除抖动基线，得到有效延迟
            auto effective_lag_us = capped_lag_us > jitter_baseline_us
                ? capped_lag_us - jitter_baseline_us
                : 0ULL;

            // 低于 1ms 的延迟视为零，过滤噪声
            if (effective_lag_us <= 1000ULL)
            {
                effective_lag_us = 0ULL;
            }

            // 指数移动平均平滑延迟值，权重 7/8 给历史值
            smoothed_lag_us = (smoothed_lag_us * 7ULL + effective_lag_us) / 8ULL;
            event_loop_lag_us_.store(smoothed_lag_us, std::memory_order_relaxed);
        }
    }
} // namespace psm::agent::worker::stats
