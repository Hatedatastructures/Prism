/**
 * @file runtime.cpp
 * @brief 运行状态与负载统计实现
 */
#include <prism/stats/runtime.hpp>
#include <prism/trace.hpp>

namespace psm::stats::runtime
{
    // --- worker_load ---

    worker_load::worker_load()
        : active_sessions_(std::make_shared<std::atomic<std::uint32_t>>(0U))
    {
    }

    void worker_load::session_open() noexcept
    {
        active_sessions_->fetch_add(1U, std::memory_order_relaxed);
    }

    void worker_load::session_close() noexcept
    {
        active_sessions_->fetch_sub(1U, std::memory_order_relaxed);
    }

    void worker_load::handoff_push() noexcept
    {
        pending_handoffs_.fetch_add(1U, std::memory_order_relaxed);
    }

    void worker_load::handoff_pop() noexcept
    {
        pending_handoffs_.fetch_sub(1U, std::memory_order_relaxed);
    }

    auto worker_load::session_counter() const noexcept
        -> const std::shared_ptr<std::atomic<std::uint32_t>> &
    {
        return active_sessions_;
    }

    auto worker_load::snapshot() const noexcept -> worker_load_snapshot
    {
        return {
            active_sessions_->load(std::memory_order_relaxed),
            pending_handoffs_.load(std::memory_order_relaxed),
            event_loop_lag_us_.load(std::memory_order_relaxed)};
    }

    auto worker_load::observe(net::io_context &ioc) -> net::awaitable<void>
    {
        net::steady_timer timer(ioc);
        auto expected_time = std::chrono::steady_clock::now();
        std::uint64_t jitter_baseline_us = 0;
        std::uint64_t smoothed_lag_us = 0;
        std::uint32_t warmup_samples = 0;

        for (;;)
        {
            expected_time += std::chrono::milliseconds(250);
            timer.expires_at(expected_time);

            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                if (ec != net::error::operation_aborted)
                {
                    trace::debug("[Stats] observe timer error: {}", ec.message());
                }
                co_return;
            }

            const auto current_time = std::chrono::steady_clock::now();
            const auto difference =
                std::chrono::duration_cast<std::chrono::microseconds>(current_time - expected_time).count();
            const auto lag_time = current_time > expected_time ? difference : 0;
            const auto raw_lag_us = lag_time > 0 ? static_cast<std::uint64_t>(lag_time) : 0ULL;
            const auto capped_lag_us = raw_lag_us > 20000ULL ? 20000ULL : raw_lag_us;

            if (warmup_samples < 16U)
            {
                jitter_baseline_us = (jitter_baseline_us * warmup_samples + capped_lag_us) / (warmup_samples + 1U);
                ++warmup_samples;
                event_loop_lag_us_.store(0ULL, std::memory_order_relaxed);
                continue;
            }

            auto effective_lag_us = capped_lag_us > jitter_baseline_us
                ? capped_lag_us - jitter_baseline_us
                : 0ULL;

            if (effective_lag_us <= 1000ULL)
            {
                effective_lag_us = 0ULL;
            }

            smoothed_lag_us = (smoothed_lag_us * 7ULL + effective_lag_us) / 8ULL;
            event_loop_lag_us_.store(smoothed_lag_us, std::memory_order_relaxed);
        }
    }

    // --- system_state ---

    auto system_state::instance() -> system_state &
    {
        static system_state inst;
        return inst;
    }

    void system_state::mark_started(std::uint32_t worker_count) noexcept
    {
        if (started_.exchange(true, std::memory_order_relaxed))
        {
            return;
        }
        start_time_ = std::chrono::steady_clock::now();
        worker_count_ = worker_count;
    }

    auto system_state::snapshot() const noexcept -> runtime_snapshot
    {
        if (!started_.load(std::memory_order_relaxed))
        {
            return {};
        }
        const auto now = std::chrono::steady_clock::now();
        const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - start_time_).count();
        return {static_cast<std::uint64_t>(uptime), worker_count_};
    }
} // namespace psm::stats::runtime
