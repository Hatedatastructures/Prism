#include <forward-engine/agent/reactor/stats.hpp>

namespace ngx::agent::reactor::stats
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
                co_return;
            }

            const auto current_time = std::chrono::steady_clock::now();
            const auto lag_time = current_time > expected_time
                ? std::chrono::duration_cast<std::chrono::microseconds>(current_time - expected_time).count()
                : 0;
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
} // namespace ngx::agent::reactor::stats
