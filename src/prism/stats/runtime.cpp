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


    auto worker_load::snapshot() const noexcept
        -> worker_snapshot
    {
        return {
            active_sessions_->load(std::memory_order_relaxed),
            pending_handoffs_.load(std::memory_order_relaxed),
            lag_us_.load(std::memory_order_relaxed)};
    }


    // 算法流程：
    // 1. 每 250ms 设置定时器并等待
    // 2. 测量实际等待时间与预期时间的偏差
    // 3. 前 16 次采样为预热，建立抖动基线（jitter_baseline_us）
    // 4. 之后的有效延迟 = 实际延迟 - 抖动基线，低于 1ms 的忽略
    // 5. EMA 平滑系数 7/8，与 Linux 内核 load average 一致
    auto worker_load::observe(net::io_context &ioc)
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
            co_await timer.async_wait(net::redirect_error(trace::use_prefix_awaitable, ec));
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
            std::int64_t lag_time;
            if (current_time > expected_time)
            {
                lag_time = difference;
            }
            else
            {
                lag_time = 0;
            }
            std::uint64_t raw_lag_us;
            if (lag_time > 0)
            {
                raw_lag_us = static_cast<std::uint64_t>(lag_time);
            }
            else
            {
                raw_lag_us = 0ULL;
            }
            std::uint64_t capped_lag_us;
            if (raw_lag_us > 20000ULL)
            {
                capped_lag_us = 20000ULL;
            }
            else
            {
                capped_lag_us = raw_lag_us;
            }

            if (warmup_samples < 16U)
            {
                jitter_baseline_us = (jitter_baseline_us * warmup_samples + capped_lag_us) / (warmup_samples + 1U);
                ++warmup_samples;
                lag_us_.store(0ULL, std::memory_order_relaxed);
                continue;
            }

            std::uint64_t effective_lag_us;
            if (capped_lag_us > jitter_baseline_us)
            {
                effective_lag_us = capped_lag_us - jitter_baseline_us;
            }
            else
            {
                effective_lag_us = 0ULL;
            }

            if (effective_lag_us <= 1000ULL)
            {
                effective_lag_us = 0ULL;
            }

            smoothed_lag_us = (smoothed_lag_us * 7ULL + effective_lag_us) / 8ULL;
            lag_us_.store(smoothed_lag_us, std::memory_order_relaxed);
        }
    }


    // --- system_state ---

    auto system_state::instance()
        -> system_state &
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


    auto system_state::snapshot() const noexcept
        -> runtime_snapshot
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
