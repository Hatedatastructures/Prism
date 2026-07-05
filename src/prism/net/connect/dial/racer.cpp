#include <prism/net/connect/dial/racer.hpp>

#include <prism/foundation/memory/container.hpp>
#include <boost/asio/co_spawn.hpp>
#include <prism/trace/trace.hpp>
#include <prism/trace/context.hpp>

#include <atomic>
#include <memory>

using namespace psm::trace;

namespace psm::connect
{

    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;

    // 竞速上下文：多个端点并发连接，首个成功者通过原子标志选出胜者
    struct address_racer::race_context
    {
        std::atomic<bool> winner{false}; // 原子标志，首个成功连接的端点设为 true
        pooled_connection result;        // 胜者的连接，由 CAS 竞争写入
        std::atomic<std::size_t> pending; // 尚未完成的协程计数
        net::steady_timer signal;        // 不会自动到期，仅靠 cancel() 手动唤醒主协程

        race_context(const std::size_t count, net::any_io_executor ex)
            : pending(count), signal(std::move(ex))
        {
            // 设为 time_point::max 使定时器永不自动到期，
            // 主协程 co_await 等待它被 cancel() 才继续
            signal.expires_at(net::steady_timer::time_point::max());
        }

        void complete()
        {
            // fetch_sub 返回减之前的值；返回 1 表示自己是最后一个，
            // 此时所有子协程都已完成（无论成功或失败），取消定时器唤醒主协程
            if (pending.fetch_sub(1) == 1)
            {
                signal.cancel();
            }
        }
    };

    address_racer::address_racer(connection_pool &pool)
        : pool_(pool)
    {
    }

    auto address_racer::race(std::span<const tcp::endpoint> endpoints, std::shared_ptr<trace::trace_context> trace)
        -> net::awaitable<pooled_connection>
    {
        if (endpoints.empty())
        {
            co_return pooled_connection{};
        }

        if (endpoints.size() == 1)
        {
            auto [code, conn] = co_await pool_.async_acquire(endpoints[0], trace);
            co_return conn;
        }

        // 限制同时竞速的端点数，防止 DNS 返回大量结果时创建过多协程
        constexpr std::size_t max_racing = 6;
        const auto count = std::min(endpoints.size(), max_racing);

        trace::debug<flt::conn | flt::protocol>(trace, "racing {} endpoints", count);

        auto executor = co_await net::this_coro::executor;
        auto ctx = std::make_shared<race_context>(count, executor);

        for (std::size_t i = 0; i < count; ++i)
        {
        // RFC 8305 Happy Eyeballs stagger 策略：
        // 首端点立即连接，后续端点按 secondary_delay 递增延迟，
        // 给 IPv4 优先机会但不会长时间阻塞在失败地址上
        // trace 参数已显式传入（替代旧 active_prefix 获取）

        std::chrono::milliseconds delay{0};
            if (i > 0)
                delay = secondary_delay * static_cast<long>(i);

            net::co_spawn(executor,
                race_endpoint(endpoints[i], delay, ctx, trace), net::detached);
        }

        boost::system::error_code ec;
        co_await ctx->signal.async_wait(net::redirect_error(trace::use_prefix_awaitable, ec));
        co_return std::move(ctx->result);
    }

    auto address_racer::race_endpoint(tcp::endpoint ep, std::chrono::milliseconds delay, std::shared_ptr<race_context> ctx, std::shared_ptr<trace::trace_context> trace)
        -> net::awaitable<void>
    {
    // 子协程：每个端点一个，延迟到期后尝试连接
    // 清除父协程日志前缀，子协程不应该继承调用者的会话上下文

        try
        {
            if (delay.count() > 0)
            {
                net::steady_timer timer(co_await net::this_coro::executor);
                timer.expires_after(delay);

                boost::system::error_code ec;
                co_await timer.async_wait(net::redirect_error(trace::use_prefix_awaitable, ec));

                if (ec)
                {
                    ctx->complete();
                    co_return;
                }
            }

            if (ctx->winner.load(std::memory_order_acquire))
            {
                ctx->complete();
                co_return;
            }

            auto [code, conn] = co_await pool_.async_acquire(ep, trace);

            if (!conn.valid())
            {
                trace::debug<flt::conn | flt::protocol>(trace, "endpoint {} failed: {}", ep.address().to_string(), static_cast<int>(code));
                ctx->complete();
                co_return;
            }

            // 原子 exchange(true) 实现 CAS：如果之前无人获胜（返回 false），
            // 自己成为胜者并保存连接；否则说明已有更快端点，把连接归还池
            if (!ctx->winner.exchange(true, std::memory_order_acq_rel))
            {
                ctx->result = std::move(conn);

                trace::info<flt::conn | flt::protocol>(trace, "endpoint {} won the race", ep.address().to_string());

                ctx->signal.cancel();
            }
            else
            {
                trace::debug<flt::conn | flt::protocol>(trace, "endpoint {} connected but not winner, returning to pool", ep.address().to_string());

                conn.reset();
            }

            ctx->complete();
        }
        catch (const std::exception &e)
        {
            trace::debug<flt::conn | flt::protocol>(trace, "endpoint {} error: {}", ep.address().to_string(), e.what());
            ctx->complete();
        }
        catch (...)
        {
            trace::error<flt::conn | flt::protocol>(trace, "endpoint {} unknown error", ep.address().to_string());
            ctx->complete();
        }
    }

} // namespace psm::connect
