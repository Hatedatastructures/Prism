#include <prism/channel/eyeball/racer.hpp>

#include <prism/trace.hpp>

#include <memory>

namespace psm::channel::eyeball
{
    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;

    struct address_racer::race_context
    {
        std::atomic<bool> winner{false};  // 获胜标志
        pooled_connection result;          // 获胜连接
        std::atomic<std::size_t> pending;  // 未完成计数
        net::steady_timer signal;          // 完成信号定时器

        race_context(const std::size_t count, net::any_io_executor ex)
            : pending(count), signal(std::move(ex))
        {
            signal.expires_at(net::steady_timer::time_point::max());
        }

        /// 递减 pending，最后一个完成时取消 signal 唤醒主协程
        void complete()
        {
            if (pending.fetch_sub(1) == 1)
            {
                signal.cancel();
            }
        }
    };

    address_racer::address_racer(connection_pool &pool)
        : pool_(pool)
    {
        trace::debug("[Racer] instance created");
    }

    auto address_racer::race(std::span<const tcp::endpoint> endpoints)
        -> net::awaitable<pooled_connection>
    {
        if (endpoints.empty())
        {
            co_return pooled_connection{};
        }

        // 单端点无需并发开销
        if (endpoints.size() == 1)
        {
            auto [code, conn] = co_await pool_.async_acquire(endpoints[0]);
            co_return conn;
        }

        trace::debug("[Racer] racing {} endpoints", endpoints.size());

        auto executor = co_await net::this_coro::executor;
        auto ctx = std::make_shared<race_context>(endpoints.size(), executor);

        // 第 1 个端点立即连接，后续按 250ms 间隔递增启动（RFC 8305）
        for (std::size_t i = 0; i < endpoints.size(); ++i)
        {
            const auto delay = (i == 0) ? std::chrono::milliseconds(0) : secondary_delay * static_cast<long>(i);

            net::co_spawn(executor, race_endpoint(endpoints[i], delay, ctx), net::detached);
        }

        // 等待任意子协程取消 signal（有获胜者或全部失败）
        boost::system::error_code ec;
        co_await ctx->signal.async_wait(net::redirect_error(net::use_awaitable, ec));
        co_return std::move(ctx->result);
    }

    auto address_racer::race_endpoint(tcp::endpoint ep, std::chrono::milliseconds delay, std::shared_ptr<race_context> ctx)
        -> net::awaitable<void>
    {
        try
        {
            // 等待 staggered delay（第 1 个端点 delay=0 跳过）
            if (delay.count() > 0)
            {
                net::steady_timer timer(co_await net::this_coro::executor);
                timer.expires_after(delay);

                boost::system::error_code ec;
                co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));

                if (ec)
                {
                    ctx->complete();
                    co_return;
                }
            }

            // 延迟期间可能已有获胜者，跳过连接
            if (ctx->winner.load(std::memory_order_acquire))
            {
                ctx->complete();
                co_return;
            }

            auto [code, conn] = co_await pool_.async_acquire(ep);

            if (!conn.valid())
            {
                trace::debug("[Racer] endpoint {} failed: {}", ep.address().to_string(), static_cast<int>(code));
                ctx->complete();
                co_return;
            }

            // exchange 原子操作：只有第一个成功者得到 false
            if (!ctx->winner.exchange(true, std::memory_order_acq_rel))
            {
                // 获胜：保存连接，唤醒主协程
                ctx->result = std::move(conn);

                trace::info("[Racer] endpoint {} won the race", ep.address().to_string());

                ctx->signal.cancel();
            }
            else
            {
                // 落败：归还连接到池中供复用
                trace::debug("[Racer] endpoint {} connected but not winner, returning to pool", ep.address().to_string());

                conn.reset();
            }

            ctx->complete();
        }
        catch (const std::exception &e)
        {
            trace::debug("[Racer] endpoint {} error: {}", ep.address().to_string(), e.what());
            ctx->complete();
        }
        catch (...)
        {
            trace::error("[Racer] endpoint {} unknown error", ep.address().to_string());
            ctx->complete();
        }
    }

} // namespace psm::channel::eyeball
