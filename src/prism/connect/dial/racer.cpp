#include <prism/connect/dial/racer.hpp>

#include <prism/memory/container.hpp>
#include <prism/trace.hpp>
#include <prism/trace/context.hpp>

#include <atomic>
#include <memory>

using namespace psm::trace;

namespace psm::connect
{

    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;

    struct address_racer::race_context
    {
        std::atomic<bool> winner{false};
        pooled_connection result;
        std::atomic<std::size_t> pending;
        net::steady_timer signal;

        race_context(const std::size_t count, net::any_io_executor ex)
            : pending(count), signal(std::move(ex))
        {
            signal.expires_at(net::steady_timer::time_point::max());
        }

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
    }

    auto address_racer::race(std::span<const tcp::endpoint> endpoints)
        -> net::awaitable<pooled_connection>
    {
        if (endpoints.empty())
        {
            co_return pooled_connection{};
        }

        if (endpoints.size() == 1)
        {
            auto [code, conn] = co_await pool_.async_acquire(endpoints[0]);
            co_return conn;
        }

        constexpr std::size_t max_racing = 6;
        const auto count = std::min(endpoints.size(), max_racing);

        trace::debug<flt::conn | flt::protocol>("racing {} endpoints", count);

        auto executor = co_await net::this_coro::executor;
        auto ctx = std::make_shared<race_context>(count, executor);

        for (std::size_t i = 0; i < count; ++i)
        {
            std::chrono::milliseconds delay{0};
            if (i > 0)
                delay = secondary_delay * static_cast<long>(i);

            net::co_spawn(executor, race_endpoint(endpoints[i], delay, ctx), net::detached);
        }

        boost::system::error_code ec;
        co_await ctx->signal.async_wait(net::redirect_error(trace::use_prefix_awaitable, ec));
        co_return std::move(ctx->result);
    }

    auto address_racer::race_endpoint(tcp::endpoint ep, std::chrono::milliseconds delay, std::shared_ptr<race_context> ctx)
        -> net::awaitable<void>
    {
        trace::active_prefix = nullptr;

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

            auto [code, conn] = co_await pool_.async_acquire(ep);

            if (!conn.valid())
            {
                trace::debug<flt::conn | flt::protocol>("endpoint {} failed: {}", ep.address().to_string(), static_cast<int>(code));
                ctx->complete();
                co_return;
            }

            if (!ctx->winner.exchange(true, std::memory_order_acq_rel))
            {
                ctx->result = std::move(conn);

                trace::info<flt::conn | flt::protocol>("endpoint {} won the race", ep.address().to_string());

                ctx->signal.cancel();
            }
            else
            {
                trace::debug<flt::conn | flt::protocol>("endpoint {} connected but not winner, returning to pool", ep.address().to_string());

                conn.reset();
            }

            ctx->complete();
        }
        catch (const std::exception &e)
        {
            trace::debug<flt::conn | flt::protocol>("endpoint {} error: {}", ep.address().to_string(), e.what());
            ctx->complete();
        }
        catch (...)
        {
            trace::error<flt::conn | flt::protocol>("endpoint {} unknown error", ep.address().to_string());
            ctx->complete();
        }
    }

} // namespace psm::connect
