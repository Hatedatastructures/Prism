/**
 * @file tunnel_relay.cpp
 * @brief 隧道转发器实现
 * @details 从 tunnel.cpp 的 tunnel(opts) free function 迁移。
 */

#include <prism/net/connect/tunnel/tunnel_relay.hpp>

#include <prism/account/entry.hpp>
#include <prism/net/connect/util.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/foundation/memory/pool.hpp>
#include <prism/account/stats/traffic.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/pad.hpp>

#include <boost/asio/experimental/awaitable_operators.hpp>

#include <array>
#include <chrono>
#include <functional>

using namespace psm::trace;

namespace psm::connect
{

    namespace
    {
        struct relay_options
        {
            write_policy policy;
            std::array<std::size_t, 2> &total_bytes;
            std::shared_ptr<net::steady_timer> &idle_timer;
            std::function<void(const boost::system::error_code &)> &idle_handler;
            std::chrono::seconds idle_timeout;
            const shared_transmission &from;
            const shared_transmission &to;
            std::span<std::byte> scratch;
            std::size_t idx;
        };

        auto relay_loop(relay_options opts)
            -> net::awaitable<void>
        {
            std::error_code ec;
            while (true)
            {
                const auto transferred = co_await opts.from->async_read_some(opts.scratch, ec);
                if (ec || transferred == 0)
                    co_return;

                opts.total_bytes[opts.idx] += transferred;
                opts.idle_timer->expires_after(opts.idle_timeout);
                opts.idle_timer->async_wait(opts.idle_handler);

                const auto data = opts.scratch.first(transferred);
                std::size_t written;
                if (opts.policy == write_policy::complete)
                {
                    written = co_await transport::async_write(*opts.to, data, ec);
                }
                else
                {
                    auto remaining = data;
                    while (!remaining.empty())
                    {
                        written = co_await opts.to->async_write_some(remaining, ec);
                        if (ec || written == 0)
                            co_return;
                        remaining = remaining.subspan(written);
                    }
                    written = transferred;
                }

                if (ec || (opts.policy == write_policy::complete && written < transferred))
                    co_return;

                opts.idle_timer->expires_after(opts.idle_timeout);
                opts.idle_timer->async_wait(opts.idle_handler);
            }
        }
    } // anonymous namespace

    tunnel_relay::tunnel_relay(tunnel_options opts) noexcept
        : opts_(std::move(opts))
    {
    }

    auto tunnel_relay::run() -> net::awaitable<void>
    {
        auto inbound = std::move(opts_.inbound);
        auto outbound = std::move(opts_.outbound);
        const auto policy = opts_.policy;

        if (opts_.pad_cfg && opts_.pad_cfg->enabled())
        {
            inbound = std::make_shared<transport::pad_transport>(inbound, *opts_.pad_cfg);
        }
        const auto start_time = std::chrono::steady_clock::now();

        auto *mr = memory::system::local_pool();
        const auto array_size = (std::max)(opts_.buffer_size, 2U);
        memory::vector<std::byte> buffer(array_size, memory::effective_mr(mr));
        const auto half = buffer.size() / 2;
        const auto left = std::span(buffer).first(half);
        const auto right = std::span(buffer).last(half);

        std::array<std::size_t, 2> total_bytes{0, 0};
        constexpr auto idle_timeout = std::chrono::seconds(300);
        auto idle_timer = std::make_shared<net::steady_timer>(co_await net::this_coro::executor);
        std::function<void(const boost::system::error_code &)> idle_handler =
            [inbound, outbound, prefix = opts_.trace](const boost::system::error_code &ec)
        {
            if (!ec)
            {
                trace::info<flt::conn | flt::protocol>(prefix, "idle timeout, closing tunnel");
                inbound->cancel();
                outbound->cancel();
            }
        };
        idle_timer->expires_after(idle_timeout);
        idle_timer->async_wait(idle_handler);

        relay_options state{
            policy, total_bytes,
            idle_timer, idle_handler, idle_timeout,
            inbound, outbound, left, 0};

        using boost::asio::experimental::awaitable_operators::operator||;
        auto mirror = relay_options{
            policy, total_bytes,
            idle_timer, idle_handler, idle_timeout,
            outbound, inbound, right, 1};
        co_await (relay_loop(state) || relay_loop(std::move(mirror)));

        idle_timer->cancel();

        const auto end_time = std::chrono::steady_clock::now();
        if (const auto up = total_bytes[0], down = total_bytes[1]; up > 0 || down > 0)
        {
            trace::info<flt::conn | flt::protocol>(opts_.trace,
                "Transfer: up={}B down={}B, {}ms",
                up, down,
                std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());
        }

        if (opts_.traffic)
        {
            opts_.traffic->flush_traffic(
                opts_.detected, total_bytes[0], total_bytes[1]);
        }

        if (opts_.lease)
        {
            if (total_bytes[0] > 0)
                account::accumulate_uplink(opts_.lease->get(), total_bytes[0]);
            if (total_bytes[1] > 0)
                account::accumulate_downlink(opts_.lease->get(), total_bytes[1]);
        }

        shut_close(inbound);
        shut_close(outbound);
    }

} // namespace psm::connect
