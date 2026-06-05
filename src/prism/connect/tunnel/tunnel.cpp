#include <prism/connect/tunnel/tunnel.hpp>

#include <prism/account/entry.hpp>
#include <prism/connect/util.hpp>
#include <prism/memory/container.hpp>
#include <prism/memory/pool.hpp>
#include <prism/stats/traffic.hpp>
#include <prism/trace.hpp>
#include <prism/transport/transmission.hpp>

#include <boost/asio/experimental/awaitable_operators.hpp>

#include <array>
#include <chrono>

using namespace psm::trace;

namespace psm::connect
{

    namespace
    {
        // 转发中继共享状态
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

        // 单向转发循环，从 from 读取数据写入 to
        auto relay_loop(relay_options opts)
            -> net::awaitable<void>
        {
            const bool is_download = (opts.idx == 1);
            const auto *dir = "upload";
            if (is_download)
            {
                dir = "download";
            }
            const auto *pol = "partial";
            if (opts.policy == write_policy::complete)
            {
                pol = "complete";
            }
            trace::debug<flt::conn | flt::protocol>("forward[{}]: started, policy={}",
                                                        dir, pol);

            std::error_code ec;
            while (true)
            {
                const auto transferred = co_await opts.from->async_read_some(opts.scratch, ec);
                if (ec || transferred == 0)
                {
                    trace::debug<flt::conn | flt::protocol>("forward[{}]: read done, transferred={}, ec={}",
                                                                dir, transferred, ec.message());
                    co_return;
                }

                opts.total_bytes[opts.idx] += transferred;
                trace::debug<flt::conn | flt::protocol>("forward[{}]: read {} bytes, total now {}",
                                                            dir, transferred, opts.total_bytes[opts.idx]);

                // 重置空闲超时
                opts.idle_timer->expires_after(opts.idle_timeout);
                opts.idle_timer->async_wait(opts.idle_handler);

                const auto data = opts.scratch.first(transferred);
                std::size_t written;
                if (opts.policy == write_policy::complete)
                {
                    trace::debug<flt::conn | flt::protocol>("forward[{}]: calling async_write({} bytes)",
                                                                dir, data.size());
                    written = co_await transport::async_write(*opts.to, data, ec);
                    trace::debug<flt::conn | flt::protocol>("forward[{}]: async_write returned written={}, ec={}",
                                                                dir, written, ec.message());
                }
                else
                {
                    auto remaining = data;
                    while (!remaining.empty())
                    {
                        written = co_await opts.to->async_write_some(remaining, ec);
                        if (ec)
                        {
                            trace::debug<flt::conn | flt::protocol>("forward[{}]: partial write failed, written={}",
                                                                dir, written);
                            co_return;
                        }
                        if (written == 0)
                        {
                            trace::debug<flt::conn | flt::protocol>("forward[{}]: partial write returned 0 bytes",
                                                                dir);
                            co_return;
                        }
                        remaining = remaining.subspan(written);
                    }
                    written = transferred;
                }

                if (ec || (opts.policy == write_policy::complete && written < transferred))
                {
                    trace::debug<flt::conn | flt::protocol>("forward[{}]: write done/failed, written={}, expected={}",
                                                                dir, written, transferred);
                    co_return;
                }

                // 重置空闲超时
                opts.idle_timer->expires_after(opts.idle_timeout);
                opts.idle_timer->async_wait(opts.idle_handler);
            }
        }

    } // anonymous namespace

    auto tunnel(tunnel_options opts)
        -> net::awaitable<void>
    {
        auto inbound = std::move(opts.inbound);
        auto outbound = std::move(opts.outbound);
        const auto &ctx = opts.ctx;
        const auto policy = opts.policy;
        const auto start_time = std::chrono::steady_clock::now();

        auto *mr = memory::system::local_pool();
        const auto array_size = (std::max)(ctx.buffer_size, 2U);
        memory::vector<std::byte> buffer(array_size, memory::effective_mr(mr));
        const auto half = buffer.size() / 2;
        const auto left = std::span(buffer).first(half);
        const auto right = std::span(buffer).last(half);

        std::array<std::size_t, 2> total_bytes{0, 0};

        // 空闲超时: 300 秒无数据传输则关闭隧道
        constexpr auto idle_timeout = std::chrono::seconds(300);
        auto idle_timer = std::make_shared<net::steady_timer>(co_await net::this_coro::executor);
        std::function<void(const boost::system::error_code &)> idle_handler =
            [inbound, outbound](const boost::system::error_code &ec)
        {
            if (!ec)
            {
                trace::info<flt::conn | flt::protocol>("idle timeout, closing tunnel");
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

        // 取消空闲超时定时器
        idle_timer->cancel();

        const auto end_time = std::chrono::steady_clock::now();
        if (const auto up = total_bytes[0], down = total_bytes[1]; up > 0 || down > 0)
        {
            trace::info<flt::conn | flt::protocol>("Transfer: ↑{} B ↓{} B, {} ms",
                                                        up, down,
                                                        std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());
        }

        // 刷写流量统计并累加账户用量
        if (ctx.worker_ctx.traffic)
        {
            ctx.worker_ctx.traffic->flush_traffic(
                ctx.detected_protocol, total_bytes[0], total_bytes[1]);
        }

        if (ctx.account_lease)
        {
            if (total_bytes[0] > 0)
            {
                account::accumulate_uplink(ctx.account_lease.get(), total_bytes[0]);
            }
            if (total_bytes[1] > 0)
            {
                account::accumulate_downlink(ctx.account_lease.get(), total_bytes[1]);
            }
        }

        shut_close(inbound);
        shut_close(outbound);
    }

} // namespace psm::connect
