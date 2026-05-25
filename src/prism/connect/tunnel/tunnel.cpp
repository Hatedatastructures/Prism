#include <prism/connect/tunnel/tunnel.hpp>
#include <prism/connect/util.hpp>
#include <prism/memory/container.hpp>
#include <prism/memory/pool.hpp>
#include <prism/trace.hpp>
#include <prism/transport/transmission.hpp>
#include <prism/account/entry.hpp>
#include <prism/stats/traffic.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <array>
#include <chrono>

constexpr std::string_view TunnelStr = "[Connect.Tunnel]";

namespace psm::connect
{
    namespace
    {
        /** @brief 转发中继共享状态 */
        struct relay_state
        {
            write_policy policy;
            std::array<std::size_t, 2> &total_bytes;
            std::shared_ptr<net::steady_timer> &idle_timer;
            std::function<void(const boost::system::error_code &)> &idle_handler;
            std::chrono::seconds idle_timeout;
        };

        /** @brief 单向转发循环，从 from 读取数据写入 to */
        auto relay_loop(relay_state state, const shared_transmission &from,
                        const shared_transmission &to, std::span<std::byte> scratch, std::size_t idx)
            -> net::awaitable<void>
        {
            const bool is_download = (idx == 1);
            trace::debug("{} forward[{}]: started, policy={}",
                        TunnelStr, is_download ? "download" : "upload",
                        state.policy == write_policy::complete ? "complete" : "partial");

            std::error_code ec;
            while (true)
            {
                const auto transferred = co_await from->async_read_some(scratch, ec);
                if (ec || transferred == 0)
                {
                    trace::debug("{} forward[{}]: read done, transferred={}, ec={}",
                                TunnelStr, is_download ? "download" : "upload", transferred, ec.message());
                    co_return;
                }

                state.total_bytes[idx] += transferred;
                trace::debug("{} forward[{}]: read {} bytes, total now {}",
                            TunnelStr, is_download ? "download" : "upload", transferred, state.total_bytes[idx]);

                // 重置空闲超时
                state.idle_timer->expires_after(state.idle_timeout);
                state.idle_timer->async_wait(state.idle_handler);

                const auto data = scratch.first(transferred);
                std::size_t written;
                if (state.policy == write_policy::complete)
                {
                    trace::debug("{} forward[{}]: calling async_write({} bytes)",
                                TunnelStr, is_download ? "download" : "upload", data.size());
                    written = co_await transport::async_write(*to, data, ec);
                    trace::debug("{} forward[{}]: async_write returned written={}, ec={}",
                                TunnelStr, is_download ? "download" : "upload", written, ec.message());
                }
                else
                {
                    written = co_await to->async_write_some(data, ec);
                }

                if (ec || (state.policy == write_policy::complete && written < transferred))
                {
                    trace::debug("{} forward[{}]: write done/failed, written={}, expected={}",
                                TunnelStr, is_download ? "download" : "upload", written, transferred);
                    co_return;
                }

                // 重置空闲超时
                state.idle_timer->expires_after(state.idle_timeout);
                state.idle_timer->async_wait(state.idle_handler);
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

        auto *mr = memory::system::thread_local_pool();
        const auto array_size = (std::max)(ctx.buffer_size, 2U);
        memory::vector<std::byte> buffer(array_size, mr ? mr : memory::current_resource());
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
                trace::info("{} idle timeout, closing tunnel", TunnelStr);
                inbound->cancel();
                outbound->cancel();
            }
        };
        idle_timer->expires_after(idle_timeout);
        idle_timer->async_wait(idle_handler);

        relay_state state{policy, total_bytes, idle_timer, idle_handler, idle_timeout};

        using namespace boost::asio::experimental::awaitable_operators;
        co_await (relay_loop(state, inbound, outbound, left, 0) || relay_loop(state, outbound, inbound, right, 1));

        // 取消空闲超时定时器
        idle_timer->cancel();

        const auto end_time = std::chrono::steady_clock::now();
        if (const auto up = total_bytes[0], down = total_bytes[1]; up > 0 || down > 0)
        {
            trace::info("{} [{}] Transfer: Upload {} B, Download {} B, duration: {} ms", TunnelStr, ctx.session_id, up,
                        down, std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());
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
