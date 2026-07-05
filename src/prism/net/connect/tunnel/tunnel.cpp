#include <prism/net/connect/tunnel/tunnel.hpp>

#include <prism/account/entry.hpp>
#include <prism/net/connect/util.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/foundation/memory/pool.hpp>
#include <prism/account/stats/traffic.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/pad.hpp>
#include <prism/net/transport/transmission.hpp>

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

        // 单向转发循环：从 from 持续读取数据写入 to
        // 支持 complete（全量写）和 partial（可能分片写）两种策略
        // 每次成功读写后重置空闲定时器，超时则双向关闭
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

            std::error_code ec;
            while (true)
            {
                const auto transferred = co_await opts.from->async_read_some(opts.scratch, ec);
                if (ec || transferred == 0)
                {
                    co_return;
                }

                opts.total_bytes[opts.idx] += transferred;

                // 重置空闲超时
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
                    // partial 策略：TCP async_write_some 可能只写入部分数据，
                    // 需要循环直到所有数据写完或出错
                    auto remaining = data;
                    while (!remaining.empty())
                    {
                        written = co_await opts.to->async_write_some(remaining, ec);
                        if (ec)
                        {
                            co_return;
                        }
                        if (written == 0)
                        {
                            co_return;
                        }
                        remaining = remaining.subspan(written);
                    }
                    written = transferred;
                }

                if (ec || (opts.policy == write_policy::complete && written < transferred))
                {
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
        const auto policy = opts.policy;

        // 如果配置了填充,包装 inbound（仅影响下载方向 server→client 的 TLS 记录大小分布）
        if (opts.pad_cfg && opts.pad_cfg->enabled())
        {
            inbound = std::make_shared<transport::pad_transport>(inbound, *opts.pad_cfg);
        }
        const auto start_time = std::chrono::steady_clock::now();

        auto *mr = memory::system::local_pool();
        const auto array_size = (std::max)(opts.buffer_size, 2U);
        memory::vector<std::byte> buffer(array_size, memory::effective_mr(mr));
        // PMR 缓冲区一次性分配，按半切分为两个独立 span
        // 左半给上行（client→upstream），右半给下行（upstream→client）
        // 避免两个方向的转发循环各自分配内存
        const auto half = buffer.size() / 2;
        const auto left = std::span(buffer).first(half);
        const auto right = std::span(buffer).last(half);

        std::array<std::size_t, 2> total_bytes{0, 0};

        // 空闲超时: 300 秒无数据传输则关闭隧道
        constexpr auto idle_timeout = std::chrono::seconds(300);
        auto idle_timer = std::make_shared<net::steady_timer>(co_await net::this_coro::executor);
        // idle_handler lambda 按值捕获 inbound/outbound（shared_ptr），
        // 确保定时器回调触发时传输对象仍然存活，可安全调用 cancel()
        std::function<void(const boost::system::error_code &)> idle_handler =
            [inbound, outbound, trace = opts.trace](const boost::system::error_code &ec)
        {
            if (!ec)
            {
                trace::info<flt::conn | flt::protocol>(trace, "idle timeout, closing tunnel");
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
            trace::info<flt::conn | flt::protocol>(opts.trace, "Transfer: up={}B down={}B, {}ms",
                                                        up, down,
                                                        std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());
        }

        // 刷写流量统计并累加账户用量
        if (opts.traffic)
        {
            opts.traffic->flush_traffic(
                opts.detected, total_bytes[0], total_bytes[1]);
        }

        if (opts.lease)
        {
            if (total_bytes[0] > 0)
            {
                account::accumulate_uplink(opts.lease->get(), total_bytes[0]);
            }
            if (total_bytes[1] > 0)
            {
                account::accumulate_downlink(opts.lease->get(), total_bytes[1]);
            }
        }

        shut_close(inbound);
        shut_close(outbound);
    }

} // namespace psm::connect
