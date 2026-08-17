/**
 * @file relay.hpp
 * @brief 双向转发中间件
 * @details 在 inbound 与 outbound 之间建立双向隧道：
 * inbound → outbound（上行）+ outbound → inbound（下行）并发执行。
 * 空闲超时自动关闭，结束时上报流量统计。
 * 对应生产库 net/connection/tunnel/tunnel_relay 的中间件化。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <memory>
#include <string_view>
#include <vector>

#include <common/core/fault/code.hpp>
#include <common/core/fault/handling.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/middleware/pipeline.hpp>
#include <common/core/transmission.hpp>

namespace preview::middleware::builtin
{

    namespace net = boost::asio;

    /**
     * @class relay_middleware
     * @brief 双向转发中间件
     * @details 消费 ctx.inbound（客户端侧）并拨号 outbound（上游侧），
     * 建立双向隧道。outbound 由 dial_middleware 或调用方预置。
     * @note 本中间件为管线终点（handle 后隧道运行至关闭）。
     */
    class relay_middleware final : public middleware
    {
    public:
        /**
         * @brief 构造函数
         * @param outbound 上游传输（已拨号；可为空，由管线前序注入）
         * @param idle_timeout 空闲超时（0 = 禁用）
         */
        explicit relay_middleware(preview::shared_transmission outbound,
                                  std::chrono::milliseconds idle_timeout = std::chrono::seconds(300))
            : outbound_(std::move(outbound)), idle_timeout_(idle_timeout)
        {
        }

        /**
         * @brief 获取中间件名称
         */
        [[nodiscard]] auto name() const -> std::string_view override
        {
            return "relay";
        }

        /**
         * @brief 建立双向隧道并运行至关闭
         * @param inbound 入站传输
         * @param ctx 管线上下文
         * @return 隧道结束码（success = 正常关闭）
         */
        auto handle(preview::shared_transmission &inbound, context &ctx)
            -> net::awaitable<preview::fault::code> override
        {
            // 优先使用管线上下文注入的 outbound（dial 中间件产出）
            auto outbound = outbound_;
            if (ctx.outbound)
            {
                outbound = ctx.outbound;
            }
            if (!inbound || !outbound)
            {
                co_return preview::fault::code::bad_gateway;
            }

            const auto buffer_size = (std::max)(ctx.buffer_size, std::size_t{2});
            auto buffer = std::make_shared<std::vector<std::byte>>(buffer_size);
            std::array<std::size_t, 2> total{0, 0};

            // 空闲超时：ctx.timeout 优先（>0），否则构造参数（0 = 禁用）
            auto effective_timeout = idle_timeout_;
            if (ctx.timeout > std::chrono::milliseconds::zero())
            {
                effective_timeout = ctx.timeout;
            }

            net::steady_timer idle_timer(co_await net::this_coro::executor);
            if (effective_timeout > std::chrono::milliseconds::zero())
            {
                idle_timer.expires_after(effective_timeout);
            }

            // 上行：inbound → outbound
            auto up = [inbound, outbound, buffer, &total, &idle_timer, &effective_timeout]() -> net::awaitable<void>
            {
                std::error_code ec;
                while (true)
                {
                    const auto n = co_await inbound->async_read_some(std::span<std::byte>(*buffer), ec);
                    if (ec || n == 0)
                    {
                        break;
                    }
                    co_await outbound->async_write_some(
                        std::span<const std::byte>(buffer->data(), n), ec);
                    if (ec)
                    {
                        break;
                    }
                    total[0] += n;
                    if (effective_timeout > std::chrono::milliseconds::zero())
                    {
                        idle_timer.expires_after(effective_timeout);
                    }
                }
            };

            // 下行：outbound → inbound
            auto down = [inbound, outbound, buffer, &total, &idle_timer, &effective_timeout]() -> net::awaitable<void>
            {
                std::error_code ec;
                while (true)
                {
                    const auto n = co_await outbound->async_read_some(std::span<std::byte>(*buffer), ec);
                    if (ec || n == 0)
                    {
                        break;
                    }
                    co_await inbound->async_write_some(std::span<const std::byte>(buffer->data(), n), ec);
                    if (ec)
                    {
                        break;
                    }
                    total[1] += n;
                    if (effective_timeout > std::chrono::milliseconds::zero())
                    {
                        idle_timer.expires_after(effective_timeout);
                    }
                }
            };

            // 空闲超时循环：被转发活动重置（aborted）继续等待，到期关闭两端
            auto idle_loop = [&]() -> net::awaitable<void>
            {
                if (effective_timeout <= std::chrono::milliseconds::zero())
                {
                    // 禁用超时：超长 timer 挂起（不占 socket 读，避免与 up/down 竞争吞数据）
                    net::steady_timer hold(co_await net::this_coro::executor);
                    hold.expires_after(std::chrono::hours(24));
                    boost::system::error_code ec;
                    co_await hold.async_wait(net::redirect_error(net::use_awaitable, ec));
                    co_return;
                }
                while (true)
                {
                    boost::system::error_code ec;
                    co_await idle_timer.async_wait(net::redirect_error(net::use_awaitable, ec));
                    if (ec == net::error::operation_aborted)
                    {
                        continue; // 被转发活动重置
                    }
                    inbound->close();
                    outbound->close();
                    co_return;
                }
            };

            using boost::asio::experimental::awaitable_operators::operator||;
            co_await (up() || down() || idle_loop());

            if (ctx.traffic)
            {
                ctx.traffic->report(ctx.identity, total[0], total[1]);
            }
            co_return preview::fault::code::success;
        }

    private:
        preview::shared_transmission outbound_; ///< 上游传输
        std::chrono::milliseconds idle_timeout_;       ///< 空闲超时
    };

} // namespace preview::middleware::builtin
