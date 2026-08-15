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
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/steady_timer.hpp>

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

namespace psmtest::middleware::builtin
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
        explicit relay_middleware(psmtest::shared_transmission outbound,
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
        auto handle(psmtest::shared_transmission &inbound, context &ctx)
            -> net::awaitable<psmtest::fault::code> override
        {
            // 优先使用管线上下文注入的 outbound（dial 中间件产出）
            auto outbound = ctx.outbound ? ctx.outbound : outbound_;
            if (!inbound || !outbound)
            {
                co_return psmtest::fault::code::bad_gateway;
            }

            const auto buffer_size = (std::max)(ctx.buffer_size, std::size_t{2});
            auto buffer = std::make_shared<std::vector<std::byte>>(buffer_size);
            std::array<std::size_t, 2> total{0, 0};

            net::steady_timer idle_timer(co_await net::this_coro::executor);
            if (idle_timeout_ > std::chrono::milliseconds::zero())
            {
                idle_timer.expires_after(idle_timeout_);
            }

            // 上行：inbound → outbound
            auto up = [inbound, outbound, buffer, &total]() -> net::awaitable<void>
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
                }
            };

            // 下行：outbound → inbound
            auto down = [inbound, outbound, buffer, &total]() -> net::awaitable<void>
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
                }
            };

            using boost::asio::experimental::awaitable_operators::operator||;
            co_await (up() || down());

            if (ctx.traffic)
            {
                ctx.traffic->report(ctx.identity, total[0], total[1]);
            }
            co_return psmtest::fault::code::success;
        }

    private:
        psmtest::shared_transmission outbound_; ///< 上游传输
        std::chrono::milliseconds idle_timeout_;       ///< 空闲超时
    };

} // namespace psmtest::middleware::builtin
