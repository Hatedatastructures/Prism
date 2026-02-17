/**
 * @file handler.hpp
 * @brief WebSocket 处理器定义
 * @details 处理 WebSocket 连接，定期推送统计快照到客户端。
 *
 * 核心特性：
 * - 实时推送：每 100ms 推送一次统计快照
 * - JSON 序列化：使用 glaze 库进行 JSON 序列化
 * - 优雅关闭：支持正常关闭 WebSocket 连接
 *
 * @note 设计原则：
 * - 异步处理：使用协程风格异步处理
 * - 错误处理：完善的异常处理
 * - 低延迟：使用定时器实现低延迟推送
 *
 */
#pragma once

#include <string>
#include <chrono>
#include <iostream>

#include "../stats/metrics.hpp"
#include "../stats/snapshot.hpp"
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/websocket.hpp>
#include <forward-engine/transformer/json.hpp>
#include <glaze/glaze.hpp>

namespace srv::websocket
{
    using namespace srv::stats;
    using namespace ngx::transformer::json;

    class stats_websocket_handler final
    {
    public:
        using websocket_stream_type = boost::beast::websocket::stream<boost::beast::tcp_stream>;

        stats_websocket_handler(websocket_stream_type &&ws, detailed_stats &stats) noexcept
            : ws_(std::move(ws)), stats_(stats), timer_(ws_.get_executor())
        {
        }

        boost::asio::awaitable<void> handle_connection()
        {
            try
            {
                boost::beast::error_code ec;
                co_await ws_.async_accept(boost::asio::redirect_error(boost::asio::use_awaitable, ec));

                if (ec)
                {
                    std::cout << "WebSocket握手失败: " << ec.message() << std::endl;
                    co_return;
                }

                ws_.binary(false);

                while (true)
                {
                    const auto snapshot = create_snapshot(stats_);

                    auto json_buffer = serialize(snapshot);

                    co_await ws_.async_write(
                        boost::asio::buffer(json_buffer), boost::asio::redirect_error(boost::asio::use_awaitable, ec));

                    if (ec)
                    {
                        break;
                    }

                    timer_.expires_after(std::chrono::milliseconds(100));
                    co_await timer_.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, ec));

                    if (ec)
                    {
                        break;
                    }
                }
            }
            catch (const std::exception &e)
            {
                std::cout << "WebSocket异常: " << e.what() << std::endl;
            }

            try
            {
                boost::beast::error_code ec;
                co_await ws_.async_close(
                    boost::beast::websocket::close_code::normal, boost::asio::redirect_error(boost::asio::use_awaitable, ec));

                if (ec)
                {
                    std::cout << "WebSocket关闭失败: " << ec.message() << std::endl;
                }
            }
            catch (...)
            {
            }
        }

    private:
        websocket_stream_type ws_;
        detailed_stats &stats_;
        boost::asio::steady_timer timer_;
    };

    template <typename WebSocketStream>
    boost::asio::awaitable<void> handle_websocket_connection(WebSocketStream &&ws, detailed_stats &stats)
    {
        stats_websocket_handler handler(std::move(ws), stats);
        co_await handler.handle_connection();
    }
}
