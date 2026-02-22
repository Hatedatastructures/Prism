/**
 * @file websocket.hpp
 * @brief WebSocket 处理器模块
 * @details 高性能 WebSocket 处理，支持实时统计推送。
 *
 * 核心特性：
 * - 实时推送：每 100ms 推送一次统计快照
 * - 零拷贝：使用 string_view 和移动语义
 * - 协程优先：所有异步操作使用 co_await
 *
 * @note 设计原则：
 * - 高性能：零拷贝 + 移动语义
 * - 协程优先：严禁回调函数
 * - 低延迟：定时器实现低延迟推送
 */

#pragma once

#include <string>
#include <chrono>
#include <utility>
#include <vector>

#include "statistics.hpp"

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/websocket.hpp>

#include <forward-engine/protocol/http.hpp>
#include <forward-engine/protocol/http/serialization.hpp>
#include <forward-engine/transformer/json.hpp>
#include <forward-engine/trace.hpp>
#include <forward-engine/memory.hpp>

namespace srv::websocket
{
    namespace net = boost::asio;
    namespace beast = boost::beast;
    namespace websocket = boost::beast::websocket;

    using namespace srv::statistics;
    using namespace ngx::protocol::http;
    using namespace ngx::transformer::json;

    /**
     * @class stats_handler
     * @brief WebSocket 统计处理器
     * @details 高性能 WebSocket 处理，定期推送统计快照
     */
    class stats_handler final
    {
    public:
        using stream_type = websocket::stream<beast::tcp_stream>;

        /**
         * @brief 构造函数
         * @param ws WebSocket 流
         * @param stats 统计数据引用
         */
        stats_handler(stream_type &&ws, detailed_stats &stats) noexcept
            : ws_(std::move(ws)), stats_(stats), timer_(ws_.get_executor())
        {
        }

        /**
         * @brief 处理 WebSocket 连接（使用已解析的请求）
         * @param req 已解析的 HTTP 升级请求
         */
        net::awaitable<void> handle_connection(const request &req)
        {
            beast::error_code ec;

            // 将请求序列化为原始字节，传递给 async_accept
            // 因为 Boost.Beast WebSocket 需要重新读取握手数据
            auto *pool = ngx::memory::system::thread_local_pool();
            const auto raw_request = serialize(req, pool);

            // WebSocket 握手 - 使用预读取的请求字节
            co_await ws_.async_accept(
                net::buffer(raw_request.data(), raw_request.size()),
                net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                ngx::trace::warn("WebSocket握手失败: {}", ec.message());
                co_return;
            }

            ws_.binary(false);

            // 推送循环
            while (true)
            {
                // 创建统计快照
                const auto snapshot = create_snapshot(stats_);

                // 序列化为 JSON
                auto json_buffer = serialize(snapshot);

                // 发送数据
                co_await ws_.async_write(
                    net::buffer(json_buffer),
                    net::redirect_error(net::use_awaitable, ec));

                if (ec)
                {
                    break;
                }

                // 等待 100ms
                timer_.expires_after(std::chrono::milliseconds(100));
                co_await timer_.async_wait(net::redirect_error(net::use_awaitable, ec));

                if (ec)
                {
                    break;
                }
            }

            // 优雅关闭
            co_await ws_.async_close(
                websocket::close_code::normal,
                net::redirect_error(net::use_awaitable, ec));
        }

    private:
        stream_type ws_;
        detailed_stats &stats_;
        net::steady_timer timer_;
    };

    /**
     * @brief 处理 WebSocket 连接
     * @tparam WebSocketStream WebSocket 流类型
     * @param ws WebSocket 流
     * @param req 已解析的 HTTP 升级请求
     * @param stats 统计数据
     */
    template <typename WebSocketStream>
    net::awaitable<void> handle_websocket(WebSocketStream &&ws, const request &req, detailed_stats &stats)
    {
        stats_handler handler(std::move(ws), stats);
        co_await handler.handle_connection(req);
    }
}
