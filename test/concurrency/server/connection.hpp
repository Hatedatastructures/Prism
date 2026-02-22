/**
 * @file connection.hpp
 * @brief HTTP 连接处理模块
 * @details 基于 beast::tcp_stream，提供高性能零拷贝 HTTP 连接处理。
 *
 * 核心特性：
 * - 传输层：使用 beast::tcp_stream
 * - 零拷贝：使用 string_view 和内存池避免数据拷贝
 * - 协程优先：所有异步操作使用 co_await
 * - 内存池化：使用 ngx::memory::frame_arena 管理请求内存
 *
 * @note 设计原则：
 * - 高性能：零拷贝 + 内存池 + 无锁
 * - 协程优先：严禁回调函数
 *
 * @see dualport.hpp
 */

#pragma once

#include <chrono>
#include <string>
#include <string_view>
#include <array>
#include <span>
#include <utility>

#include "routing.hpp"
#include "processor.hpp"
#include "websocket.hpp"
#include "socket.hpp"
#include "statistics.hpp"

#include <boost/asio.hpp>
#include <boost/beast.hpp>

#include <forward-engine/protocol/http.hpp>
#include <forward-engine/protocol/http/deserialization.hpp>
#include <forward-engine/protocol/http/serialization.hpp>
#include <forward-engine/gist/code.hpp>
#include <forward-engine/memory.hpp>
#include <forward-engine/memory/pool.hpp>
#include <forward-engine/trace.hpp>
#include <forward-engine/transformer/json.hpp>

namespace srv::connection
{
    namespace net = boost::asio;
    namespace beast = boost::beast;

    using namespace srv::routing;
    using namespace srv::processor;
    using namespace srv::processor::main_api;
    using namespace srv::processor::stats_api;
    using namespace srv::websocket;
    using namespace srv::statistics;
    using namespace srv::socket;
    using namespace ngx::protocol::http;
    using namespace ngx::gist;
    using namespace ngx::transformer::json;

    /**
     * @brief 安全的字符串转整数函数
     */
    template <typename IntType = int>
    [[nodiscard]] IntType safe_parse_int(std::string_view str, IntType default_value = IntType{}) noexcept
    {
        if (str.empty())
        {
            return default_value;
        }

        IntType result{};
        const auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), result);

        if (ec == std::errc{} && ptr == str.data() + str.size())
        {
            return result;
        }
        return default_value;
    }

    /**
     * @brief 关闭传输层资源
     */
    template <typename Stream>
    inline void shut_close(Stream &stream)
    {
        stream.close();
    }

    /**
     * @brief 处理主端口连接
     */
    auto do_main(tcp_wrapper stream, detailed_stats &stats, const static_handler &file_handler,
                 const main_router &router, std::size_t conn_index)
        -> net::awaitable<void>
    {
        stats.add_connection();

        // 设置 TCP 选项
        stream.set_option(net::ip::tcp::no_delay(true));
        stream.set_option(net::ip::tcp::socket::send_buffer_size(256 * 1024));
        stream.set_option(net::ip::tcp::socket::receive_buffer_size(256 * 1024));

        // 获取内存池
        auto *pool = ngx::memory::system::thread_local_pool();

        // 缓冲区 - 必须在循环外部，保持持久化
        beast::flat_buffer buffer;

        // 请求处理循环
        while (true)
        {
            // HTTP 请求对象
            request req(pool);

            // 设置读取超时
            stream.expires_after(std::chrono::seconds(30));

            // 读取 HTTP 请求 - 使用 stream 和 buffer
            const auto read_result = co_await async_read(stream, req, buffer, pool);

            if (read_result != code::success)
            {
                if (read_result == code::eof)
                {
                    ngx::trace::debug("主端口: 客户端关闭连接 (EOF)");
                }
                else
                {
                    // keep-alive 超时或连接重置是正常现象
                    ngx::trace::debug("主端口: 连接关闭 ({})", describe(read_result));
                }
                break;
            }

            stats.increment_requests();
            stats.add_bytes_received(req.body().size());

            const auto start_time = std::chrono::steady_clock::now();
            const auto method_str = req.method_string();
            stats.record_method(method_str);

            // 响应对象 - 使用帧内存池
            ngx::memory::frame_arena resp_arena;
            response resp(resp_arena.get());

            const std::string_view target = req.target();
            const auto route = router.match(target);

            // 根据 HTTP 版本和 Connection 头决定是否保持连接
            // HTTP/1.1 默认 keep-alive，HTTP/1.0 默认 close
            const auto connection_header = req.at(field::connection);
            const bool is_http_11 = (req.version() == 11);
            bool keep_alive = is_http_11;
            if (connection_header == "close")
            {
                keep_alive = false;
            }
            else if (connection_header == "keep-alive")
            {
                keep_alive = true;
            }

            // 更新连接统计
            if (conn_index < detailed_stats::MAX_CONNECTIONS)
            {
                stats.active_connection_list[conn_index].request_path = std::string(target);
                stats.increment_connection_request_count(conn_index);
                stats.touch_connection(conn_index);
            }

            // 路由处理
            if (route.type == route_type::api_endpoint)
            {
                stats.increment_api_requests();

                if (target == "/api/login")
                {
                    co_await login(resp, stats);
                }
                else if (target == "/api/register")
                {
                    co_await register_user(resp, stats);
                }
                else if (target == "/api/captcha/send")
                {
                    co_await send_captcha(resp, stats);
                }
                else if (target == "/api/products")
                {
                    co_await get_products(req, resp, stats);
                }
                else if (target.starts_with("/api/product/"))
                {
                    co_await get_product_detail(req, resp, stats, route.param);
                }
                else if (target == "/api/cart")
                {
                    co_await cart_operations(req, resp, stats);
                }
                else if (target == "/api/cart/item")
                {
                    const auto method = req.method();
                    if (method == verb::put)
                    {
                        co_await update_cart_item(resp, stats);
                    }
                    else if (method == verb::delete_)
                    {
                        co_await delete_cart_item(resp, stats);
                    }
                    else
                    {
                        resp.status(status::method_not_allowed);
                        resp.set(field::content_type, "application/json");
                        resp.set(field::server, "ForwardEngine/1.0");
                        resp.content_length(30);
                        resp.body(R"({"error":"Method Not Allowed"})");
                        stats.record_status_code(405);
                    }
                }
                else if (target == "/api/cart/items")
                {
                    co_await delete_cart_items(resp, stats);
                }
                else if (target == "/api/cart/checkout")
                {
                    co_await cart_checkout(resp, stats);
                }
                else if (target == "/api/search")
                {
                    co_await search_products(req, resp, stats);
                }
                else if (target == "/api/user")
                {
                    constexpr std::string_view user_body = R"({"id":"user001","name":"用户001","email":"user@example.com","avatar":"/images/avatar.jpg"})";
                    resp.status(status::ok);
                    resp.set(field::content_type, "application/json");
                    resp.set(field::server, "ForwardEngine/1.0");
                    resp.content_length(user_body.size());
                    resp.body(user_body);
                    stats.record_status_code(200);
                }
                else if (target == "/api/orders")
                {
                    co_await create_order(resp, stats);
                }
                else
                {
                    resp.status(status::not_found);
                    resp.set(field::content_type, "application/json");
                    resp.set(field::server, "ForwardEngine/1.0");
                    resp.content_length(58);
                    resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
                    stats.increment_not_found();
                    stats.record_status_code(404);
                }
            }
            else
            {
                // 静态文件服务
                if (file_handler.serve_file(route.path, resp, stats))
                {
                    resp.set(field::server, "ForwardEngine/1.0");
                    stats.record_status_code(200);
                }
                else
                {
                    resp.status(status::not_found);
                    resp.set(field::content_type, "text/html");
                    resp.set(field::server, "ForwardEngine/1.0");
                    resp.content_length(97);
                    resp.body(R"(<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>)");
                    stats.increment_not_found();
                    stats.record_status_code(404);
                }
            }

            // 记录请求时间
            const auto end_time = std::chrono::steady_clock::now();
            const auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
            stats.record_request_time(duration_ns);

            resp.keep_alive(keep_alive);

            // 序列化响应 - 使用内存池
            const auto serialized = serialize(resp, pool);

            // 设置写入超时
            stream.expires_after(std::chrono::seconds(120));

            // 写入响应
            boost::system::error_code write_ec;
            co_await net::async_write(
                stream,
                net::buffer(serialized.data(), serialized.size()),
                net::redirect_error(net::use_awaitable, write_ec));

            if (write_ec)
            {
                stats.increment_errors();
                break;
            }

            stats.add_bytes_sent(serialized.size());

            if (!keep_alive)
            {
                break;
            }
        }

        stream.close();
        stats.remove_connection();
    }

    /**
     * @brief 处理统计端口连接
     */
    net::awaitable<void> do_dashboard(tcp_wrapper stream, detailed_stats &stats,
                                      const static_handler &file_handler,
                                      const stats_router &router, std::size_t conn_index)
    {
        stats.add_connection();

        // 设置 TCP 选项
        stream.set_option(net::ip::tcp::no_delay(true));
        stream.set_option(net::ip::tcp::socket::send_buffer_size(256 * 1024));
        stream.set_option(net::ip::tcp::socket::receive_buffer_size(256 * 1024));

        // 获取内存池
        auto *pool = ngx::memory::system::thread_local_pool();

        // 缓冲区 - 必须在循环外部，保持持久化
        beast::flat_buffer buffer;

        // 请求处理循环
        while (true)
        {
            // HTTP 请求对象
            request req(pool);

            // 设置读取超时
            stream.expires_after(std::chrono::seconds(30));

            // 读取 HTTP 请求 - 使用 stream 和 buffer
            const auto read_result = co_await async_read(stream, req, buffer, pool);

            if (read_result != code::success)
            {
                if (read_result == code::eof)
                {
                    ngx::trace::debug("[统计端口] 客户端关闭连接 (EOF)");
                }
                else
                {
                    // keep-alive 超时或连接重置是正常现象
                    ngx::trace::debug("[统计端口] 连接关闭 ({})", describe(read_result));
                }
                break;
            }

            stats.increment_requests();
            stats.add_bytes_received(req.body().size());

            const auto start_time = std::chrono::steady_clock::now();
            const auto method_str = req.method_string();
            stats.record_method(method_str);

            const std::string_view target = req.target();
            const auto route = router.match(target);

            // 根据 HTTP 版本和 Connection 头决定是否保持连接
            // HTTP/1.1 默认 keep-alive，HTTP/1.0 默认 close
            const auto connection_header = req.at(field::connection);
            const bool is_http_11 = (req.version() == 11);
            bool keep_alive = is_http_11;
            if (connection_header == "close")
            {
                keep_alive = false;
            }
            else if (connection_header == "keep-alive")
            {
                keep_alive = true;
            }

            // 更新连接统计
            if (conn_index < detailed_stats::MAX_CONNECTIONS)
            {
                stats.active_connection_list[conn_index].request_path = std::string(target);
                stats.increment_connection_request_count(conn_index);
                stats.touch_connection(conn_index);
            }

            // WebSocket 升级处理
            if (route.type == route_type::websocket_endpoint)
            {
                // 释放 tcp_stream 并创建 WebSocket 流
                beast::websocket::stream<beast::tcp_stream> ws(stream.release());
                // 传递已解析的 HTTP 请求给 WebSocket 处理器
                co_await handle_websocket(std::move(ws), req, stats);
                stats.remove_connection();
                co_return;
            }

            // API 端点处理
            if (route.type == route_type::api_endpoint)
            {
                stats.increment_api_requests();

                ngx::memory::frame_arena resp_arena;
                response resp(resp_arena.get());

                if (target == "/api/stats")
                {
                    co_await get_stats(resp, stats);
                }
                else if (target == "/api/stats/realtime")
                {
                    co_await get_stats(resp, stats);
                }
                else if (target.starts_with("/api/stats/history/"))
                {
                    std::uint32_t minutes = 60;
                    if (route.param.size() > 0)
                    {
                        minutes = safe_parse_int<std::uint32_t>(route.param, 60);
                    }
                    co_await get_traffic_history(resp, stats, minutes);
                }
                else if (target == "/api/connections" || target == "/api/connections/active")
                {
                    co_await get_active_connections(resp, stats);
                }
                else if (target == "/api/performance")
                {
                    co_await get_performance(resp, stats);
                }
                else
                {
                    resp.status(status::not_found);
                    resp.set(field::content_type, "application/json");
                    resp.set(field::server, "ForwardEngine/1.0");
                    resp.content_length(64);
                    resp.body(R"({"error":"Not Found","message":"Stats API endpoint not found"})");
                    stats.increment_not_found();
                    stats.record_status_code(404);
                }

                const auto end_time = std::chrono::steady_clock::now();
                const auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
                stats.record_request_time(duration_ns);

                resp.keep_alive(keep_alive);

                const auto serialized = serialize(resp, pool);

                // 设置写入超时
                stream.expires_after(std::chrono::seconds(120));

                boost::system::error_code write_ec;
                co_await net::async_write(
                    stream,
                    net::buffer(serialized.data(), serialized.size()),
                    net::redirect_error(net::use_awaitable, write_ec));

                if (write_ec)
                {
                    stats.increment_errors();
                    break;
                }

                stats.add_bytes_sent(serialized.size());

                if (!keep_alive)
                {
                    break;
                }
            }
            else
            {
                // 静态文件服务
                ngx::memory::frame_arena resp_arena;
                response resp(resp_arena.get());

                if (file_handler.serve_file(route.path, resp, stats))
                {
                    resp.set(field::server, "ForwardEngine/1.0");
                    stats.record_status_code(200);
                }
                else
                {
                    resp.status(status::not_found);
                    resp.set(field::content_type, "text/html");
                    resp.set(field::server, "ForwardEngine/1.0");
                    resp.content_length(97);
                    resp.body(R"(<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>)");
                    stats.increment_not_found();
                    stats.record_status_code(404);
                }

                const auto end_time = std::chrono::steady_clock::now();
                const auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
                stats.record_request_time(duration_ns);

                resp.keep_alive(keep_alive);

                const auto serialized = serialize(resp, pool);

                // 设置写入超时
                stream.expires_after(std::chrono::seconds(120));

                boost::system::error_code write_ec;
                co_await net::async_write(
                    stream,
                    net::buffer(serialized.data(), serialized.size()),
                    net::redirect_error(net::use_awaitable, write_ec));

                if (write_ec)
                {
                    stats.increment_errors();
                    break;
                }

                stats.add_bytes_sent(serialized.size());

                if (!keep_alive)
                {
                    break;
                }
            }
        }

        stream.close();
        stats.remove_connection();
    }
}
