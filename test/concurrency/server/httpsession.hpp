/**
 * @file httpsession.hpp
 * @brief HTTP 会话处理模块
 * @details 处理 HTTP/HTTPS 会话，包括请求解析、路由匹配、响应构建等。
 *
 * 核心特性：
 * - 异步处理：使用协程风格异步处理
 * - Keep-Alive 支持：支持 HTTP Keep-Alive 连接
 * - 协议检测：自动检测 HTTP/HTTPS 协议
 * - 统计记录：记录请求时间、状态码、方法等统计信息
 *
 * @note 设计原则：
 * - 模板化：支持 TCP 和 SSL 流
 * - 零拷贝：尽可能避免数据拷贝
 * - 错误处理：完善的异常处理
 *
 * @see dualport.hpp
 */
#pragma once

#include <chrono>
#include <string>
#include <string_view>
#include <array>

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
#include <glaze/glaze.hpp>

namespace srv::httpsession
{
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
     * @tparam IntType 整数类型
     * @param str 输入字符串
     * @param default_value 解析失败时的默认值
     * @return 解析结果或默认值
     * @note 不会抛出异常，使用 std::from_chars 进行安全解析
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
     * @enum protocol
     * @brief 检测到的协议类型
     */
    enum class protocol
    {
        http,
        https,
        unknown
    };

    /**
     * @struct protocol_detect_result
     * @brief 协议检测结果结构体
     * @details 包含检测到的协议类型和预读取的数据，用于协议自动检测
     */
    struct protocol_detect_result final
    {
        /// @brief 检测到的协议类型（HTTP、HTTPS 或未知）
        protocol detected_protocol{protocol::unknown};
        /// @brief 预读取的数据（最多 3 字节），需在后续处理中使用
        std::array<std::byte, 3> peek_data{};
        /// @brief 实际读取的字节数
        std::size_t bytes_read{0};
    };

    /**
     * @brief 检测协议类型（带数据保存）
     * @param socket TCP socket
     * @return 协议检测结果（包含协议类型和预读取的数据）
     * @note 此函数会读取 3 字节数据，调用者需要将 peek_data 放入 buffer 中供后续使用
     * @warning 预读取的数据必须被后续的读取操作使用，否则数据会丢失
     */
    [[nodiscard]] inline auto detect_protocol(boost::asio::ip::tcp::socket &socket)
        -> boost::asio::awaitable<protocol_detect_result>
    {
        protocol_detect_result result;

        boost::beast::error_code ec;
        auto token = boost::asio::redirect_error(boost::asio::use_awaitable, ec);
        const std::size_t n = co_await socket.async_read_some(boost::asio::buffer(result.peek_data), token);

        result.bytes_read = n;

        if (ec || n < 3)
        {
            co_return result;
        }

        const std::uint8_t byte0 = static_cast<std::uint8_t>(result.peek_data[0]);
        const std::uint8_t byte1 = static_cast<std::uint8_t>(result.peek_data[1]);
        const std::uint8_t byte2 = static_cast<std::uint8_t>(result.peek_data[2]);

        if (byte0 == 0x16 && byte1 == 0x03 && (byte2 == 0x00 || byte2 == 0x01 || byte2 == 0x02 || byte2 == 0x03))
        {
            result.detected_protocol = protocol::https;
            co_return result;
        }

        const std::string_view method_str(reinterpret_cast<const char *>(result.peek_data.data()), 3);

        if (method_str == "GET" || method_str == "POS" || method_str == "PUT" || method_str == "HEA" ||
            method_str == "DEL" || method_str == "OPT" || method_str == "CON" || method_str == "TRA")
        {
            result.detected_protocol = protocol::http;
            co_return result;
        }
        result.detected_protocol = protocol::http;
        co_return result;
    }

    /**
     * @brief 处理主端口会话
     * @tparam Stream 流类型（tcp_wrapper 或 ssl_wrapper）
     * @param stream 网络流对象（TCP 或 SSL 包装器）
     * @param stats 服务器统计数据引用，用于记录请求统计
     * @param file_handler 静态文件处理器，用于服务静态文件
     * @param router 主端口路由器，用于匹配请求路径到处理器
     * @param conn_index 连接在活动连接列表中的索引
     * @return 协程任务
     */
    template <typename Stream>
    auto do_main_session(Stream &&stream, detailed_stats &stats, const static_handler &file_handler,
                         const main_router &router, std::size_t conn_index)
        -> boost::asio::awaitable<void>
    {
        stats.add_connection();

        boost::beast::flat_buffer buffer;
        boost::system::error_code ec;

        if constexpr (std::is_same_v<std::decay_t<Stream>, ssl_wrapper>)
        {
            co_await stream.native_handle().async_handshake(
                boost::asio::ssl::stream_base::server, boost::asio::redirect_error(boost::asio::use_awaitable, ec));

            if (ec)
            {
                ngx::trace::error("TLS握手失败: {}", ec.message());
                stats.remove_connection();
                co_return;
            }
        }

        stream.set_option(boost::asio::ip::tcp::no_delay(true));
        stream.set_option(boost::asio::ip::tcp::socket::send_buffer_size(256 * 1024));
        stream.set_option(boost::asio::ip::tcp::socket::receive_buffer_size(256 * 1024));

        auto *pool = ngx::memory::system::thread_local_pool();

        while (true)
        {
            ngx::memory::frame_arena arena;
            ngx::protocol::http::request req(arena.get());

            stream.expires_after(std::chrono::seconds(30));

            const auto read_result = co_await ngx::protocol::http::async_read(stream, req, buffer, pool);

            if (read_result != ngx::gist::code::success)
            {
                if (read_result == ngx::gist::code::eof)
                {
                    break;
                }
                ngx::trace::error("主端口读取请求失败: {} ({})", ngx::gist::describe(read_result), static_cast<int>(read_result));
                stats.increment_errors();
                break;
            }

            stats.increment_requests();
            stats.add_bytes_received(req.body().size());

            const auto start_time = std::chrono::steady_clock::now();
            const auto method_str = req.method_string();
            stats.record_method(method_str);

            ngx::memory::frame_arena resp_arena;
            ngx::protocol::http::response resp(resp_arena.get());

            const std::string_view target = req.target();
            const auto route = router.match(target);

            const auto connection_header = req.at(ngx::protocol::http::field::connection);
            bool keep_alive = (connection_header != "close");

            if (conn_index < detailed_stats::MAX_CONNECTIONS)
            {
                stats.active_connection_list[conn_index].request_path = std::string(target);
                stats.increment_connection_request_count(conn_index);
                stats.touch_connection(conn_index);
            }

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
                    if (method == ngx::protocol::http::verb::put)
                    {
                        co_await update_cart_item(resp, stats);
                    }
                    else if (method == ngx::protocol::http::verb::delete_)
                    {
                        co_await delete_cart_item(resp, stats);
                    }
                    else
                    {
                        resp.status(ngx::protocol::http::status::method_not_allowed);
                        resp.set(ngx::protocol::http::field::content_type, "application/json");
                        resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                        resp.body(std::string_view(R"({"error":"Method Not Allowed"})"));
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
                    resp.status(ngx::protocol::http::status::ok);
                    resp.set(ngx::protocol::http::field::content_type, "application/json");
                    resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                    resp.body(std::string_view(R"({"id":"user001","name":"用户001","email":"user@example.com","avatar":"/images/avatar.jpg"})"));
                    stats.record_status_code(200);
                }
                else if (target == "/api/orders")
                {
                    co_await create_order(resp, stats);
                }
                else
                {
                    resp.status(ngx::protocol::http::status::not_found);
                    resp.set(ngx::protocol::http::field::content_type, "application/json");
                    resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                    resp.body(std::string_view(R"({"error":"Not Found","message":"API endpoint not found"})"));
                    stats.increment_not_found();
                    stats.record_status_code(404);
                }
            }
            else
            {
                if (file_handler.serve_file(route.path, resp, stats))
                {
                    resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                    stats.record_status_code(200);
                }
                else
                {
                    resp.status(ngx::protocol::http::status::not_found);
                    resp.set(ngx::protocol::http::field::content_type, "text/html");
                    resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                    resp.body(std::string_view(R"(<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1><p>The requested resource was not found on this server.</p></body></html>)"));
                    stats.increment_not_found();
                    stats.record_status_code(404);
                }
            }

            const auto end_time = std::chrono::steady_clock::now();
            const auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
            stats.record_request_time(duration_ns);

            resp.keep_alive(keep_alive);

            const auto serialized = ngx::protocol::http::serialize(resp, pool);

            stream.expires_after(std::chrono::seconds(120));

            const auto bytes_sent = co_await boost::asio::async_write(
                stream, boost::asio::buffer(serialized.data(), serialized.size()), boost::asio::redirect_error(boost::asio::use_awaitable, ec));

            if (ec)
            {
                stats.increment_errors();
                break;
            }

            stats.add_bytes_sent(bytes_sent);

            if (!keep_alive)
            {
                break;
            }
        }

        stream.close();
        stats.remove_connection();
    }

    /**
     * @brief 处理统计端口会话
     * @tparam Stream 流类型（tcp_wrapper 或 ssl_wrapper）
     * @param stream 网络流对象（TCP 或 SSL 包装器）
     * @param stats 服务器统计数据引用，用于记录请求统计和获取统计信息
     * @param file_handler 静态文件处理器，用于服务统计面板静态文件
     * @param router 统计端口路由器，用于匹配请求路径到处理器
     * @param conn_index 连接在活动连接列表中的索引
     * @return 协程任务
     */
    template <typename Stream>
    boost::asio::awaitable<void> do_dashboard_session(Stream &&stream, detailed_stats &stats,
                                                      const static_handler &file_handler,
                                                      const stats_router &router, std::size_t conn_index)
    {
        stats.add_connection();

        boost::beast::flat_buffer buffer;
        boost::system::error_code ec;

        if constexpr (std::is_same_v<std::decay_t<Stream>, ssl_wrapper>)
        {
            auto token = boost::asio::redirect_error(boost::asio::use_awaitable, ec);
            co_await stream.native_handle().async_handshake(boost::asio::ssl::stream_base::server, token);

            if (ec)
            {
                ngx::trace::error("TLS握手失败: {}", ec.message());
                stats.remove_connection();
                co_return;
            }
        }

        stream.set_option(boost::asio::ip::tcp::no_delay(true));
        stream.set_option(boost::asio::ip::tcp::socket::send_buffer_size(256 * 1024));
        stream.set_option(boost::asio::ip::tcp::socket::receive_buffer_size(256 * 1024));

        auto *pool = ngx::memory::system::thread_local_pool();

        while (true)
        {
            ngx::memory::frame_arena arena;
            ngx::protocol::http::request req(arena.get());

            stream.expires_after(std::chrono::seconds(30));

            // 调试：检查 socket 状态
            boost::system::error_code debug_ec;
            const auto bytes_readable = stream.next_layer().available(debug_ec);
            ngx::trace::debug("[统计端口] 等待读取请求... buffer大小: {}, socket可读字节: {}, socket错误: {}",
                              buffer.size(), bytes_readable, debug_ec.message());

            const auto read_result = co_await ngx::protocol::http::async_read(stream, req, buffer, pool);

            if (read_result != ngx::gist::code::success)
            {
                if (read_result == ngx::gist::code::eof)
                {
                    ngx::trace::info("[统计端口] 客户端关闭连接 (EOF)");
                    break;
                }

                // 打印 buffer 内容用于诊断
                std::string buffer_content;
                if (buffer.size() > 0)
                {
                    auto buffer_data = boost::beast::buffers_front(buffer.data());
                    buffer_content = std::string(static_cast<const char *>(buffer_data.data()),
                                                 std::min(buffer.size(), static_cast<std::size_t>(200)));
                }

                ngx::trace::error("[统计端口] 读取请求失败: {} ({}), buffer大小: {}, buffer内容: {}",
                                  ngx::gist::describe(read_result), static_cast<int>(read_result),
                                  buffer.size(),
                                  buffer.size() == 0 ? "(空)" : buffer_content);
                stats.increment_errors();
                break;
            }

            stats.increment_requests();
            stats.add_bytes_received(req.body().size());

            const auto start_time = std::chrono::steady_clock::now();
            const auto method_str = req.method_string();
            stats.record_method(method_str);

            const std::string_view target = req.target();
            const auto route = router.match(target);

            const auto connection_header = req.at(ngx::protocol::http::field::connection);
            bool keep_alive = (connection_header != "close");

            if (conn_index < detailed_stats::MAX_CONNECTIONS)
            {
                stats.active_connection_list[conn_index].request_path = std::string(target);
                stats.increment_connection_request_count(conn_index);
                stats.touch_connection(conn_index);
            }

            if (route.type == route_type::websocket_endpoint)
            {
                if constexpr (std::is_same_v<std::decay_t<Stream>, tcp_wrapper>)
                {
                    boost::beast::websocket::stream<boost::beast::tcp_stream> ws(std::move(stream.native_handle()));
                    co_await handle_connection(std::move(ws), stats);
                }
                else
                {
                    ngx::memory::frame_arena resp_arena;
                    ngx::protocol::http::response resp(resp_arena.get());
                    resp.status(ngx::protocol::http::status::upgrade_required);
                    resp.set(ngx::protocol::http::field::content_type, "application/json");
                    resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                    resp.body(std::string_view(R"({"error":"Upgrade Required","message":"WebSocket over SSL is not supported on this endpoint"})"));
                    stats.record_status_code(426);

                    const auto serialized = ngx::protocol::http::serialize(resp, pool);
                    auto token = boost::asio::redirect_error(boost::asio::use_awaitable, ec);
                    co_await boost::asio::async_write(stream, boost::asio::buffer(serialized.data(), serialized.size()), token);
                }
                stats.remove_connection();
                co_return;
            }
            else if (route.type == route_type::api_endpoint)
            {
                stats.increment_api_requests();

                ngx::memory::frame_arena resp_arena;
                ngx::protocol::http::response resp(resp_arena.get());

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
                    resp.status(ngx::protocol::http::status::not_found);
                    resp.set(ngx::protocol::http::field::content_type, "application/json");
                    resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                    resp.body(std::string_view(R"({"error":"Not Found","message":"Stats API endpoint not found"})"));
                    stats.increment_not_found();
                    stats.record_status_code(404);
                }

                const auto end_time = std::chrono::steady_clock::now();
                const auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
                stats.record_request_time(duration_ns);

                resp.keep_alive(keep_alive);

                const auto serialized = ngx::protocol::http::serialize(resp, pool);

                stream.expires_after(std::chrono::seconds(120));

                const auto bytes_sent = co_await boost::asio::async_write(
                    stream, boost::asio::buffer(serialized.data(), serialized.size()), boost::asio::redirect_error(boost::asio::use_awaitable, ec));

                if (ec)
                {
                    stats.increment_errors();
                    break;
                }

                stats.add_bytes_sent(bytes_sent);

                if (!keep_alive)
                {
                    break;
                }
            }
            else
            {
                ngx::memory::frame_arena resp_arena;
                ngx::protocol::http::response resp(resp_arena.get());

                if (file_handler.serve_file(route.path, resp, stats))
                {
                    resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                    stats.record_status_code(200);
                }
                else
                {
                    resp.status(ngx::protocol::http::status::not_found);
                    resp.set(ngx::protocol::http::field::content_type, "text/html");
                    resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                    resp.body(std::string_view(R"(<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1><p>The requested resource was not found on this server.</p></body></html>)"));
                    stats.increment_not_found();
                    stats.record_status_code(404);
                }

                const auto end_time = std::chrono::steady_clock::now();
                const auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
                stats.record_request_time(duration_ns);

                resp.keep_alive(keep_alive);

                const auto serialized = ngx::protocol::http::serialize(resp, pool);

                stream.expires_after(std::chrono::seconds(120));

                const auto bytes_sent = co_await boost::asio::async_write(
                    stream, boost::asio::buffer(serialized.data(), serialized.size()), boost::asio::redirect_error(boost::asio::use_awaitable, ec));

                if (ec)
                {
                    stats.increment_errors();
                    break;
                }

                stats.add_bytes_sent(bytes_sent);

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
