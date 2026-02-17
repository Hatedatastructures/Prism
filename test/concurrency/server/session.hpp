/**
 * @file session.hpp
 * @brief 会话处理函数定义
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
 */
#pragma once

#include <chrono>
#include <string>
#include <string_view>
#include <array>
#include <iostream>

#include "router/route.hpp"
#include "router/main_router.hpp"
#include "router/stats_router.hpp"
#include "handler/static_file.hpp"
#include "handler/main_api.hpp"
#include "handler/stats_api.hpp"
#include "websocket/handler.hpp"
#include "stream/tcp_wrapper.hpp"
#include "stream/ssl_wrapper.hpp"
#include "stats/metrics.hpp"
#include "mime/types.hpp"
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <forward-engine/protocol/http.hpp>
#include <forward-engine/protocol/http/deserialization.hpp>
#include <forward-engine/protocol/http/serialization.hpp>
#include <forward-engine/gist/code.hpp>
#include <forward-engine/memory.hpp>
#include <forward-engine/memory/pool.hpp>
#include <forward-engine/transformer/json.hpp>
#include <glaze/glaze.hpp>

namespace srv::session
{
    namespace fs = std::filesystem;
    using namespace srv::router;
    using namespace srv::handler;
    using namespace srv::handler::main_api;
    using namespace srv::handler::stats_api;
    using namespace srv::websocket;
    using namespace srv::stats;
    using namespace srv::stream;
    using namespace srv::mime;
    using namespace ngx::protocol::http;
    using namespace ngx::gist;
    using namespace ngx::transformer::json;

    enum class detected_protocol
    {
        http,
        https,
        unknown
    };

    [[nodiscard]] inline auto detect_protocol(boost::asio::ip::tcp::socket &socket) -> boost::asio::awaitable<detected_protocol>
    {
        std::array<std::byte, 3> peek_buffer{};

        boost::beast::error_code ec;
        const std::size_t n = co_await socket.async_read_some(
            boost::asio::buffer(peek_buffer), boost::asio::redirect_error(boost::asio::use_awaitable, ec));

        if (ec || n < 3)
        {
            co_return detected_protocol::unknown;
        }

        const std::uint8_t byte0 = static_cast<std::uint8_t>(peek_buffer[0]);
        const std::uint8_t byte1 = static_cast<std::uint8_t>(peek_buffer[1]);
        const std::uint8_t byte2 = static_cast<std::uint8_t>(peek_buffer[2]);

        if (byte0 == 0x16 && byte1 == 0x03 && (byte2 == 0x00 || byte2 == 0x01 || byte2 == 0x02 || byte2 == 0x03))
        {
            co_return detected_protocol::https;
        }

        const std::string_view method_str(reinterpret_cast<const char *>(peek_buffer.data()), 3);

        if (method_str == "GET" || method_str == "POS" || method_str == "PUT" || method_str == "HEA" ||
            method_str == "DEL" || method_str == "OPT" || method_str == "CON" || method_str == "TRA")
        {
            co_return detected_protocol::http;
        }

        co_return detected_protocol::http;
    }

    template <typename Stream>
    boost::asio::awaitable<void> do_main_session(Stream &&stream, detailed_stats &stats,
                                                 const static_file_handler &file_handler,
                                                 const main_router &router, std::size_t conn_index);

    template <typename Stream>
    boost::asio::awaitable<void> do_stats_session(Stream &&stream, detailed_stats &stats,
                                                  const static_file_handler &file_handler,
                                                  const stats_router &router, std::size_t conn_index);

    template <typename Stream>
    boost::asio::awaitable<void> do_main_session(Stream &&stream, detailed_stats &stats,
                                                 const static_file_handler &file_handler,
                                                 const main_router &router, std::size_t conn_index)
    {
        stats.add_connection();

        boost::beast::flat_buffer buffer;
        boost::system::error_code ec;

        if constexpr (std::is_same_v<std::decay_t<Stream>, ssl_stream_wrapper>)
        {
            co_await stream.native_handle().async_handshake(
                boost::asio::ssl::stream_base::server, boost::asio::redirect_error(boost::asio::use_awaitable, ec));

            if (ec)
            {
                std::cout << "TLS握手失败: " << ec.message() << std::endl;
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
                std::cout << "读取请求失败: " << static_cast<int>(read_result) << std::endl;
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
                auto conn_info = stats.active_connection_list[conn_index];
                const std::string target_str(target);
                conn_info.request_path = target_str;
                conn_info.request_count++;
                conn_info.last_active = std::chrono::steady_clock::now();
                stats.update_connection_info(conn_index, conn_info);
            }

            if (route.type == route_type::api_endpoint)
            {
                stats.increment_api_requests();

                if (target == "/api/products")
                {
                    co_await get_products(req, resp, stats);
                }
                else if (target.starts_with("/api/product/"))
                {
                    co_await get_product_detail(req, resp, stats, route.param);
                }
                else if (target == "/api/cart" || target.starts_with("/api/cart/"))
                {
                    co_await cart_operations(req, resp, stats);
                }
                else if (target == "/api/search")
                {
                    co_await search_products(req, resp, stats);
                }
                else if (target == "/api/user")
                {
                    resp.status(ngx::protocol::http::status::ok);
                    resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
                    resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                    resp.body(std::string_view(R"({"id":"user001","name":"用户001","email":"user@example.com","avatar":"/images/avatar.jpg"})"));
                    stats.record_status_code(200);
                }
                else
                {
                    resp.status(ngx::protocol::http::status::not_found);
                    resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
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
                    resp.set(ngx::protocol::http::field::content_type, HTML_CONTENT_TYPE);
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

    template <typename Stream>
    boost::asio::awaitable<void> do_stats_session(Stream &&stream, detailed_stats &stats,
                                                  const static_file_handler &file_handler,
                                                  const stats_router &router, std::size_t conn_index)
    {
        stats.add_connection();

        boost::beast::flat_buffer buffer;
        boost::system::error_code ec;

        if constexpr (std::is_same_v<std::decay_t<Stream>, ssl_stream_wrapper>)
        {
            co_await stream.native_handle().async_handshake(
                boost::asio::ssl::stream_base::server, boost::asio::redirect_error(boost::asio::use_awaitable, ec));

            if (ec)
            {
                std::cout << "TLS握手失败: " << ec.message() << std::endl;
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
                std::cout << "读取请求失败: " << static_cast<int>(read_result) << std::endl;
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
                auto conn_info = stats.active_connection_list[conn_index];
                const std::string target_str(target);
                conn_info.request_path = target_str;
                conn_info.request_count++;
                conn_info.last_active = std::chrono::steady_clock::now();
                stats.update_connection_info(conn_index, conn_info);
            }

            if (route.type == route_type::websocket_endpoint)
            {
                if constexpr (std::is_same_v<std::decay_t<Stream>, tcp_stream_wrapper>)
                {
                    boost::beast::websocket::stream<boost::beast::tcp_stream> ws(std::move(stream.native_handle()));
                    co_await handle_websocket_connection(std::move(ws), stats);
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
                        minutes = static_cast<std::uint32_t>(std::stoi(std::string(route.param)));
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
                    resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
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
                    resp.set(ngx::protocol::http::field::content_type, HTML_CONTENT_TYPE);
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

    template <typename Stream>
    boost::asio::awaitable<void> do_session(Stream &&stream, detailed_stats &stats,
                                            const static_file_handler &file_handler,
                                            const main_router &router_)
    {
        stats.add_connection();

        boost::beast::flat_buffer buffer;
        boost::system::error_code ec;

        if constexpr (std::is_same_v<std::decay_t<Stream>, ssl_stream_wrapper>)
        {
            co_await stream.native_handle().async_handshake(
                boost::asio::ssl::stream_base::server, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
            if (ec)
            {
                std::cout << "TLS握手失败: " << ec.message() << std::endl;
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
                std::cout << "读取请求失败: " << static_cast<int>(read_result) << std::endl;
                stats.increment_errors();
                break;
            }

            stats.increment_requests();
            stats.add_bytes_received(req.body().size());

            ngx::memory::frame_arena resp_arena;
            ngx::protocol::http::response resp(resp_arena.get());

            const std::string_view target = req.target();
            const auto route = router_.match(target);

            const auto connection_header = req.at(ngx::protocol::http::field::connection);
            bool keep_alive = (connection_header != "close");

            if (route.type == route_type::api_endpoint)
            {
                stats.increment_api_requests();

                if (target == "/health" || target == "/stats")
                {
                    const auto snapshot = create_snapshot(stats);
                    auto stats_json = serialize(snapshot);

                    resp.status(ngx::protocol::http::status::ok);
                    resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
                    resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                    resp.body(std::string(stats_json));
                    stats.record_status_code(200);
                }
                else if (target == "/api/time")
                {
                    const auto now = std::chrono::system_clock::now();
                    const auto time_t_now = std::chrono::system_clock::to_time_t(now);

                    std::string time_str(128, '\0');
                    std::strftime(time_str.data(), time_str.size(), "%Y-%m-%d %H:%M:%S", std::localtime(&time_t_now));
                    time_str.resize(std::strlen(time_str.c_str()));

                    std::string json = R"({"time":")" + time_str + R"("})";

                    resp.status(ngx::protocol::http::status::ok);
                    resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
                    resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                    resp.body(std::string(json));
                    stats.record_status_code(200);
                }
                else
                {
                    resp.status(ngx::protocol::http::status::not_found);
                    resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
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
                    resp.set(ngx::protocol::http::field::content_type, HTML_CONTENT_TYPE);
                    resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                    resp.body(std::string_view(R"(<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1><p>The requested resource was not found on this server.</p></body></html>)"));
                    stats.increment_not_found();
                    stats.record_status_code(404);
                }
            }

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
}
