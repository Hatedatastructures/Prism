/**
 * @file session.hpp
 * @brief HTTP 会话处理模块
 * @details 基于 `tcp_wrapper` 和内存池的高性能 HTTP 会话处理器，支持 HTTP/1.1 Keep-Alive 和零拷贝响应。
 *
 * 核心特性：
 * - 传输层：使用 `tcp_wrapper` 封装 TCP 流
 * - 内存池绑定：每个会话持有专属 `ngx::memory::pool`，生命周期与连接一致
 * - 零拷贝：请求解析和响应序列化均使用 `std::string_view` 和内存池分配
 * - 协程优先：所有异步操作使用 `co_await`，严禁回调
 * - 架构分层：严格分离会话层、协议层、路由层和业务层
 *
 * @note 设计原则：
 * - 高性能：零拷贝 + 内存池 + 无锁
 * - 内存安全：动态响应体必须使用会话内存池分配，确保在 `async_write` 完成前有效
 * - 资源绑定：会话持有 socket 和内存池，确保生命周期一致
 * - 职责单一：会话仅负责协议读写和生命周期管理，业务逻辑委托给路由器和处理器
 *
 * @see routing.hpp
 * @see socket.hpp
 * @see processor.hpp
 */

#pragma once

#include <chrono>
#include <string_view>
#include <utility>
#include <fstream>

#include "routing.hpp"
#include "handler.hpp"
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

namespace srv::session
{
    namespace net = boost::asio;
    namespace beast = boost::beast;

    using namespace srv::routing;
    using namespace srv::handler;
    using namespace srv::handler::main_api;
    using namespace srv::handler::stats_api;
    using namespace srv::websocket;
    using namespace srv::statistics;
    using namespace srv::socket;
    using namespace ngx::protocol::http;
    using namespace ngx::gist;
    using namespace ngx::transformer::json;

    /**
     * @class session
     * @brief HTTP 会话类模板
     * @tparam Router 路由器类型（必须是 `main_router` 或 `stats_router`）
     * @details 管理单个客户端连接的生命周期，处理 HTTP/1.1 Keep-Alive 循环。
     *          持有底层 TCP 流和专属内存池，确保所有动态内存分配在会话生命周期内有效。
     */
    template <typename Router>
    class session final
    {
    public:
        /**
         * @brief 构造函数
         * @param stream TCP 流包装器
         * @param stats 统计信息引用
         * @param file_handler 静态文件处理器引用
         * @param router 路由器引用
         * @param conn_index 连接索引（用于统计）
         * @param pool 内存池指针（若为 nullptr，则使用线程本地内存池）
         */
        session(tcp_wrapper stream, detailed_stats &stats, const static_handler &file_handler,
                const Router &router, std::size_t conn_index,
                ngx::memory::pool *pool = nullptr) noexcept
            : stream_(std::move(stream)),
              stats_(stats),
              file_handler_(file_handler),
              router_(router),
              conn_index_(conn_index),
              pool_(pool ? pool : ngx::memory::system::thread_local_pool())
        {
        }

        session(const session &) = delete;
        session &operator=(const session &) = delete;
        session(session &&) = default;
        session &operator=(session &&) = default;

        /**
         * @brief 启动会话处理协程
         * @return net::awaitable<void> 协程，处理该连接的所有请求直到关闭
         * @details 主循环流程：
         *          1. 读取数据 -> 调用 `ngx::protocol::http::async_read` 解析请求
         *          2. 分发给路由器匹配 -> 调用对应的处理器
         *          3. 调用 `ngx::protocol::http::serialize` 序列化响应
         *          4. 通过 `async_write` 写回
         *          5. 若为 Keep-Alive 连接，重复步骤 1；否则退出循环
         *          每个循环开始或结束时必须清理内存池，防止 Keep-Alive 长连接导致内存泄漏。
         */
        net::awaitable<void> start() noexcept
        {
            stats_.add_connection();

            // 设置 TCP 选项
            stream_.set_option(net::ip::tcp::no_delay(true));
            stream_.set_option(net::ip::tcp::socket::send_buffer_size(256 * 1024));
            stream_.set_option(net::ip::tcp::socket::receive_buffer_size(256 * 1024));

            // 缓冲区 - 必须在循环外部，保持持久化
            beast::flat_buffer buffer;

            // 请求处理循环
            while (true)
            {
                // 每次循环开始时清理内存池，防止 Keep-Alive 长连接导致内存泄漏
                // 注意：这会将内存池重置为空状态，所有之前分配的内存将被释放
                // 这确保每个请求都从干净的内存状态开始，避免内存碎片
                pool_->clear();

                // HTTP 请求对象，使用会话内存池
                request req(pool_);

                // 设置读取超时
                stream_.expires_after(std::chrono::seconds(30));

                // 读取 HTTP 请求 - 使用 stream 和 buffer
                const auto read_result = co_await async_read(stream_, req, buffer, pool_);

                if (read_result != code::success)
                {
                    if (read_result == code::eof)
                    {
                        ngx::trace::debug("会话: 客户端关闭连接 (EOF)");
                    }
                    else
                    {
                        // keep-alive 超时或连接重置是正常现象
                        ngx::trace::debug("会话: 连接关闭 ({})", describe(read_result));
                    }
                    break;
                }

                stats_.increment_requests();
                stats_.add_bytes_received(req.body().size());

                const auto start_time = std::chrono::steady_clock::now();
                const auto method_str = req.method_string();
                stats_.record_method(method_str);

                // 响应对象 - 使用帧内存池（独立于会话内存池，避免污染）
                ngx::memory::frame_arena resp_arena;
                response resp(resp_arena.get());

                const std::string_view target = req.target();
                const auto route = router_.match(target);

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
                if (conn_index_ < detailed_stats::MAX_CONNECTIONS)
                {
                    stats_.active_connection_list[conn_index_].request_path = std::string(target);
                    stats_.increment_connection_request_count(conn_index_);
                    stats_.touch_connection(conn_index_);
                }

                // 路由处理
                if (route.type == route_type::api_endpoint)
                {
                    stats_.increment_api_requests();
                    co_await handle_api_request(target, route, req, resp);
                }
                else if (route.type == route_type::websocket_endpoint)
                {
                    // WebSocket 升级处理
                    beast::websocket::stream<beast::tcp_stream> ws(stream_.release());
                    co_await handle_websocket(std::move(ws), req, stats_);
                    stats_.remove_connection();
                    co_return;
                }
                else
                {
                    // 静态文件服务
                    if (file_handler_.serve_file(route.path, resp, stats_, pool_))
                    {
                        resp.set(field::server, "ForwardEngine/1.0");
                        stats_.record_status_code(200);
                    }
                    else
                    {
                        // 使用自定义错误页面或默认页面
                        if (!load_error_page("webroot/404.html", resp))
                        {
                            // 使用编译期计算的默认 404 页面
                            static constexpr std::string_view default_404_body =
                                R"(<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>)";
                            resp.status(status::not_found);
                            resp.set(field::content_type, "text/html");
                            resp.set(field::server, "ForwardEngine/1.0");
                            resp.content_length(default_404_body.size());
                            resp.body(default_404_body);
                        }
                        else
                        {
                            resp.status(status::not_found);
                            resp.set(field::content_type, "text/html");
                            resp.set(field::server, "ForwardEngine/1.0");
                        }
                        stats_.increment_not_found();
                        stats_.record_status_code(404);
                    }
                }

                // 记录请求时间
                const auto end_time = std::chrono::steady_clock::now();
                const auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
                stats_.record_request_time(duration_ns);

                resp.keep_alive(keep_alive);

                // 序列化响应 - 使用会话内存池
                const auto serialized = serialize(resp, pool_);

                // 设置写入超时
                stream_.expires_after(std::chrono::seconds(120));

                boost::system::error_code write_ec;
                co_await net::async_write(
                    stream_,
                    net::buffer(serialized.data(), serialized.size()),
                    net::redirect_error(net::use_awaitable, write_ec));

                if (write_ec)
                {
                    stats_.increment_errors();
                    break;
                }

                stats_.add_bytes_sent(serialized.size());

                if (!keep_alive)
                {
                    break;
                }
            }

            stream_.close();
            stats_.remove_connection();
        }

        /**
         * @brief 获取底层内存池指针
         * @return ngx::memory::pool* 内存池指针
         */
        [[nodiscard]] ngx::memory::pool *get_pool() const noexcept
        {
            return pool_;
        }

        /**
         * @brief 获取分配器（用于 PMR 容器）
         * @return std::pmr::polymorphic_allocator<> 分配器
         */
        [[nodiscard]] auto get_allocator() const noexcept
        {
            return pool_->get_allocator();
        }

    private:
        /**
         * @brief 处理 API 请求（内部方法）
         * @details 根据目标路径调用对应的 API 处理器。
         *          所有动态响应体必须使用会话内存池分配，确保在 async_write 完成前有效。
         *          使用第二步重构后的安全处理器，彻底修复悬垂指针漏洞。
         */
        net::awaitable<void> handle_api_request(std::string_view target, const route_result &route,
                                                const request &req, response &resp) noexcept
        {
            // 根据路由器类型选择处理器
            if constexpr (std::is_same_v<Router, main_router>)
            {
                // 主 API 处理器
                auto handler = create_main_handler(pool_);

                if (target == "/api/login")
                {
                    co_await handler->handle_login(resp, stats_);
                }
                else if (target == "/api/register")
                {
                    co_await handler->handle_register(resp, stats_);
                }
                else if (target == "/api/send_captcha")
                {
                    co_await handler->handle_send_captcha(resp, stats_);
                }
                else if (target == "/api/products")
                {
                    co_await handler->handle_products(req, resp, stats_);
                }
                else if (target.starts_with("/api/product/"))
                {
                    // 提取商品 ID
                    const auto product_id = target.substr(std::string_view("/api/product/").size());
                    co_await handler->handle_product_detail(product_id, resp, stats_);
                }
                else if (target == "/api/cart")
                {
                    co_await handler->handle_cart_operations(req, resp, stats_);
                }
                else if (target == "/api/search")
                {
                    co_await handler->handle_search_products(req, resp, stats_);
                }
                else
                {
                    // API 端点未找到 - 使用编译期计算的 JSON 错误响应
                    static constexpr std::string_view not_found_json =
                        R"({"error":"Not Found","message":"API endpoint not found"})";

                    resp.status(status::not_found);
                    resp.set(field::content_type, "application/json");
                    resp.set(field::server, "ForwardEngine/1.0");
                    resp.content_length(not_found_json.size());
                    resp.body(not_found_json);
                    stats_.increment_not_found();
                    stats_.record_status_code(404);
                }
            }
            else if constexpr (std::is_same_v<Router, stats_router>)
            {
                // 统计 API 处理器
                auto handler = create_stats_handler(pool_);

                if (target == "/api/stats")
                {
                    co_await handler->handle_get_stats(resp, stats_);
                }
                else if (target == "/api/connections")
                {
                    co_await handler->handle_get_active_connections(resp, stats_);
                }
                else if (target == "/api/traffic")
                {
                    // 默认查询最近 60 分钟流量历史
                    co_await handler->handle_get_traffic_history(resp, stats_, 60);
                }
                else if (target.starts_with("/api/traffic/"))
                {
                    // 提取分钟数，例如 /api/traffic/30
                    const auto minutes_str = target.substr(std::string_view("/api/traffic/").size());
                    const auto minutes = safe_parse_int<std::uint32_t>(minutes_str, 60);
                    co_await handler->handle_get_traffic_history(resp, stats_, minutes);
                }
                else if (target == "/api/performance")
                {
                    co_await handler->handle_get_performance(resp, stats_);
                }
                else
                {
                    // API 端点未找到 - 使用编译期计算的 JSON 错误响应
                    static constexpr std::string_view not_found_json =
                        R"({"error":"Not Found","message":"Stats API endpoint not found"})";

                    resp.status(status::not_found);
                    resp.set(field::content_type, "application/json");
                    resp.set(field::server, "ForwardEngine/1.0");
                    resp.content_length(not_found_json.size());
                    resp.body(not_found_json);
                    stats_.increment_not_found();
                    stats_.record_status_code(404);
                }
            }
            else
            {
                // 未知路由器类型 - 使用编译期计算的 JSON 错误响应
                static constexpr std::string_view internal_error_json =
                    R"({"error":"Internal Server Error","message":"Unknown router type"})";

                resp.status(status::internal_server_error);
                resp.set(field::content_type, "application/json");
                resp.set(field::server, "ForwardEngine/1.0");
                resp.content_length(internal_error_json.size());
                resp.body(internal_error_json);
                stats_.increment_errors();
                stats_.record_status_code(500);
            }

            co_return;
        }

        /**
         * @brief 加载错误页面文件
         * @param error_page_path 错误页面文件路径
         * @param resp 响应对象
         * @return bool 是否成功加载
         */
        bool load_error_page(std::string_view error_page_path, response &resp) noexcept
        {
            std::ifstream file(error_page_path.data(), std::ios::binary | std::ios::ate);
            if (!file.is_open())
            {
                return false;
            }

            const auto file_size = file.tellg();
            if (file_size <= 0)
            {
                return false;
            }

            // 使用内存池分配字符串
            ngx::memory::string content(pool_, file_size, '\0');
            file.seekg(0);
            file.read(content.data(), file_size);

            if (!file)
            {
                return false;
            }

            resp.content_length(content.size());
            resp.body(content);
            return true;
        }

    private:
        tcp_wrapper stream_;
        detailed_stats &stats_;
        const static_handler &file_handler_;
        const Router &router_;
        std::size_t conn_index_;
        ngx::memory::pool *pool_;
    };

    // 别名，方便使用
    using main_session = session<main_router>;
    using stats_session = session<stats_router>;
}
const Router &router_;
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

// 别名，方便使用
using main_session = session<main_router>;
using stats_session = session<stats_router>;
}
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
const Router &router_;
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

// 别名，方便使用
using main_session = session<main_router>;
using stats_session = session<stats_router>;
}
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
const Router &router_;
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

// 别名，方便使用
using main_session = session<main_router>;
using stats_session = session<stats_router>;
}
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
const Router &router_;
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

// 别名，方便使用
using main_session = session<main_router>;
using stats_session = session<stats_router>;
}
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
const Router &router_;
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

// 别名，方便使用
using main_session = session<main_router>;
using stats_session = session<stats_router>;
}
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
const Router &router_;
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

// 别名，方便使用
using main_session = session<main_router>;
using stats_session = session<stats_router>;
}
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
const Router &router_;
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

// 别名，方便使用
using main_session = session<main_router>;
using stats_session = session<stats_router>;
}
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
const Router &router_;
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

// 别名，方便使用
using main_session = session<main_router>;
using stats_session = session<stats_router>;
}
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
const Router &router_;
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

// 别名，方便使用
using main_session = session<main_router>;
using stats_session = session<stats_router>;
}
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
const Router &router_;
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

// 别名，方便使用
using main_session = session<main_router>;
using stats_session = session<stats_router>;
}
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
const Router &router_;
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

// 别名，方便使用
using main_session = session<main_router>;
using stats_session = session<stats_router>;
}
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
const Router &router_;
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

// 别名，方便使用
using main_session = session<main_router>;
using stats_session = session<stats_router>;
}
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
const Router &router_;
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

// 别名，方便使用
using main_session = session<main_router>;
using stats_session = session<stats_router>;
}
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
const Router &router_;
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

// 别名，方便使用
using main_session = session<main_router>;
using stats_session = session<stats_router>;
}
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
const Router &router_;
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

// 别名，方便使用
using main_session = session<main_router>;
using stats_session = session<stats_router>;
}
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
const Router &router_;
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

// 别名，方便使用
using main_session = session<main_router>;
using stats_session = session<stats_router>;
}
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
const Router &router_;
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

// 别名，方便使用
using main_session = session<main_router>;
using stats_session = session<stats_router>;
}
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
const Router &router_;
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

// 别名，方便使用
using main_session = session<main_router>;
using stats_session = session<stats_router>;
}
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
const Router &router_;
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

// 别名，方便使用
using main_session = session<main_router>;
using stats_session = session<stats_router>;
}
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
const Router &router_;
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

// 别名，方便使用
using main_session = session<main_router>;
using stats_session = session<stats_router>;
}
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
const Router &router_;
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;

// 别名，方便使用
using main_session = session<main_router>;
using stats_session = session<stats_router>;
}
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
resp.content_length(58);
resp.body(R"({"error":"Not Found","message":"API endpoint not found"})");
stats_.increment_not_found();
stats_.record_status_code(404);
}
}

private:
tcp_wrapper stream_;
detailed_stats & stats_;
const static_handler &file_handler_;
const main_router &router_; // 注意：这里使用 main_router 作为通用类型，实际可能为 stats_router
std::size_t conn_index_;
ngx::memory::pool *pool_;
}
;
