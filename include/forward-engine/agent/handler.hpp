#pragma once
#include <cstddef>
#include <cctype>

#include <array>
#include <memory>
#include <string>
#include <format>
#include <utility>
#include <functional>
#include <string_view>
#include <span>

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <forward-engine/abnormal.hpp>
#include <forward-engine/gist.hpp>
#include <forward-engine/memory/pool.hpp>
#include <forward-engine/agent/distributor.hpp>
#include <forward-engine/protocol/analysis.hpp>
#include <forward-engine/transport/obscura.hpp>
#include <forward-engine/protocol/socks5.hpp>
#include <forward-engine/protocol/trojan.hpp>
#include <forward-engine/transport/source.hpp>
#include <forward-engine/transport/adaptation.hpp>
#include <forward-engine/protocol/http/deserialization.hpp>
#include <forward-engine/protocol/http/serialization.hpp>
#include <forward-engine/transport/transfer.hpp>

namespace ngx::agent
{
    namespace net = boost::asio;
    namespace ssl = boost::asio::ssl;
    namespace beast = boost::beast;
    namespace beast_http = beast::http; // Beast HTTP

    // Protocol aliases
    namespace protocol = ngx::protocol;
    namespace transport = ngx::transport;
    // HTTP Protocol alias
    namespace http_protocol = ngx::protocol::http;

    // Transport detail alias
    namespace detail = ngx::transport::detail;

    using tcp = boost::asio::ip::tcp;
    using level = detail::log_level;
    using unique_sock = transport::unique_sock;

    /**
     * @brief 会话上下文
     * @tparam Transport socket 类型
     * @details 包含 Handler 运行所需的所有资源引用，不负责生命周期管理
     */
    template <transport::SocketConcept Transport>
    struct session_context
    {
        using socket_type = Transport;
        using unique_sock = transport::unique_sock;

        net::io_context &io_context;
        socket_type &client_socket;
        unique_sock &server_socket;
        distributor &distributor_ref;
        std::shared_ptr<ssl::context> ssl_ctx;
        ngx::memory::frame_arena &frame_arena;
        std::span<std::byte> buffer;
        std::function<bool(std::string_view)> &password_verifier;
    };

    /**
     * @brief 创建会话上下文的辅助函数
     * @tparam Transport socket 类型
     */
    template <transport::SocketConcept Transport>
    [[nodiscard]] auto make_session_context( net::io_context &io_context,
        Transport &client_socket, transport::unique_sock &server_socket,
        distributor &distributor_ref, std::shared_ptr<ssl::context> ssl_ctx,
        ngx::memory::frame_arena &frame_arena, std::span<std::byte> buffer,
        std::function<bool(std::string_view)> &password_verifier) 
            -> session_context<Transport>
    {
        return session_context<Transport>
        {
            io_context, client_socket, server_socket,
            distributor_ref, ssl_ctx, frame_arena,
            buffer, password_verifier
        };
    }
}

namespace ngx::agent::handler
{
    using namespace ngx::agent;

    /**
     * @brief 关闭连接辅助函数
     */
    template <typename Socket>
    void shut_close(std::unique_ptr<Socket> &socket_ptr) noexcept
    {
        if (socket_ptr)
        {
            detail::shut_close(*socket_ptr);
            socket_ptr.reset();
        }
    }

    template <typename Socket>
    void shut_close(Socket &socket) noexcept
    {
        detail::shut_close(socket);
    }

    /**
     * @brief 关闭会话资源
     */
    template <typename Context>
    void close_session(Context &ctx) noexcept
    {
        detail::event_tracking(level::debug, "[Handler] Session closing.");
        shut_close(ctx.client_socket);
        shut_close(ctx.server_socket);
    }

    /**
     * @brief 连接上游服务器
     */
    template <typename Context>
    auto connect_upstream(Context &ctx, std::string_view label, const protocol::analysis::target &target,
                          const bool allow_reverse, const bool require_open) -> net::awaitable<bool>
    {
        gist::code ec = gist::code::success;
        if (allow_reverse && !target.forward_proxy)
        {
            auto result = co_await ctx.distributor_ref.route_reverse(target.host);
            ec = result.first;
            ctx.server_socket = std::move(result.second);
        }
        else
        {
            auto result = co_await ctx.distributor_ref.route_forward(target.host, target.port);
            ec = result.first;
            ctx.server_socket = std::move(result.second);
        }

        if (ec != ngx::gist::code::success)
        {
            const auto message = std::format("[Handler] {} route failed: {}", label, ngx::gist::describe(ec));
            detail::event_tracking(level::warn, message);
            co_return false;
        }

        if (!ctx.server_socket || (require_open && !ctx.server_socket->is_open()))
        {
            const auto message = std::format("[Handler] {} route to upstream failed (connection invalid).", label);
            detail::event_tracking(level::error, message);
            co_return false;
        }

        const auto message = std::format("[Handler] {} upstream connected.", label);
        detail::event_tracking(level::info, message);
        co_return true;
    }

    /**
     * @brief 原始 TCP 隧道
     */
    template <typename Context>
    auto original_tunnel(Context &ctx) -> net::awaitable<void>
    {
        if (!ctx.server_socket)
        {
            detail::event_tracking(level::warn, "[Handler] raw tunnel: no upstream connection.");
            co_return;
        }

        auto tunnel_ctx = detail::make_tunnel_context(&*ctx.server_socket, &ctx.client_socket);
        detail::tunnel t;

        if (ctx.buffer.size() < 2)
        {
            detail::event_tracking(level::error, "[Handler] raw tunnel: buffer too small.");
            co_return;
        }

        try
        {
            co_await t.stream(tunnel_ctx, ctx.buffer.data(), ctx.buffer.size());
        }
        catch (const std::exception &e)
        {
            detail::event_tracking(level::warn, std::format("[Handler] raw tunnel error: {}", e.what()));
        }

        shut_close(ctx.server_socket);
    }

    /**
     * @brief 隧道 TCP 流量 (Obscura)
     */
    template <typename Context>
    auto tunnel(Context &ctx) -> net::awaitable<void>
    {
        if (!ctx.server_socket)
        {
            detail::event_tracking(level::warn, "[Tunnel] aborted: upstream socket is missing.");
            co_return;
        }

        ctx.frame_arena.reset();

        auto tunnel_ctx = detail::make_tunnel_context(ctx.server_socket.get(), &ctx.client_socket);
        detail::tunnel tunnel_unit;

        try
        {
            co_await tunnel_unit.stream(tunnel_ctx, ctx.buffer.data(), ctx.buffer.size());
        }
        catch ([[maybe_unused]] const std::exception &e)
        {
            const auto message = std::format("[Tunnel] error: {}", e.what());
            detail::event_tracking(level::error, message);
        }
        catch (...)
        {
            detail::event_tracking(level::error, "[Tunnel] unknown error.");
        }

        shut_close(ctx.client_socket);
        shut_close(ctx.server_socket);
    }

    /**
     * @brief 处理 HTTP 请求
     */
    template <typename Context>
    auto http(Context &ctx) -> net::awaitable<void>
    {
        ctx.frame_arena.reset();
        auto mr = ctx.frame_arena.get();
        beast::basic_flat_buffer<http_protocol::network_allocator> read_buffer(http_protocol::network_allocator{mr});
        {
            http_protocol::request req(mr);
            detail::event_tracking(level::debug, "[Handler] Waiting for HTTP request...");
            const auto ec = co_await http_protocol::async_read(ctx.client_socket, req, read_buffer, mr);

            if (ec != ngx::gist::code::success)
            {
                detail::event_tracking(level::warn, std::format("[Handler] HTTP read failed: {}", ngx::gist::describe(ec)));
                co_return;
            }
            {
                const auto message = std::format("[Handler] HTTP request received: {} {}", req.method_string(), req.target());
                detail::event_tracking(level::info, message);
            }
            //  连接上游
            const auto target = protocol::analysis::resolve(req);
            {
                const auto message = std::format("[Handler] HTTP upstream resolving: forward_proxy=`{}` host=`{}` port=`{}`",
                                                 target.forward_proxy ? "true" : "false", target.host, target.port);
                detail::event_tracking(level::debug, message);
            }
            const bool connected = co_await connect_upstream(ctx, "HTTP", target, true, false);
            if (!connected)
            {
                co_return;
            }

            // 转发
            if (req.method() == http_protocol::verb::connect)
            {
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                const std::string resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
                co_await transport::adaptation::async_write(ctx.client_socket, net::buffer(resp), token);
                if (ec && !detail::normal_close(ec))
                {
                    detail::event_tracking(level::warn, "[Handler] CONNECT response send failed.");
                    close_session(ctx);
                    co_return;
                }
                detail::event_tracking(level::info, "[Handler] Sent 200 Connection Established.");

                // HTTP CONNECT 隧道应该是纯 TCP 透传
                detail::event_tracking(level::info, "[Handler] Starting raw tunnel (HTTP CONNECT)...");
                co_await original_tunnel(ctx);
                co_return;
            }
            else
            {
                // 序列化发送
                const auto data = http_protocol::serialize(req, mr);
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                co_await transport::adaptation::async_write(*ctx.server_socket, net::buffer(data), token);
                if (ec && !detail::normal_close(ec))
                {
                    detail::event_tracking(level::warn, "[Handler] HTTP request forward failed.");
                    close_session(ctx);
                    co_return;
                }
            }

            if (read_buffer.size() != 0)
            {
                const auto message = std::format("[Handler] Forwarding {} bytes of prefetched data.", read_buffer.size());
                detail::event_tracking(level::debug, message);
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                co_await transport::adaptation::async_write(*ctx.server_socket, read_buffer.data(), token);
                if (ec && !detail::normal_close(ec))
                {
                    detail::event_tracking(level::warn, "[Handler] Prefetched data forward failed.");
                    close_session(ctx);
                    co_return;
                }
                read_buffer.consume(read_buffer.size());
            }
        } // 限制request 生命周期防止在下面request指向无效的tcp字节流

        detail::event_tracking(level::info, "[Handler] Starting tunnel (Obscura upgrade)...");
        co_await tunnel(ctx);
    }

    /**
     * @brief 处理 SOCKS5 请求
     */
    template <typename Context>
    auto socks5(Context &ctx) -> net::awaitable<void>
    {
        auto agent = std::make_shared<protocol::socks5::stream<typename Context::socket_type>>(std::move(ctx.client_socket));
        auto [ec, request] = co_await agent->handshake();

        if (ec != ngx::gist::code::success)
        {
            detail::event_tracking(level::warn, std::format("[SOCKS5] Handshake failed: {}", ngx::gist::describe(ec)));
            co_return;
        }

        // 构造 target 对象
        protocol::analysis::target target(ctx.frame_arena.get());
        auto host_str = protocol::socks5::to_string(request.destination_address, ctx.frame_arena.get());
        target.host = std::move(host_str);
        target.port.assign(std::to_string(request.destination_port));
        target.forward_proxy = true;

        const std::string label = std::format("[SOCKS5] {}:{}", target.host, target.port);
        detail::event_tracking(level::info, label);

        if (co_await connect_upstream(ctx, "SOCKS5", target, true, true))
        {
            co_await agent->send_success(request);
            ctx.client_socket = std::move(agent->socket());
            co_await original_tunnel(ctx);
        }
        else
        {
            co_await agent->send_error(protocol::socks5::reply_code::host_unreachable);
        }
    }

    /**
     * @brief 处理 Obscura
     */
    template <typename Context, typename Stream>
    auto obscura(Context &ctx, std::shared_ptr<Stream> stream, std::string_view pre_read_data) -> net::awaitable<void>
    {
        ctx.frame_arena.reset();
        auto mr = ctx.frame_arena.get();
        auto proto = std::make_shared<transport::obscura<tcp>>(stream, transport::role::server);
        std::string target_path;
        detail::event_tracking(level::debug, "[Handler] Obscura handshake with preread data started.");
        try
        {
            target_path = co_await proto->handshake_preread(pre_read_data);
        }
        catch (...)
        {
            detail::event_tracking(level::warn, "[Handler] Obscura handshake failed.");
            co_return;
        }

        if (target_path.starts_with('/'))
        {
            target_path.erase(0, 1);
        }

        if (!target_path.empty())
        {
            const auto message = std::format("[Handler] Obscura target path: `{}`", target_path);
            detail::event_tracking(level::debug, message);
        }

        const auto target = protocol::analysis::resolve(std::string_view(target_path), mr);
        if (target.host.empty())
        {
            detail::event_tracking(level::warn, "[Handler] Obscura resolve failed: empty host.");
            co_return;
        }

        {
            const auto message = std::format("[Handler] Obscura upstream resolving: {}:{}", target.host, target.port);
            detail::event_tracking(level::info, message);
        }

        const bool connected = co_await connect_upstream(ctx, "Obscura", target, false, true);
        if (!connected)
        {
            co_return;
        }

        ctx.frame_arena.reset();

        co_await detail::tunnel::obscura(std::move(proto), *ctx.server_socket,
                                         ctx.buffer.data(), ctx.buffer.size());

        shut_close(ctx.server_socket);
    }

    /**
     * @brief 处理 Trojan
     */
    template <typename Context, typename Stream>
    auto trojan(Context &ctx, std::shared_ptr<Stream> stream, std::string_view pre_read_data) -> net::awaitable<void>
    {
        // 构造 Trojan 代理 (使用已握手的 stream)
        using Transport = typename Context::socket_type;
        auto agent = std::make_shared<protocol::trojan::stream<Transport>>(stream, ctx.password_verifier);

        // 1. 握手 (带预读数据)
        auto [ec, info] = co_await agent->handshake_preread(pre_read_data);
        if (ec != ngx::gist::code::success)
        {
            detail::event_tracking(level::warn, std::format("[Trojan] Handshake failed: {}", ngx::gist::describe(ec)));
            co_return;
        }

        // 2. 解析目标
        protocol::analysis::target target(ctx.frame_arena.get());
        auto host_str = protocol::trojan::to_string(info.destination_address, ctx.frame_arena.get());
        target.host = std::move(host_str);
        target.port.assign(std::to_string(info.port));
        target.forward_proxy = true;

        const std::string label = std::format("[Trojan] {}:{}", target.host, target.port);
        detail::event_tracking(level::info, label);

        // 3. 连接上游
        if (co_await connect_upstream(ctx, "Trojan", target, true, true))
        {
            // 4. 建立隧道 (SSL Stream <-> TCP Socket)
            auto &client_stream = agent->get_stream();
            auto &server_socket = *ctx.server_socket;

            // 定义单向转发 lambda
            auto forward = [](auto &read_stream, auto &write_stream) -> net::awaitable<void>
            {
                std::array<char, 8192> buf{};
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                while (true)
                {
                    ec.clear();
                    const auto n = co_await read_stream.async_read_some(net::buffer(buf), token);
                    if (ec || n == 0)
                    {
                        co_return;
                    }

                    ec.clear();
                    co_await net::async_write(write_stream, net::buffer(buf, n), token);
                    if (ec)
                    {
                        co_return;
                    }
                }
            };

            // 并行执行双向转发
            using namespace boost::asio::experimental::awaitable_operators;
            co_await (
                forward(client_stream, server_socket) &&
                forward(server_socket, client_stream));

            // 5. 清理
            shut_close(ctx.server_socket);
            co_await agent->close();
        }

        ctx.server_socket.reset();
    }

    /**
     * @brief 处理 TLS
     */
    template <typename Context>
    auto tls(Context &ctx) -> net::awaitable<void>
    {
        if (!ctx.ssl_ctx)
        {
            detail::event_tracking(level::warn, "[Handler] TLS disabled: ssl context is missing.");
            co_return;
        }

        // 1. 执行 SSL 握手 (统一入口)
        using Transport = typename Context::socket_type;
        auto ssl_stream = std::make_shared<ssl::stream<Transport>>(std::move(ctx.client_socket), *ctx.ssl_ctx);

        boost::system::error_code ec;
        co_await ssl_stream->async_handshake(ssl::stream_base::server, net::redirect_error(net::use_awaitable, ec));
        if (ec)
        {
            detail::event_tracking(level::warn, "[Handler] TLS handshake failed.");
            co_return;
        }

        // 2. 二次探测 (Peek 解密后的数据)
        std::array<char, 24> peek_buf{};
        std::size_t n = 0;
        n = co_await ssl_stream->async_read_some(net::buffer(peek_buf), net::redirect_error(net::use_awaitable, ec));
        if (ec)
        {
            co_return;
        }

        std::string_view peek_view(peek_buf.data(), n);

        bool is_http = false;
        static constexpr std::array<std::string_view, 9> http_methods =
            {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS ", "TRACE ", "PATCH "};

        for (const auto &method : http_methods)
        {
            if (peek_view.size() >= method.size() && peek_view.substr(0, method.size()) == method)
            {
                is_http = true;
                break;
            }
        }

        if (is_http)
        {
            detail::event_tracking(level::debug, "[Handler] TLS payload detected as HTTP/WebSocket (Obscura).");
            co_await obscura(ctx, ssl_stream, peek_view);
        }
        else
        {
            detail::event_tracking(level::debug, "[Handler] TLS payload detected as Trojan.");
            co_await trojan(ctx, ssl_stream, peek_view);
        }
    }
}
