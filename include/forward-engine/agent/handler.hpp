/**
 * @file handler.hpp
 * @brief 会话处理逻辑
 * @details 定义了各种协议（`HTTP`、`SOCKS5`、`Trojan`、`TLS`、`Obscura`）的具体处理函数。
 *
 * 该文件以 `Boost.Asio` 协程 (`net::awaitable`) 作为基础抽象，每个处理函数通常具备如下职责：
 * - 从客户端连接读取并解析握手/请求；
 * - 调用 `distributor` 执行路由（`route_forward`/`route_reverse`），获取到上游连接；
 * - 按协议要求回复客户端，并启动数据转发（原始 `TCP` 或 `Obscura` 隧道）。
 *
 * @note 该文件主要由模板与 `inline` 协程组成，变更会影响所有包含它的编译单元。
 */
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

#include <forward-engine/gist.hpp>
#include <forward-engine/memory/pool.hpp>
#include <forward-engine/agent/validator.hpp>
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

    namespace detail = transport::detail;
    namespace protocol_http = protocol::http;

    using tcp = boost::asio::ip::tcp;
    using level = detail::log_level;
    using unique_sock = transport::unique_sock;

    /**
     * @brief 会话上下文
     * @tparam Transport 传输层 `socket` 类型
     * @details 包含 Handler 模块运行所需的所有资源引用，不负责生命周期管理，仅作为上下文传递。
     */
    template <transport::SocketConcept Transport>
    struct session_context
    {
        using socket_type = Transport;
        using unique_sock = transport::unique_sock;

        net::io_context &io_context; // 全局 IO 上下文
        socket_type &client_socket; // 客户端连接
        unique_sock &server_socket; // 服务端连接 (智能指针)
        distributor &distributor_ref; // 分发器引用
        std::shared_ptr<ssl::context> ssl_ctx; // SSL 上下文 (可选)
        memory::frame_arena &frame_arena; // 帧内存池
        std::span<std::byte> buffer; // 共享缓冲区
        std::function<bool(std::string_view)> &credential_verifier; // 凭据验证回调
        validator *account_validator_ptr{nullptr};
    }; // struct session_context

    /**
     * @brief 创建会话上下文的辅助函数
     * @tparam Transport 传输层 `socket` 类型
     * @param io_context IO 上下文
     * @param client_socket 客户端 `socket`
     * @param server_socket 服务器 `socket` (包装在 `unique_sock` 中)
     * @param distributor_ref 分发器引用
     * @param ssl_ctx SSL 上下文
     * @param frame_arena 内存池
     * @param buffer 缓冲区
     * @param credential_verifier 用户凭据验证器
     * @param account_validator_ptr 账户验证器
     * @return session_context<Transport> 构造完成的会话上下文
     */
    template <transport::SocketConcept Transport>
    [[nodiscard]] auto make_session_context( net::io_context &io_context,
        Transport &client_socket, transport::unique_sock &server_socket,
        distributor &distributor_ref, std::shared_ptr<ssl::context> ssl_ctx,
        memory::frame_arena &frame_arena, std::span<std::byte> buffer,
        std::function<bool(std::string_view)> &credential_verifier,
        validator *account_validator_ptr) 
            -> session_context<Transport>
    {
        return session_context<Transport>
        {
            io_context, client_socket, server_socket,
            distributor_ref, ssl_ctx, frame_arena,
            buffer, credential_verifier, account_validator_ptr
        };
    }
} // namespace ngx::agent

/**
 * @namespace ngx::agent::handler
 * @brief 协议处理器集合 (Protocol Handlers)
 * @details 提供针对不同应用层协议（HTTP, SOCKS5, TLS/Trojan/Obscura）的处理逻辑。
 * 每个 handler 都是一个无状态的异步协程，接受 `session_context` 作为输入，
 * 完成协议握手、路由决策和数据转发。
 * @see session
 */
namespace ngx::agent::handler
{
    using namespace ngx::agent;

    /**
     * @brief 关闭连接辅助函数 (unique_ptr 版本)
     * @details 关闭 `socket` 并释放资源，内部调用 `detail::shut_close`。
     * @tparam Socket 套接字类型
     * @param socket_ptr 指向 `socket` 的唯一指针
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

    /**
     * @brief 关闭连接辅助函数 (引用版本)
     * @tparam Socket 套接字类型
     * @param socket `socket` 对象引用
     */
    template <typename Socket>
    void shut_close(Socket &socket) noexcept
    {
        detail::shut_close(socket);
    }

    /**
     * @brief 关闭会话资源
     * @details 同时关闭客户端和服务端的连接。
     * @tparam Context 会话上下文类型
     * @param ctx 会话上下文
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
     * @details 根据目标信息，选择正向代理或反向代理方式连接上游。
     * @tparam Context 会话上下文类型
     * @param ctx 会话上下文
     * @param label 日志标签 (用于区分协议)
     * @param target 目标地址信息
     * @param allow_reverse 是否允许反向代理
     * @param require_open 是否要求连接必须处于打开状态
     * @return `bool` 连接是否成功
     */
    template <typename Context>
    auto connect_upstream(Context &ctx, std::string_view label, const protocol::analysis::target &target,
        const bool allow_reverse, const bool require_open) 
        -> net::awaitable<bool>
    {
        auto ec = gist::code::success;
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
     * @details 在客户端和服务端之间双向转发数据，直到一方断开。
     * @tparam Context 会话上下文类型
     * @param ctx 会话上下文
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

        if (ctx.buffer.size() < 2)
        {
            detail::event_tracking(level::error, "[Handler] raw tunnel: buffer too small.");
            co_return;
        }

        try
        {
            detail::tunnel t;
            co_await t.stream(tunnel_ctx, ctx.buffer.data(), ctx.buffer.size());
        }
        catch (const std::exception &e)
        {
            detail::event_tracking(level::warn, std::format("[Handler] raw tunnel error: {}", e.what()));
        }

        shut_close(ctx.server_socket);
    }

    /**
     * @brief 隧道 TCP 流量 (Obscura 协议升级)
     * @details 处理 Obscura 协议的隧道传输。
     * @tparam Context 会话上下文类型
     * @param ctx 会话上下文
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

        try
        {
            co_await detail::tunnel::stream(tunnel_ctx, ctx.buffer.data(), ctx.buffer.size());
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
     * @details 解析 HTTP 请求，支持 CONNECT 方法建立隧道，或者转发普通 HTTP 请求。
     * @tparam Context 会话上下文类型
     * @param ctx 会话上下文
     */
    template <typename Context>
    auto http(Context &ctx) -> net::awaitable<void>
    {
        ctx.frame_arena.reset();
        auto mr = ctx.frame_arena.get();
        beast::basic_flat_buffer read_buffer(protocol_http::network_allocator{mr});
        {
            protocol_http::request req(mr);
            detail::event_tracking(level::debug, "[Handler] Waiting for HTTP request...");
            const auto ec = co_await protocol_http::async_read(ctx.client_socket, req, read_buffer, mr);

            if (ec != gist::code::success)
            {
                detail::event_tracking(level::warn, std::format("[Handler] HTTP read failed: {}", gist::describe(ec)));
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
            if (req.method() == protocol_http::verb::connect)
            {
                boost::system::error_code error;
                auto token = net::redirect_error(net::use_awaitable, error);
                constexpr  std::string_view resp = {"HTTP/1.1 200 Connection Established\r\n\r\n"};
                co_await transport::adaptation::async_write(ctx.client_socket, net::buffer(resp), token);
                if (error && !detail::normal_close(error))
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
            // 序列化发送
            const auto data = protocol_http::serialize(req, mr);
            boost::system::error_code error;
            auto token = net::redirect_error(net::use_awaitable, error);
            co_await transport::adaptation::async_write(*ctx.server_socket, net::buffer(data), token);
            if (error && !detail::normal_close(error))
            {
                detail::event_tracking(level::warn, "[Handler] HTTP request forward failed.");
                close_session(ctx);
                co_return;
            }

            if (read_buffer.size() != 0)
            {
                const auto message = std::format("[Handler] Forwarding {} bytes of prefetched data.", read_buffer.size());
                detail::event_tracking(level::debug, message);
                boost::system::error_code code;
                auto redirect_error = net::redirect_error(net::use_awaitable, code);
                co_await transport::adaptation::async_write(*ctx.server_socket, read_buffer.data(), redirect_error);
                if (code && !detail::normal_close(code))
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
     * @details 执行 SOCKS5 握手，解析目标地址并建立连接。
     * @tparam Context 会话上下文类型
     * @param ctx 会话上下文
     */
    template <typename Context>
    auto socks5(Context &ctx) -> net::awaitable<void>
    {
        auto agent = std::make_shared<protocol::socks5::stream<typename Context::socket_type>>(std::move(ctx.client_socket));
        auto [ec, request] = co_await agent->handshake();

        if (ec != gist::code::success)
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
     * @brief 处理 Obscura 协议
     * @details 执行 Obscura 握手，解析目标地址并建立连接。
     * @tparam Context 会话上下文类型
     * @tparam Stream 抽象流类型 (通常是 SSL stream)
     * @param ctx 会话上下文
     * @param stream 已经建立的流
     * @param pre_read_data 预读的数据
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
     * @brief 处理 Trojan 协议
     * @details 执行 Trojan 握手，解析目标地址并建立隧道。
     * @tparam Context 会话上下文类型
     * @tparam Stream 抽象流类型 (通常是 SSL stream)
     * @param ctx 会话上下文
     * @param stream 已经建立的流
     * @param pre_read_data 预读的数据
     */
    template <typename Context, typename Stream>
    auto trojan(Context &ctx, std::shared_ptr<Stream> stream, std::string_view pre_read_data) -> net::awaitable<void>
    {
        // 构造 Trojan 代理 (使用已握手的 stream)
        using Transport = typename Context::socket_type;
        auto agent = std::make_shared<protocol::trojan::stream<Transport>>(stream, ctx.credential_verifier);

        // 1. 握手 (带预读数据)
        auto [ec, info] = co_await agent->handshake_preread(pre_read_data);
        if (ec != gist::code::success)
        {
            detail::event_tracking(level::warn, std::format("[Trojan] Handshake failed: {}", ngx::gist::describe(ec)));
            co_return;
        }

        validator::traffic_metrics *user_state_ptr = nullptr;
        if (ctx.account_validator_ptr)
        {
            const std::string_view credential_view(info.credential.data(), info.credential.size());
            validator::protector user_session = ctx.account_validator_ptr->try_acquire(credential_view);
            if (!user_session)
            {
                detail::event_tracking(level::warn, "[Trojan] Connection rejected by account validator.");
                co_return;
            }
            user_state_ptr = user_session.state();
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
            auto *validator_ptr = ctx.account_validator_ptr;

            // 定义单向转发 lambda
            auto forward = [validator_ptr, user_state_ptr](auto &read_stream, auto &write_stream, const bool uplink) -> net::awaitable<void>
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

                    if (validator_ptr && user_state_ptr)
                    {
                        if (uplink)
                        {
                            validator_ptr->accumulate_uplink(user_state_ptr, n);
                        }
                        else
                        {
                            validator_ptr->accumulate_downlink(user_state_ptr, n);
                        }
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
            co_await (forward(client_stream, server_socket, true) || forward(server_socket, client_stream, false));

            // 5. 清理
            shut_close(ctx.server_socket);
            co_await agent->close();
        }

        ctx.server_socket.reset();
    }

    /**
     * @brief 处理 TLS 连接
     * @details 执行 TLS 握手，然后根据内容探测协议 (HTTP/WebSocket -> Obscura, 其他 -> Trojan)。
     * @tparam Context 会话上下文类型
     * @param ctx 会话上下文
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
