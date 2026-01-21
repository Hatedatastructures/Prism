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

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <abnormal.hpp>
#include <memory/pool.hpp>
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
    namespace http_proto = ngx::protocol::http;

    // Transport detail alias
    namespace detail = ngx::transport::detail;
    using tcp = boost::asio::ip::tcp;
    using level = detail::log_level;
    using exclusive_connection = transport::exclusive_connection;

    /**
     * @brief 会话管理类
     * @tparam Transport socket 类型
     * @note 作为会话管理类，负责管理与目标服务器（或客户端）的连接，自动处理代理转发和http请求
     */
    template <transport::SocketConcept SocketType>
    class session : public std::enable_shared_from_this<session<SocketType>>
    {
    public:
        using socket_type = SocketType;

        explicit session(net::io_context &io_context, socket_type socket, distributor &dist,
                         std::shared_ptr<ssl::context> ssl_ctx);
        virtual ~session();

        void start();
        void close();

        void registered_log_function(std::function<void(level, std::string_view)> trace) noexcept;

        /**
         * @brief 设置密码验证回调
         * @param verifier 验证函数
         */
        void set_password_verifier(std::function<bool(std::string_view)> verifier)
        {
            this->password_verifier_ = std::move(verifier);
        }

    private:
        using mutable_buf = net::mutable_buffer;
        using cancellation_slot = net::cancellation_slot;
        using cancellation_signal = net::cancellation_signal;

        /**
         * @brief 关闭 exclusive_connection 管理的 socket
         * @details 尝试正常关闭 socket，如果失败则强制关闭。
         */
        static void shut_close(const exclusive_connection &socket_ptr) noexcept
        {
            if (socket_ptr)
            {
                detail::shut_close(*socket_ptr);
            }
        }

        net::awaitable<void> diversion();
        net::awaitable<void> tunnel();
        net::awaitable<void> raw_tunnel();

        net::awaitable<bool> connect_upstream(std::string_view label, const protocol::analysis::target &target,
                                              bool allow_reverse, bool require_open);

        net::awaitable<void> handle_http();
        net::awaitable<void> handle_socks5();

        net::awaitable<void> handle_tls();

        net::awaitable<void> handle_obscura_with_stream(std::shared_ptr<ssl::stream<SocketType>> stream, std::string_view pre_read_data);
        net::awaitable<void> handle_trojan_with_stream(std::shared_ptr<ssl::stream<SocketType>> stream, std::string_view pre_read_data);

        net::io_context &io_context_;
        std::shared_ptr<ssl::context> ssl_ctx_;
        distributor &distributor_;
        socket_type client_socket_;              // 客户端连接
        exclusive_connection server_socket_ptr_; // 服务器连接

        std::array<std::byte, 16384> buffer_{};
        ngx::memory::frame_arena frame_arena_;
        std::function<bool(std::string_view)> password_verifier_;
    }; // class session
}

namespace ngx::agent
{
    template <transport::SocketConcept SocketType>
    session<SocketType>::session(net::io_context &io_context, socket_type socket, distributor &dist,
                                 std::shared_ptr<ssl::context> ssl_ctx)
        : io_context_(io_context), ssl_ctx_(std::move(ssl_ctx)), distributor_(dist),
          client_socket_(std::move(socket)) {}

    template <transport::SocketConcept Transport>
    session<Transport>::~session()
    {
        close();
    }

    /**
     * @brief 注册日志函数
     * @param trace 日志函数
     * @details 该函数用于注册日志函数，以便在会话中记录日志。
     * @warning 该函数必须在会话启动前调用，否则会什么也不记录。
     */
    template <transport::SocketConcept SocketType>
    void session<SocketType>::registered_log_function(std::function<void(level, std::string_view)> trace) noexcept
    {
        detail::tracker = std::move(trace);
    }

    /**
     * @brief 启动会话
     * @details 该函数会启动会话，开始处理客户端请求。
     */
    template <transport::SocketConcept SocketType>
    void session<SocketType>::start()
    {
        detail::event_tracking(level::info, "[Session] Session started.");
        auto process = [self = this->shared_from_this()]() -> net::awaitable<void>
        {
            co_await self->diversion();
        };
        auto completion = [self = this->shared_from_this()](const std::exception_ptr &ep) noexcept
        {
            if (!ep)
            {
                return;
            }

            try
            {
                std::rethrow_exception(ep);
            }
            catch (const abnormal::exception &e)
            {
                const auto message = e.dump();
                detail::event_tracking(level::error, message);
            }
            catch (const std::exception &e)
            {
                detail::event_tracking(level::error, e.what());
            }

            self->close();
        };

        net::co_spawn(io_context_, std::move(process), std::move(completion));
    }

    /**
     * @brief 关闭会话
     * @details 该函数会关闭与目标服务器（或客户端）的连接，释放相关资源。
     */
    template <transport::SocketConcept SocketType>
    void session<SocketType>::close()
    {
        detail::event_tracking(level::debug, "[Session] Session closing.");
        detail::shut_close(client_socket_);
        shut_close(server_socket_ptr_);
        server_socket_ptr_.reset();
    }

    /**
     * @brief 会话分发器
     * @details 该函数会根据请求协议类型，选择相应的处理函数。
     */
    template <transport::SocketConcept SocketType>
    net::awaitable<void> session<SocketType>::diversion()
    {
        boost::system::error_code ec;

        // 1. 偷看数据 (Peek)
        std::array<char, 24> peek_buf{};
        auto buf = net::buffer(peek_buf);
        auto token = net::redirect_error(net::use_awaitable, ec);
        const std::size_t n = co_await client_socket_.async_receive(buf, tcp::socket::message_peek, token);
        if (ec)
        {
            if (detail::normal_close(ec))
            {
                co_return;
            }
            throw abnormal::network("diversion peek failed: {}", ec.message());
        }

        {
            const auto message = std::format("[Session] Peeked `{}` bytes.", n);
            detail::event_tracking(level::debug, message);
        }

        // 2. 识别协议 (调用 analysis)
        const auto type = protocol::analysis::detect(std::string_view(peek_buf.data(), n));

        // 3. 分流
        if (type == protocol::protocol_type::http)
        {
            detail::event_tracking(level::debug, "[Session] Detected protocol: http.");
            co_await handle_http();
        }
        else if (type == protocol::protocol_type::socks5)
        {
            detail::event_tracking(level::debug, "[Session] Detected protocol: socks5.");
            co_await handle_socks5();
        }
        else if (type == protocol::protocol_type::tls)
        {
            detail::event_tracking(level::debug, "[Session] Detected protocol: tls (Trojan/Obscura).");
            co_await handle_tls();
        }
        else
        {
            detail::event_tracking(level::warn, "[Session] Unknown protocol detected.");
        }
    }

    template <transport::SocketConcept SocketType>
    net::awaitable<void> session<SocketType>::handle_tls()
    {
        if (!ssl_ctx_)
        {
            detail::event_tracking(level::warn, "[Session] TLS disabled: ssl context is missing.");
            co_return;
        }

        // 1. 执行 SSL 握手 (统一入口)
        auto ssl_stream = std::make_shared<ssl::stream<SocketType>>(std::move(client_socket_), *ssl_ctx_);

        try
        {
            co_await ssl_stream->async_handshake(ssl::stream_base::server, net::use_awaitable);
        }
        catch (const std::exception &e)
        {
            detail::event_tracking(level::warn, std::format("[Session] TLS handshake failed: {}", e.what()));
            co_return;
        }

        // 2. 二次探测 (Peek 解密后的数据)
        std::array<char, 24> peek_buf{};
        std::size_t n = 0;
        try
        {
            n = co_await ssl_stream->async_read_some(net::buffer(peek_buf), net::use_awaitable);
        }
        catch (const std::exception &e)
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
            detail::event_tracking(level::debug, "[Session] TLS payload detected as HTTP/WebSocket (Obscura).");
            co_await this->handle_obscura_with_stream(ssl_stream, peek_view);
        }
        else
        {
            detail::event_tracking(level::debug, "[Session] TLS payload detected as Trojan.");
            co_await this->handle_trojan_with_stream(ssl_stream, peek_view);
        }
    }

    template <transport::SocketConcept SocketType>
    net::awaitable<void> session<SocketType>::handle_obscura_with_stream(std::shared_ptr<ssl::stream<SocketType>> stream, std::string_view pre_read_data)
    {
        frame_arena_.reset();
        auto mr = frame_arena_.get();
        auto proto = std::make_shared<transport::obscura<tcp>>(stream, transport::role::server);
        std::string target_path;
        try
        {
            detail::event_tracking(level::debug, "[Session] Obscura handshake with preread data started.");
            target_path = co_await proto->handshake_with_preread(pre_read_data);
        }
        catch (const boost::system::system_error &e)
        {
            throw abnormal::protocol("obscura handshake failed: {}", e.code().message());
        }
        catch (const std::exception &e)
        {
            throw abnormal::protocol("obscura handshake failed: {}", e.what());
        }

        if (target_path.starts_with('/'))
        {
            target_path.erase(0, 1);
        }

        if (!target_path.empty())
        {
            const auto message = std::format("[Session] Obscura target path: `{}`", target_path);
            detail::event_tracking(level::debug, message);
        }

        const auto target = protocol::analysis::resolve(std::string_view(target_path), mr);
        if (target.host.empty())
        {
            detail::event_tracking(level::warn, "[Session] Obscura resolve failed: empty host.");
            co_return;
        }

        {
            const auto message = std::format("[Session] Obscura upstream resolving: {}:{}", target.host, target.port);
            detail::event_tracking(level::info, message);
        }

        const bool connected = co_await connect_upstream("Obscura", target, false, true);
        if (!connected)
        {
            co_return;
        }

        frame_arena_.reset();

        std::exception_ptr error;
        try
        {
            co_await detail::tunnel::obscura(std::move(proto), *server_socket_ptr_,
                                             buffer_.data(), buffer_.size());
        }
        catch (...)
        {
            error = std::current_exception();
        }

        detail::shut_close(*server_socket_ptr_);
        server_socket_ptr_.reset();

        if (error)
        {
            std::rethrow_exception(error);
        }
    }

    template <transport::SocketConcept SocketType>
    net::awaitable<void> session<SocketType>::handle_trojan_with_stream(std::shared_ptr<ssl::stream<SocketType>> stream, std::string_view pre_read_data)
    {
        // 构造 Trojan 代理 (使用已握手的 stream)
        // 如果没有设置验证器，传递 nullptr (trojan 内部默认不验证，或者我们可以提供一个默认允许的验证器)
        // 但根据 TODO，我们希望这里能用上配置
        auto agent = std::make_shared<protocol::trojan::stream<SocketType>>(stream, password_verifier_);

        try
        {
            // 1. 握手 (带预读数据)
            auto info = co_await agent->handshake_with_preread(pre_read_data);

            // 2. 解析目标
            protocol::analysis::target target(frame_arena_.get());
            target.host.assign(info.host.begin(), info.host.end());
            target.port.assign(std::to_string(info.port));
            target.forward_proxy = true;

            const std::string label = std::format("[Trojan] {}:{}", target.host, target.port);
            detail::event_tracking(level::info, label);

            // 3. 连接上游
            if (co_await connect_upstream("Trojan", target, true, true))
            {
                // 4. 建立隧道 (SSL Stream <-> TCP Socket)
                auto &client_stream = agent->get_stream();
                auto &server_socket = *server_socket_ptr_;

                // 定义单向转发 lambda
                auto forward = [](auto &read_stream, auto &write_stream) -> net::awaitable<void>
                {
                    try
                    {
                        std::array<char, 8192> buf;
                        while (true)
                        {
                            auto n = co_await read_stream.async_read_some(net::buffer(buf), net::use_awaitable);
                            co_await net::async_write(write_stream, net::buffer(buf, n), net::use_awaitable);
                        }
                    }
                    catch (...)
                    {
                        // 忽略连接断开错误
                    }
                };

                // 并行执行双向转发
                using namespace boost::asio::experimental::awaitable_operators;
                co_await (
                    forward(client_stream, server_socket) &&
                    forward(server_socket, client_stream));

                // 5. 清理
                detail::shut_close(server_socket);
                co_await agent->close();
            }
        }
        catch (const std::exception &e)
        {
            detail::event_tracking(level::error, std::format("[Trojan] Error: {}", e.what()));
        }

        server_socket_ptr_.reset();
    }

    template <transport::SocketConcept SocketType>
    net::awaitable<bool> session<SocketType>::connect_upstream(std::string_view label, const protocol::analysis::target &target,
                                                               const bool allow_reverse, const bool require_open)
    {
        if (allow_reverse && !target.forward_proxy)
        {
            server_socket_ptr_ = co_await distributor_.route_reverse(target.host);
        }
        else
        {
            server_socket_ptr_ = co_await distributor_.route_forward(target.host, target.port);
        }

        if (!server_socket_ptr_ || (require_open && !server_socket_ptr_->is_open()))
        {
            const auto message = std::format("[Session] {} route to upstream failed.", label);
            detail::event_tracking(level::error, message);
            co_return false;
        }

        const auto message = std::format("[Session] {} upstream connected.", label);
        detail::event_tracking(level::info, message);
        co_return true;
    }

    /**
     * @brief 处理HTTP请求
     * @details 该函数会从客户端读取HTTP请求，并根据请求类型进行相应的处理。
     */
    template <transport::SocketConcept SocketType>
    net::awaitable<void> session<SocketType>::handle_http()
    {
        frame_arena_.reset();
        auto mr = frame_arena_.get();
        beast::basic_flat_buffer<http_proto::network_allocator> read_buffer(http_proto::network_allocator{mr});
        {
            http_proto::request req(mr);
            detail::event_tracking(level::debug, "[Session] Waiting for HTTP request...");
            const bool success = co_await http_proto::async_read(client_socket_, req, read_buffer, mr);

            if (!success)
            {
                detail::event_tracking(level::warn, "[Session] HTTP read failed or connection closed.");
                co_return;
            }
            {
                const auto message = std::format("[Session] HTTP request received: {} {}", req.method_string(), req.target());
                detail::event_tracking(level::info, message);
            }
            //  连接上游
            const auto target = protocol::analysis::resolve(req);
            {
                const auto message = std::format("[Session] HTTP upstream resolving: forward_proxy=`{}` host=`{}` port=`{}`",
                                                 target.forward_proxy ? "true" : "false", target.host, target.port);
                detail::event_tracking(level::debug, message);
            }
            const bool connected = co_await connect_upstream("HTTP", target, true, false);
            if (!connected)
            {
                co_return;
            }

            // 转发
            if (req.method() == http_proto::verb::connect)
            {
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                const std::string resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
                co_await transport::adaptation::async_write(client_socket_, net::buffer(resp), token);
                if (ec && !detail::normal_close(ec))
                {
                    throw abnormal::network("CONNECT response send failed: {}", ec.message());
                }
                detail::event_tracking(level::info, "[Session] Sent 200 Connection Established.");

                // HTTP CONNECT 隧道应该是纯 TCP 透传
                detail::event_tracking(level::info, "[Session] Starting raw tunnel (HTTP CONNECT)...");
                co_await raw_tunnel();
                co_return;
            }
            else
            {
                // 序列化发送
                const auto data = http_proto::serialize(req, mr);
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                co_await transport::adaptation::async_write(*server_socket_ptr_, net::buffer(data), token);
                if (ec && !detail::normal_close(ec))
                {
                    throw abnormal::network("HTTP request forward failed: {}", ec.message());
                }
            }

            if (read_buffer.size() != 0)
            {
                const auto message = std::format("[Session] Forwarding {} bytes of prefetched data.", read_buffer.size());
                detail::event_tracking(level::debug, message);
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                co_await transport::adaptation::async_write(*server_socket_ptr_, read_buffer.data(), token);
                if (ec && !detail::normal_close(ec))
                {
                    throw abnormal::network("Prefetched data forward failed: {}", ec.message());
                }
                read_buffer.consume(read_buffer.size());
            }
        } // 限制request 生命周期防止在下面request指向无效的tcp字节流

        detail::event_tracking(level::info, "[Session] Starting tunnel (Obscura upgrade)...");
        co_await tunnel();
    }

    /**
     * @brief 处理 SOCKS5 请求
     */
    template <transport::SocketConcept SocketType>
    net::awaitable<void> session<SocketType>::handle_socks5()
    {
        try
        {
            auto agent = std::make_shared<protocol::socks5::stream<SocketType>>(std::move(client_socket_));
            auto target_info = co_await agent->handshake();

            // 构造 target 对象
            protocol::analysis::target target(frame_arena_.get());
            target.host.assign(target_info.host.begin(), target_info.host.end());
            target.port.assign(std::to_string(target_info.port));
            target.forward_proxy = true;

            const std::string label = std::format("[SOCKS5] {}:{}", target.host, target.port);
            detail::event_tracking(level::info, label);

            if (co_await connect_upstream("SOCKS5", target, true, true))
            {
                // 发送成功响应
                co_await agent->send_success(target_info);

                // 移回 socket
                client_socket_ = std::move(agent->socket());

                co_await raw_tunnel();
            }
            else
            {
                co_await agent->send_error(protocol::socks5::reply_code::host_unreachable);
            }
        }
        catch (const std::exception &e)
        {
            detail::event_tracking(level::error, std::format("[SOCKS5] Error: {}", e.what()));
            throw;
        }
    }

    /**
     * @brief 原始 TCP 隧道
     */
    template <transport::SocketConcept SocketType>
    net::awaitable<void> session<SocketType>::raw_tunnel()
    {
        if (!server_socket_ptr_)
        {
            detail::event_tracking(level::warn, "[Session] raw tunnel: no upstream connection.");
            co_return;
        }

        auto ctx = detail::make_tunnel_context(&*server_socket_ptr_, &client_socket_);
        detail::tunnel t;

        // 确保 buffer_ 大小足够
        if (buffer_.size() < 2)
        {
            detail::event_tracking(level::error, "[Session] raw tunnel: buffer too small.");
            co_return;
        }

        try
        {
            co_await t.stream(ctx, buffer_.data(), buffer_.size());
        }
        catch (const std::exception &e)
        {
            detail::event_tracking(level::warn, std::format("[Session] raw tunnel error: {}", e.what()));
        }

        detail::shut_close(*server_socket_ptr_);
        server_socket_ptr_.reset();
    }

    /**
     * @brief 隧道 TCP 流量 (Obscura)
     * @details 该函数会在客户端套接字和上游服务器套接字之间建立隧道，实现流量的双向传输。
     */
    template <transport::SocketConcept SocketType>
    net::awaitable<void> session<SocketType>::tunnel()
    {
        if (!server_socket_ptr_)
        {
            detail::event_tracking(level::warn, "[Tunnel] aborted: upstream socket is missing.");
            co_return;
        }

        frame_arena_.reset();

        auto ctx = detail::make_tunnel_context(server_socket_ptr_.get(), &client_socket_);
        detail::tunnel tunnel_unit;

        try
        {
            co_await tunnel_unit.stream(ctx, buffer_.data(), buffer_.size());
        }
        catch ([[maybe_unused]] const std::exception &e)
        {
            const auto message = std::format("[Tunnel] error: {}", e.what());
            detail::event_tracking(level::error, message);
            // 记录错误但继续清理
        }
        catch (...)
        {
            detail::event_tracking(level::error, "[Tunnel] unknown error.");
        }

        detail::shut_close(client_socket_);
        shut_close(server_socket_ptr_);
        server_socket_ptr_.reset();
    }

}
