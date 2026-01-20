#pragma once
#include <cstddef>
#include <cctype>

#include <array>
#include <memory>
#include <string>
#include <format>
#include <utility>
#include <iostream>
#include <functional>
#include <string_view>

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <abnormal.hpp>
#include <memory/pool.hpp>
#include "analysis.hpp"
#include "obscura.hpp"
#include "source.hpp"
#include "adaptation.hpp"
#include <http/deserialization.hpp>
#include <http/serialization.hpp>
#include "transfer.hpp"


namespace ngx::agent
{
    using tcp = boost::asio::ip::tcp;
    using level = detail::log_level;


    /**
     * @brief 会话管理类
     * @tparam Transport socket 类型
     * @note 作为会话管理类，负责管理与目标服务器（或客户端）的连接，自动处理代理转发和http请求
     */
    template <SocketConcept Transport>
    class session : public std::enable_shared_from_this<session<Transport>>
    {
    public:
        using socket_type = Transport;

        explicit session(net::io_context &io_context, socket_type socket, distributor &dist,
        std::shared_ptr<ssl::context> ssl_ctx);
        virtual ~session();

        void start();
        void close();

        void registered_log_function(std::function<void(level, std::string_view)> trace) noexcept;
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

        net::awaitable<bool> connect_upstream(std::string_view label, const analysis::target &target,
            bool allow_reverse, bool require_open);

        net::awaitable<void> handle_http();
        net::awaitable<void> handle_obscura();

        
        net::io_context &io_context_;
        std::shared_ptr<ssl::context> ssl_ctx_;
        
        distributor &distributor_;
        socket_type client_socket_; // 客户端连接
        exclusive_connection server_socket_ptr_; // 服务器连接

        std::array<std::byte, 16384> buffer_{};
        ngx::memory::frame_arena frame_arena_;
    }; // class session
}

namespace ngx::agent
{
    template <SocketConcept Transport>
    session<Transport>::session(net::io_context &io_context, socket_type socket, distributor &dist,
        std::shared_ptr<ssl::context> ssl_ctx)
    : io_context_(io_context), ssl_ctx_(std::move(ssl_ctx)), distributor_(dist),
    client_socket_(std::move(socket)) {}

    template <SocketConcept Transport>
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
    template <SocketConcept Transport>
    void session<Transport>::registered_log_function(std::function<void(level, std::string_view)> trace) noexcept
    {
        detail::tracker = std::move(trace);
    }

    /**
     * @brief 启动会话
     * @details 该函数会启动会话，开始处理客户端请求。
     */
    template <SocketConcept Transport>
    void session<Transport>::start()
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
    template <SocketConcept Transport>
    void session<Transport>::close()
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
    template <SocketConcept Transport>
    net::awaitable<void> session<Transport>::diversion()
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
        const auto type = analysis::detect(std::string_view(peek_buf.data(), n));

        // 3. 分流
        if (type == protocol_type::http)
        {
            detail::event_tracking(level::debug, "[Session] Detected protocol: http.");
            co_await handle_http();
        }
        else
        {
            detail::event_tracking(level::debug, "[Session] Detected protocol: obscura.");
            co_await handle_obscura();
        }
    }

    template <SocketConcept Transport>
    net::awaitable<bool> session<Transport>::connect_upstream(std::string_view label, const analysis::target &target,
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
    template <SocketConcept Transport>
    net::awaitable<void> session<Transport>::handle_http()
    {
        frame_arena_.reset();
        auto mr = frame_arena_.get();
        beast::basic_flat_buffer<http::network_allocator> read_buffer(http::network_allocator{mr});
        {
            http::request req(mr);
            detail::event_tracking(level::debug, "[Session] Waiting for HTTP request...");
            const bool success = co_await http::async_read(client_socket_, req, read_buffer, mr);

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
            const auto target = analysis::resolve(req);
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
            if (req.method() == http::verb::connect)
            {
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                const std::string resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
                co_await adaptation::async_write(client_socket_, net::buffer(resp), token);
                if (ec && !detail::normal_close(ec))
                {
                    throw abnormal::network("CONNECT response send failed: {}", ec.message());
                }
                detail::event_tracking(level::info, "[Session] Sent 200 Connection Established.");
            }
            else
            {
                // 序列化发送
                const auto data = http::serialize(req, mr);
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                co_await adaptation::async_write(*server_socket_ptr_, net::buffer(data), token);
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
                co_await adaptation::async_write(*server_socket_ptr_, read_buffer.data(), token);
                if (ec && !detail::normal_close(ec))
                {
                    throw abnormal::network("Prefetched data forward failed: {}", ec.message());
                }
                read_buffer.consume(read_buffer.size());
            }
        } // 限制request 生命周期防止在下面request指向无效的tcp字节流
        
        detail::event_tracking(level::info, "[Session] Starting tunnel...");
        co_await tunnel();
    }

    /**
     * @brief 隧道 TCP 流量
     * @details 该函数会在客户端套接字和上游服务器套接字之间建立隧道，实现流量的双向传输。
     */
    template<SocketConcept Transport>
    net::awaitable<void> session<Transport>::tunnel()
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

    /**
     * @brief 处理 obscura 协议
     * @details 该函数会处理 obscura 协议，并建立与上游服务器的连接。
     */
    template <SocketConcept Transport>
    net::awaitable<void> session<Transport>::handle_obscura()
    {
        if (!ssl_ctx_)
        {
            detail::event_tracking(level::warn, "[Session] Obscura disabled: ssl context is missing.");
            co_return;
        }

        frame_arena_.reset();
        auto mr = frame_arena_.get();
        auto proto = std::make_shared<obscura<tcp>>(std::move(client_socket_), ssl_ctx_, role::server);
        std::string target_path;
        try
        {
            detail::event_tracking(level::debug, "[Session] Obscura handshake started.");
            target_path = co_await proto->handshake();
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

        const auto target = analysis::resolve(std::string_view(target_path), mr);
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

}
