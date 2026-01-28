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

#include <abnormal.hpp>
#include <memory/pool.hpp>
#include <forward-engine/agent/distributor.hpp>
#include <forward-engine/protocol/analysis.hpp>
#include <forward-engine/agent/handler.hpp>

namespace ngx::agent
{
    namespace net = boost::asio;
    namespace ssl = boost::asio::ssl;
    
    // Transport detail alias
    namespace detail = ngx::transport::detail;
    using tcp = boost::asio::ip::tcp;
    using level = detail::log_level;
    using unique_sock = transport::unique_sock;

    /**
     * @brief 会话管理类
     * @tparam Transport socket 类型
     * @note 作为会话管理类，负责管理与目标服务器（或客户端）的连接，自动处理代理转发和http请求
     */
    template <transport::SocketConcept Transport>
    class session : public std::enable_shared_from_this<session<Transport>>
    {
    public:
        using socket_type = Transport;

        explicit session(net::io_context &io_context, socket_type socket, 
            distributor &dist, std::shared_ptr<ssl::context> ssl_ctx);
        virtual ~session();

        void start();
        void close();

        static void registered_log_function(std::function<void(level, std::string_view)> trace) noexcept;

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

        [[nodiscard]] auto create_context() -> session_context<Transport>
        {
            return make_session_context<Transport>(
                io_context_,
                client_socket_,
                server_socket_ptr_,
                distributor_,
                ssl_ctx_,
                frame_arena_,
                std::span<std::byte>(buffer_),
                password_verifier_);
        }

        auto diversion() -> net::awaitable<void>;

        net::io_context &io_context_;
        std::shared_ptr<ssl::context> ssl_ctx_;
        distributor &distributor_;
        socket_type client_socket_;              // 客户端连接
        unique_sock server_socket_ptr_; // 服务器连接

        std::array<std::byte, 16384> buffer_{};
        memory::frame_arena frame_arena_;
        std::function<bool(std::string_view)> password_verifier_;
    }; // class session

    template <transport::SocketConcept Transport>
    session<Transport>::session(net::io_context &io_context, socket_type socket, distributor &dist,
                                std::shared_ptr<ssl::context> ssl_ctx)
        : io_context_(io_context), ssl_ctx_(std::move(ssl_ctx)), distributor_(dist),
          client_socket_(std::move(socket)) {}

    template <transport::SocketConcept Transport>
    session<Transport>::~session()
    {
        close();
    }

    template <transport::SocketConcept Transport>
    void session<Transport>::registered_log_function(std::function<void(level, std::string_view)> trace) noexcept
    {
        detail::tracker = std::move(trace);
    }

    template <transport::SocketConcept Transport>
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

    template <transport::SocketConcept Transport>
    void session<Transport>::close()
    {
        detail::event_tracking(level::debug, "[Session] Session closing.");
        detail::shut_close(client_socket_);
        if (server_socket_ptr_)
        {
            detail::shut_close(*server_socket_ptr_);
            server_socket_ptr_.reset();
        }
    }

    template <transport::SocketConcept Transport>
    auto session<Transport>::diversion() -> net::awaitable<void>
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
            detail::event_tracking(level::warn, "[Session] Peek failed.");
            close();
            co_return;
        }

        {
            const auto message = std::format("[Session] Peeked `{}` bytes.", n);
            detail::event_tracking(level::debug, message);
        }

        // 构造 context
        auto ctx = create_context();

        // 2. 识别协议 (调用 analysis)
        const auto type = protocol::analysis::detect(std::string_view(peek_buf.data(), n));

        // 3. 分流
        if (type == protocol::protocol_type::http)
        {
            detail::event_tracking(level::debug, "[Session] Detected protocol: http.");
            co_await handler::http(ctx);
        }
        else if (type == protocol::protocol_type::socks5)
        {
            detail::event_tracking(level::debug, "[Session] Detected protocol: socks5.");
            co_await handler::socks5(ctx);
        }
        else if (type == protocol::protocol_type::tls)
        {
            detail::event_tracking(level::debug, "[Session] Detected protocol: tls (Trojan/Obscura).");
            co_await handler::tls(ctx);
        }
        else
        {
            detail::event_tracking(level::warn, "[Session] Unknown protocol detected.");
        }
    }

}
