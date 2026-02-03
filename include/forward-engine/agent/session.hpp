/**
 * @file session.hpp
 * @brief 会话管理
 * @details 定义了会话类，负责管理单个客户端连接的生命周期、协议识别和流量转发。
 */
#pragma once

#include <cstddef>
#include <cctype>

#include <array>
#include <vector>
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
     * @class session
     * @brief 会话管理类
     * @tparam Transport 客户端 `socket` 类型 (满足 SocketConcept 约束)
     * @details 代表一个活跃的客户端连接。它是一个**自持有** (`shared_from_this`) 的对象，
     * 这意味着只要异步操作未完成，它就不会析构。
     * 
     * **核心职责**：
     * 1. **预读 (Peek)**: 读取少量数据以识别协议特征。
     * 2. **协议识别**: 区分 HTTP, SOCKS5, TLS (Trojan/Obscura)。
     * 3. **任务分派**: 将识别后的连接移交给对应的 `handler` 处理。
     * 4. **内存优化**: 采用 `lazy allocation` 策略，仅在需要时分配缓冲区，并使用线程独占内存池。
     * 
     * @see handler
     */
    template <transport::SocketConcept Transport>
    class session : public std::enable_shared_from_this<session<Transport>>
    {
    public:
        using socket_type = Transport;
        using unique_sock = transport::unique_sock;

        /**
         * @brief 构造会话
         * @param io_context IO 上下文
         * @param socket 客户端连接
         * @param dist 业务分发器
         * @param ssl_ctx SSL 上下文 (可选)
         * @param resource 内存资源 (通常为线程局部池)
         */
        explicit session(net::io_context &io_context, socket_type socket, distributor &dist,
                         std::shared_ptr<ssl::context> ssl_ctx,
                         memory::resource_pointer resource);

        ~session();

        /**
         * @brief 启动会话
         * @details 开始异步处理流程。
         * **流程**：`start` -> `diversion` (预读&识别) -> `handler::xxx` (具体协议处理)。
         */
        void start();

        /**
         * @brief 关闭会话
         * @details 强制关闭所有关联的 socket (客户端和服务端) 并释放资源。
         * @note 该函数是幂等的，多次调用无副作用。
         */
        void close();

        /**
         * @brief 注册日志回调函数
         * @param trace 日志回调函数
         */
        static void registered_log_function(std::function<void(level, std::string_view)> trace) noexcept;

        /**
         * @brief 设置用户凭据验证回调
         * @param verifier 验证函数，输入用户凭据，返回验证结果
         */
        void set_credential_verifier(std::function<bool(std::string_view)> verifier)
        {
            this->credential_verifier_ = std::move(verifier);
        }

        void set_account_validator(validator *validator) noexcept
        {
            this->account_validator_ptr_ = validator;
        }

    private:
        using mutable_buf = net::mutable_buffer;
        using cancellation_slot = net::cancellation_slot;
        using cancellation_signal = net::cancellation_signal;

        [[nodiscard]] auto create_context() 
            -> session_context<Transport>
        {
            return make_session_context<Transport>(
                io_context_,
                client_socket_,
                server_socket_ptr_,
                distributor_,
                ssl_ctx_,
                frame_arena_,
                std::span<std::byte>(buffer_),
                credential_verifier_,
                account_validator_ptr_);
        }

        /**
         * @brief 协议分流
         * @details 预读部分数据，根据协议特征进行分流处理。
         * 这是一个异步操作，会挂起当前协程。
         */
        auto diversion() -> net::awaitable<void>;

        net::io_context &io_context_;
        std::shared_ptr<ssl::context> ssl_ctx_;
        distributor &distributor_;
        socket_type client_socket_;              // 客户端连接
        unique_sock server_socket_ptr_; // 服务器连接

        memory::vector<std::byte> buffer_;
        memory::frame_arena frame_arena_;
        std::function<bool(std::string_view)> credential_verifier_;
        validator *account_validator_ptr_{nullptr};
    }; // class session

    template <transport::SocketConcept Transport>
    session<Transport>::session(net::io_context &io_context, socket_type socket, distributor &dist,
                                std::shared_ptr<ssl::context> ssl_ctx,memory::resource_pointer resource)
        : io_context_(io_context), ssl_ctx_(std::move(ssl_ctx)), distributor_(dist),
          client_socket_(std::move(socket)), buffer_(resource) {}

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

        // 按需分配 IO 缓冲区 (16KB)
        buffer_.resize(16384);

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
