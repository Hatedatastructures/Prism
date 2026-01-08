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

#include <memory/pool.hpp>

#include <boost/asio.hpp>
#include <abnormal.hpp>
#include "analysis.hpp"
#include "obscura.hpp"
#include "connection.hpp"
#include "adaptation.hpp"
#include <http/deserialization.hpp>
#include <http/serialization.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>


namespace ngx::agent
{
    using tcp = boost::asio::ip::tcp;

    /**
     * @brief 会话内部日志级别
     * @details 定义了会话过程中可能记录的日志级别，从调试到严重错误。
     */
    enum class level : std::uint8_t
    {
        debug,
        info,
        warn,
        error,
        fatal
    };

    /**
     * @brief 会话管理类
     * @tparam Transport socket 类型
     * @note 作为会话管理类，负责管理与目标服务器（或客户端）的连接，自动处理代理转发和http请求
     */
    template <socket_concept Transport>
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
         * @brief 判断 `boost::system::error_code` 是否属于“正常收尾”
         * @details “正常收尾”包括：对端正常关闭、被取消、连接被重置等。
         * 这些场景不应当转为业务异常抛出，否则会把正常断开误判为错误。
         */
        [[nodiscard]] static bool graceful(const boost::system::error_code &ec) noexcept
        {
            using namespace boost::asio;
            return ec == error::eof  || ec == error::operation_aborted || ec == error::connection_reset
                || ec == error::connection_aborted || ec == error::broken_pipe || ec == error::not_connected;
        }


        void log(level log_level, std::string_view message) const noexcept;

        /**
         * @brief 关闭 socket
         * @details 尝试正常关闭 socket，如果失败则强制关闭。
         */
        template <typename Socket>
        static void shut_close(Socket &socket) noexcept
        {
            if constexpr (requires { socket.is_open(); })
            {
                if (socket.is_open())
                {
                    boost::system::error_code ec;
                    if constexpr (requires { socket.shutdown(tcp::socket::shutdown_both, ec); })
                    {
                        socket.shutdown(tcp::socket::shutdown_both, ec);
                    }
                    socket.close(ec);
                }
            }
        }

        /**
         * @brief 关闭 exclusive_connection 管理的 socket
         * @details 尝试正常关闭 socket，如果失败则强制关闭。
         */
        static void shut_close(const exclusive_connection &socket_ptr) noexcept
        {
            if (socket_ptr)
            {
                shut_close(*socket_ptr);
            }
        }

        net::awaitable<void> diversion();
        net::awaitable<void> tunnel();

        net::awaitable<void> handle_http();
        net::awaitable<void> handle_obscura();

        net::awaitable<void> tunnel_obscura(std::shared_ptr<obscura<tcp>> proto);
        net::awaitable<void> transfer_obscura(obscura<tcp> &proto, cancellation_slot cancel_slot) const;
        net::awaitable<void> transfer_obscura(obscura<tcp> &proto, cancellation_slot cancel_slot, mutable_buf buffer) const;
        
        /**
         * @brief 从源读取数据并写入目标
         * @param from 源
         * @param to 目标
         * @param buffer 复用缓冲区（必须在 `co_await` 生命周期内保持有效）
         * @details 该函数会从源读取数据，并将数据写入目标。
         * 依赖协程的默认取消机制，不需要手动传递 cancellation_slot。
         */
        template <typename Source, typename Dest>
        net::awaitable<void> transfer_tcp(Source &from, Dest &to, mutable_buf buffer)
        {
            boost::system::error_code ec;
            auto token = net::redirect_error(net::use_awaitable, ec);

            while (true)
            {
                ec.clear();
                const std::size_t n = co_await from.async_read_some(buffer, token);
                if (ec)
                {
                    if (graceful(ec))
                    {   // 对端正常关闭或被取消
                        shut_close(to);
                        co_return;
                    }
                    throw abnormal::network("transfer_tcp 读失败: {}", ec.message());
                }

                if (n == 0)
                {   // 对端正常关闭
                    shut_close(to);
                    co_return;
                }

                ec.clear();
                co_await net::async_write(to, net::buffer(buffer.data(), n), token);
                if (ec)
                {
                    if (graceful(ec))
                    {
                        shut_close(from);
                        co_return;
                    }
                    throw abnormal::network("transfer_tcp 写失败: {}", ec.message());
                }
            }
        }

        net::io_context &io_context_;
        std::shared_ptr<ssl::context> ssl_ctx_;
        
        distributor &distributor_;
        socket_type client_socket_; // 客户端连接
        exclusive_connection server_socket_ptr_; // 服务器连接

        std::function<void(level, const std::string_view)> trace_;

        std::array<std::byte, 16384> buffer_{};
        ngx::memory::frame_arena frame_arena_;
    }; // class session
}

namespace ngx::agent
{
    template <socket_concept Transport>
    session<Transport>::session(net::io_context &io_context, socket_type socket, distributor &dist,
        std::shared_ptr<ssl::context> ssl_ctx)
    : io_context_(io_context), ssl_ctx_(std::move(ssl_ctx)), distributor_(dist),
    client_socket_(std::move(socket)) {}

    template <socket_concept Transport>
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
    template <socket_concept Transport>
    void session<Transport>::registered_log_function(std::function<void(level, std::string_view)> trace) noexcept
    {
        trace_ = std::move(trace);
    }

    /**
     * @brief 日志接口
     * @details 用于记录会话过程中所有级别的日志信息。
     */
    template <socket_concept Transport>
    void session<Transport>::log(level log_level, const std::string_view message) const noexcept
    {
        if (trace_)
        {
            trace_(log_level, message);
        }
    }

    /**
     * @brief 启动会话
     * @details 该函数会启动会话，开始处理客户端请求。
     */
    template <socket_concept Transport>
    void session<Transport>::start()
    {
        log(level::info, "[Session] Session started.");
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
                self->log(level::error, message);
            }
            catch (const std::exception &e)
            {
                self->log(level::error, e.what());
            }

            self->close();
        };

        net::co_spawn(io_context_, std::move(process), std::move(completion));
    }

    /**
     * @brief 关闭会话
     * @details 该函数会关闭与目标服务器（或客户端）的连接，释放相关资源。
     */
    template <socket_concept Transport>
    void session<Transport>::close()
    {
        log(level::debug, "[Session] Session closing.");
        shut_close(client_socket_);
        shut_close(server_socket_ptr_);
        server_socket_ptr_.reset();
    }

    /**
     * @brief 会话分发器
     * @details 该函数会根据请求协议类型，选择相应的处理函数。
     */
    template <socket_concept Transport>
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
            if (graceful(ec))
            {
                co_return;
            }
            throw abnormal::network("diversion peek 失败: {}", ec.message());
        }

        {
            const auto message = std::format("[Session] Peeked `{}` bytes.", n);
            log(level::debug, message);
        }

        // 2. 识别协议 (调用 analysis)
        const auto type = analysis::detect(std::string_view(peek_buf.data(), n));

        // 3. 分流
        if (type == protocol_type::http)
        {
            log(level::debug, "[Session] Detected protocol: http.");
            co_await handle_http();
        }
        else
        {
            log(level::debug, "[Session] Detected protocol: obscura.");
            co_await handle_obscura();
        }
    }

    /**
     * @brief 处理HTTP请求
     * @details 该函数会从客户端读取HTTP请求，并根据请求类型进行相应的处理。
     */
    template <socket_concept Transport>
    net::awaitable<void> session<Transport>::handle_http()
    {
        frame_arena_.reset();
        auto mr = frame_arena_.get();
        beast::basic_flat_buffer<http::network_allocator> read_buffer(http::network_allocator{mr});
        {
            http::request req(mr);
            log(level::debug, "[Session] Waiting for HTTP request...");
            const bool success = co_await http::async_read(client_socket_, req, read_buffer, mr);

            if (!success)
            {
                log(level::warn, "[Session] HTTP read failed or connection closed.");
                co_return;
            }
            {
                const auto message = std::format("[Session] HTTP request received: {} {}", req.method_string(), req.target());
                log(level::info, message);
            }
            //  连接上游
            const auto target = analysis::resolve(req);
            {
                const auto message = std::format("[Session] HTTP upstream resolving: forward_proxy=`{}` host=`{}` port=`{}`",
                    target.forward_proxy ? "true" : "false", target.host, target.port);
                log(level::debug, message);
            }
            if (target.forward_proxy)
            {
                server_socket_ptr_ = co_await distributor_.route_forward(target.host, target.port);
            }
            else
            {
                server_socket_ptr_ = co_await distributor_.route_reverse(target.host);
            }

            if (!server_socket_ptr_) 
            {
                log(level::error, "[Session] Failed to route to upstream.");
                co_return;
            }
            log(level::info, "[Session] Upstream connected.");

            // 转发
            if (req.method() == http::verb::connect)
            {
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                const std::string resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
                co_await adaptation::async_write(client_socket_, net::buffer(resp), token);
                if (ec && !graceful(ec))
                {
                    throw abnormal::network("CONNECT 响应发送失败: {}", ec.message());
                }
                log(level::info, "[Session] Sent 200 Connection Established.");
            }
            else
            {
                // 序列化发送
                const auto data = http::serialize(req, mr);
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                co_await adaptation::async_write(*server_socket_ptr_, net::buffer(data), token);
                if (ec && !graceful(ec))
                {
                    throw abnormal::network("HTTP 请求转发失败: {}", ec.message());
                }
            }
            
            if (read_buffer.size() != 0)
            {
                const auto message = std::format("[Session] Forwarding {} bytes of prefetched data.", read_buffer.size());
                log(level::debug, message);
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                co_await adaptation::async_write(*server_socket_ptr_, read_buffer.data(), token);
                if (ec && !graceful(ec))
                {
                    throw abnormal::network("预读残留转发失败: {}", ec.message());
                }
                read_buffer.consume(read_buffer.size());
            }
        } // 限制request 生命周期防止在下面request指向无效的tcp字节流
        
        log(level::info, "[Session] Starting tunnel...");
        co_await tunnel();
    }

    /**
     * @brief 隧道 TCP 流量
     * @details 该函数会在客户端套接字和上游服务器套接字之间建立隧道，实现流量的双向传输。
     */
    template<socket_concept Transport>
    net::awaitable<void> session<Transport>::tunnel()
    {
        if (!server_socket_ptr_)
        {
            log(level::warn, "[Session] Tunnel aborted: upstream socket is missing.");
            co_return;
        }

        /**
         * @details 使用 awaitable_operators 实现双向隧道。
         * 使用 || 运算符并发执行两个传输任务：
         * - client -> upstream
         * - upstream -> client
         * 当任意一个方向完成（断开连接或发生错误）时，|| 运算符会自动取消另一个方向的任务。
         */
        using namespace boost::asio::experimental::awaitable_operators;

        frame_arena_.reset();

        const std::size_t half = buffer_.size() / 2;
        auto left_buffer = mutable_buf(buffer_.data(), half);
        auto right_buffer = mutable_buf(buffer_.data() + half, buffer_.size() - half);

        auto client_to_upstream = [this, left_buffer]() -> net::awaitable<void>
        {
            log(level::debug, "[Session] Tunnel: Client -> Upstream started.");
            co_await transfer_tcp(client_socket_, *server_socket_ptr_, left_buffer);
            log(level::debug, "[Session] Tunnel: Client -> Upstream finished.");
        };

        auto upstream_to_client = [this, right_buffer]() -> net::awaitable<void>
        {
            log(level::debug, "[Session] Tunnel: Upstream -> Client started.");
            co_await transfer_tcp(*server_socket_ptr_, client_socket_, right_buffer);
            log(level::debug, "[Session] Tunnel: Upstream -> Client finished.");
        };

        try
        {
            // 并发执行，任一完成即结束
            co_await (client_to_upstream() || upstream_to_client());
        }
        catch ([[maybe_unused]] const std::exception &e)
        {
            const auto message = std::format("[Session] Tunnel error: {}", e.what());
            log(level::error, message);
            // 记录错误但继续清理
        }
        catch (...)
        {
            log(level::error, "[Session] Tunnel unknown error.");
        }

        shut_close(client_socket_);
        shut_close(server_socket_ptr_);
        server_socket_ptr_.reset();
    }

    /**
     * @brief 处理 obscura 协议
     * @details 该函数会处理 obscura 协议，并建立与上游服务器的连接。
     */
    template <socket_concept Transport>
    net::awaitable<void> session<Transport>::handle_obscura()
    {
        if (!ssl_ctx_)
        {
            log(level::warn, "[Session] Obscura disabled: ssl context is missing.");
            co_return;
        }

        frame_arena_.reset();
        auto mr = frame_arena_.get();
        auto proto = std::make_shared<obscura<tcp>>(std::move(client_socket_), ssl_ctx_, role::server);
        std::string target_path;
        try
        {
            log(level::debug, "[Session] Obscura handshake started.");
            target_path = co_await proto->handshake();
        }
        catch (const boost::system::system_error &e)
        {
            throw abnormal::protocol("obscura 握手失败: {}", e.code().message());
        }
        catch (const std::exception &e)
        {
            throw abnormal::protocol("obscura 握手失败: {}", e.what());
        }

        if (target_path.starts_with('/'))
        {
            target_path.erase(0, 1);
        }

        if (!target_path.empty())
        {
            const auto message = std::format("[Session] Obscura target path: `{}`", target_path);
            log(level::debug, message);
        }

        const auto target = analysis::resolve(std::string_view(target_path), mr);
        if (target.host.empty())
        {
            log(level::warn, "[Session] Obscura resolve failed: empty host.");
            co_return;
        }

        {
            const auto message = std::format("[Session] Obscura upstream resolving: {}:{}", target.host, target.port);
            log(level::info, message);
        }

        server_socket_ptr_ = co_await distributor_.route_forward(target.host, target.port);
        if (!server_socket_ptr_ || !server_socket_ptr_->is_open())
        {
            log(level::error, "[Session] Obscura route to upstream failed.");
            co_return;
        }

        log(level::info, "[Session] Obscura upstream connected.");
        co_await tunnel_obscura(std::move(proto));
    }

    /**
     * @brief 从 obscura 协议读取数据并写入服务器
     * @param proto obscura 协议实例
     * @param cancel_slot 取消信号槽实例
     * @details 该函数会从 obscura 协议读取数据，并将数据写入服务器。
     */
    template <socket_concept Transport>
    net::awaitable<void> session<Transport>::transfer_obscura(obscura<tcp> &proto, const cancellation_slot cancel_slot) const
    {
        beast::flat_buffer buffer;
        while (true)
        {
            std::size_t n = 0;
            try
            {
                n = co_await proto.async_read(buffer);
            }
            catch (const boost::system::system_error &e)
            {
                if (graceful(e.code()) || e.code() == beast::websocket::error::closed)
                {   // 正常关闭,不抛出异常
                    co_return;
                }
                throw abnormal::protocol("obscura 读失败: {}", e.code().message());
            }
            catch (const std::exception &e)
            {
                throw abnormal::protocol("obscura 读失败: {}", e.what());
            }

            if (n == 0)
            {
                co_return;
            }

            boost::system::error_code ec;
            auto token = net::bind_cancellation_slot(cancel_slot, net::redirect_error(net::use_awaitable, ec));
            co_await adaptation::async_write(*server_socket_ptr_, buffer.data(), token);
            if (ec)
            {
                if (graceful(ec))
                {
                    co_return;
                }
                throw abnormal::network("写入上游失败: {}", ec.message());
            }

            buffer.consume(n);
        }
    }

    /**
     * @brief 从服务器读取数据并写入 obscura 协议
     * @param proto obscura 协议实例
     * @param cancel_slot 取消信号槽实例
     * @param buffer 用于读取数据的缓冲区
     * @details 该函数会从服务器读取数据，并将数据写入 obscura 协议实例。
     */
    template <socket_concept Transport>
    net::awaitable<void> session<Transport>::transfer_obscura(obscura<tcp> &proto, const cancellation_slot cancel_slot, mutable_buf buffer) const
    {
        boost::system::error_code ec;
        auto token = net::bind_cancellation_slot(cancel_slot, net::redirect_error(net::use_awaitable, ec));

        while (true)
        {
            ec.clear();
            const std::size_t n = co_await server_socket_ptr_->async_read_some(buffer, token);
            if (ec)
            {
                if (graceful(ec))
                {
                    co_return;
                }
                throw abnormal::network("从上游读取失败: {}", ec.message());
            }

            if (n == 0)
            {
                co_return;
            }

            try
            {   // 写入 obscura 协议
                const auto view = std::string_view(static_cast<const char *>(buffer.data()), n);
                co_await proto.async_write(view);
            }
            catch (const boost::system::system_error &e)
            {
                if (graceful(e.code()) || e.code() == beast::websocket::error::closed)
                {
                    co_return;
                }
                throw abnormal::protocol("obscura 写失败: {}", e.code().message());
            }
            catch (const std::exception &e)
            {
                throw abnormal::protocol("obscura 写失败: {}", e.what());
            }
        }
    }

    /**
     * @brief 建立 obscura 隧道,将 obscura 协议的数据进行加密传输
     * @param proto obscura 协议实例
     * @details 该函数会在客户端和服务器之间建立一个隧道，将 obscura 协议的数据进行加密传输。
     */
    template <socket_concept Transport>
    net::awaitable<void> session<Transport>::tunnel_obscura(std::shared_ptr<obscura<tcp>> proto)
    {
        if (!proto)
        {
            co_return;
        }

        log(level::info, "[Session] Obscura tunnel started.");

        frame_arena_.reset();
        // 获取当前协程的执行器
        auto executor = co_await net::this_coro::executor;

        auto cancel_obscura_to_upstream = std::make_shared<net::cancellation_signal>();
        auto cancel_upstream_to_obscura = std::make_shared<net::cancellation_signal>();

        const std::size_t half = buffer_.size() / 2;
        auto upstream_to_obscura_buffer = mutable_buf(buffer_.data(), half);

        auto outoken = [self = this->shared_from_this(), proto,
            slot = cancel_obscura_to_upstream->slot(),
            signal = cancel_upstream_to_obscura]() -> net::awaitable<void>
        {
            try
            {
                self->log(level::debug, "[Session] Obscura tunnel: obscura -> upstream started.");
                co_await self->transfer_obscura(*proto, slot);
                self->log(level::debug, "[Session] Obscura tunnel: obscura -> upstream finished.");
            }
            catch (...)
            {
                signal->emit(net::cancellation_type::all);
                throw;
            }
            signal->emit(net::cancellation_type::all);
        };

        auto uotoken = [self = this->shared_from_this(), proto,
            slot = cancel_upstream_to_obscura->slot(),
            signal = cancel_obscura_to_upstream, upstream_to_obscura_buffer]() -> net::awaitable<void>
        {
            try
            {
                self->log(level::debug, "[Session] Obscura tunnel: upstream -> obscura started.");
                co_await self->transfer_obscura(*proto, slot, upstream_to_obscura_buffer);
                self->log(level::debug, "[Session] Obscura tunnel: upstream -> obscura finished.");
            }
            catch (...)
            {
                signal->emit(net::cancellation_type::all);
                throw;
            }
            signal->emit(net::cancellation_type::all);
        };

        /**
         * @details co_spawn函数是调用就立即返回一个可等待对象，并把这个任务投递到io事件队列中运行
         */
        auto obscura_to_upstream = net::co_spawn(executor, outoken, net::use_awaitable);
        auto upstream_to_obscura = net::co_spawn(executor, uotoken, net::use_awaitable);


        /**
         * @details 和上面的函数逻辑同理
         */
        std::exception_ptr first_error;
        try
        {
            co_await std::move(obscura_to_upstream);
        }
        catch (...)
        {
            first_error = std::current_exception();
        }

        try
        {
            co_await std::move(upstream_to_obscura);
        }
        catch (...)
        {
            if (!first_error)
            {
                first_error = std::current_exception();
            }
        }

        try
        {
            log(level::debug, "[Session] Obscura tunnel closing obscura protocol.");
            co_await proto->close();
        }
        catch (const boost::system::system_error &e)
        {
            if (!graceful(e.code()) && e.code() != beast::websocket::error::closed)
            {
                if (!first_error)
                {
                    first_error = std::make_exception_ptr(abnormal::protocol("obscura 关闭失败: {}", e.code().message()));
                }
            }
        }
        catch (const std::exception &e)
        {
            if (!first_error)
            {
                first_error = std::make_exception_ptr(abnormal::protocol("obscura 关闭失败: {}", e.what()));
            }
        }

        shut_close(server_socket_ptr_);
        server_socket_ptr_.reset();

        if (first_error)
        {
            log(level::error, "[Session] Obscura tunnel finished with error.");
            std::rethrow_exception(first_error);
        }

        log(level::info, "[Session] Obscura tunnel finished.");
    }
}
