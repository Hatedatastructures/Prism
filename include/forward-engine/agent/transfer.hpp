#pragma once
#include <cstddef>
#include <exception>
#include <functional>
#include <memory>
#include <string_view>
#include <type_traits>
#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <abnormal.hpp>
#include "adaptation.hpp"
#include "obscura.hpp"
#include "source.hpp"


namespace ngx::agent::detail
{
    namespace net = boost::asio;

    enum class log_level : std::uint8_t
    {
        debug,
        info,
        warn,
        error,
        fatal
    };

    using mutable_buf = net::mutable_buffer;

    using stream_socket = net::ip::tcp::socket;
    using datagram_socket = net::ip::udp::socket;

    inline std::function<void(log_level, std::string_view)> tracker{};

    /**
     * @brief 事件跟踪
     * @details 记录传输事件，如连接、断开、数据传输等
     * @param level 级别
     * @param msg 消息
     */
    inline void event_tracking(const log_level level, std::string_view msg) noexcept
    {
        if (tracker)
        {
            tracker(level, msg);
        }
    }

    /**
     * @brief 关闭套接字
     * @details 关闭套接字，先尝试优雅关闭，再强制关闭
     * @param socket 套接字
     */
    template <typename Socket>
    void shut_close(Socket &socket) noexcept
    {
        if constexpr (requires { socket.is_open(); })
        {
            if (socket.is_open())
            {
                boost::system::error_code ec;
                if constexpr (requires { socket.shutdown(net::socket_base::shutdown_both, ec); })
                {
                    socket.shutdown(net::socket_base::shutdown_both, ec);
                }
                socket.close(ec);
            }
        }
    }


    /**
     * @brief 判断 `boost::system::error_code` 是否属于“正常收尾”
     * @details “正常收尾”包括：对端正常关闭、被取消、连接被重置等。
     * 这些场景不应当转为业务异常抛出，否则会把正常断开误判为错误。
     */
    [[nodiscard]] inline bool normal_close(const boost::system::error_code &ec) noexcept
    {
        using namespace boost::asio;
        return ec == error::eof  || ec == error::operation_aborted || ec == error::connection_reset
            || ec == error::connection_aborted || ec == error::broken_pipe || ec == error::not_connected;
    }

    /**
     * @brief 传输上下文
     * @details 用于存储传输相关的上下文信息
     */
    template <typename Source, typename Dest>
    class transfer_context
    {
        using dest_pointer = std::add_pointer_t<Dest>;
        using source_pointer = std::add_pointer_t<Source>;
    public:
        transfer_context() noexcept = default;

        /**
         * @brief 检查上下文是否有效
         * @details 检查上下文是否包含有效指针
         * @return `true` 上下文有效
         * @return `false` 上下文无效
         */
        bool valid() const noexcept
        {
            return to && from && buffer.size() > 0;
        }
        mutable_buf buffer{};
        dest_pointer to = nullptr;
        source_pointer from = nullptr;
    };

    class tunnel_context
    {
        using socket_pointer = std::add_pointer_t<stream_socket>;
    public:
        /**
         * @brief 检查上下文是否有效
         * @details 检查上下文是否包含有效指针
         * @return `true` 上下文有效
         * @return `false` 上下文无效
         */
        bool valid() const noexcept
        {
            return server_socket && client_socket;
        }
        socket_pointer server_socket = nullptr;
        socket_pointer client_socket = nullptr;
    };

    /**
     * @brief 创建传输上下文
     * @details 创建一个传输上下文，包含源、目的指针和缓冲区
     * @param from 源指针
     * @param to 目的指针
     * @param buffer 缓冲区
     * @return transfer_context<Source, Dest> 传输上下文
     */
    template <typename Source, typename Dest>
    transfer_context<Source, Dest> make_transfer_context(Source *from, Dest *to, mutable_buf buffer)
    {
        transfer_context<Source, Dest> ctx{};
        ctx.from = from;
        ctx.to = to;
        ctx.buffer = buffer;
        return ctx;
    }

    /**
     * @brief 创建隧道上下文
     * @details 创建一个隧道上下文，包含服务器套接字和客户端套接字
     * @param server_socket 服务器套接字
     * @param client_socket 客户端套接字
     * @return tunnel_context 隧道上下文
     */
    inline tunnel_context make_tunnel_context(stream_socket *server_socket,stream_socket *client_socket)
    {
        tunnel_context ctx{};
        ctx.server_socket = server_socket;
        ctx.client_socket = client_socket;
        return ctx;
    }

    struct transfer
    {
    public:
        template <typename Source, typename Dest>
        static net::awaitable<void> stream(const transfer_context<Source, Dest> &ctx)
        {
            if (!ctx.valid())
            {
                event_tracking(log_level::warn, "[Transfer] invalid context.");
                co_return;
            }

            boost::system::error_code ec;
            auto token = net::redirect_error(net::use_awaitable, ec);
            while (true)
            {
                ec.clear();
                const std::size_t n = co_await ctx.from->async_read_some(ctx.buffer, token);
                if (ec)
                {
                    if (normal_close(ec))
                    {
                        shut_close(*ctx.to);
                        co_return;
                    }
                    throw abnormal::network("transfer read failed: {}", ec.message());
                }
                if (n == 0)
                {
                    shut_close(*ctx.to);
                    co_return;
                }
                ec.clear();
                co_await net::async_write(*ctx.to, net::buffer(ctx.buffer.data(), n), token);
                if (ec)
                {
                    if (normal_close(ec))
                    {
                        shut_close(*ctx.from);
                        co_return;
                    }
                    throw abnormal::network("transfer write failed: {}", ec.message());
                }
            }
        }

        static net::awaitable<void> obscura_to_upstream(obscura<net::ip::tcp> &proto, stream_socket &upstream,
            net::cancellation_slot cancel_slot)
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
                    if (normal_close(e.code()) || e.code() == beast::websocket::error::closed)
                    {
                        co_return;
                    }
                    throw abnormal::protocol("obscura read failed: {}", e.code().message());
                }
                catch (const std::exception &e)
                {
                    throw abnormal::protocol("obscura read failed: {}", e.what());
                }

                if (n == 0)
                {
                    co_return;
                }

                boost::system::error_code ec;
                auto token = net::bind_cancellation_slot(cancel_slot, net::redirect_error(net::use_awaitable, ec));
                co_await adaptation::async_write(upstream, buffer.data(), token);
                if (ec)
                {
                    if (normal_close(ec))
                    {
                        co_return;
                    }
                    throw abnormal::protocol("upstream write failed: {}", ec.message());
                }

                buffer.consume(n);
            }
        }

        static net::awaitable<void> upstream_to_obscura(obscura<net::ip::tcp> &proto, stream_socket &upstream,
            net::cancellation_slot cancel_slot, mutable_buf buffer)
        {
            boost::system::error_code ec;
            auto token = net::bind_cancellation_slot(cancel_slot, net::redirect_error(net::use_awaitable, ec));

            while (true)
            {
                ec.clear();
                const std::size_t n = co_await upstream.async_read_some(buffer, token);
                if (ec)
                {
                    if (normal_close(ec))
                    {
                        co_return;
                    }
                    throw abnormal::protocol("upstream read failed: {}", ec.message());
                }

                if (n == 0)
                {
                    co_return;
                }

                try
                {
                    const auto view = std::string_view(static_cast<const char *>(buffer.data()), n);
                    co_await proto.async_write(view);
                }
                catch (const boost::system::system_error &e)
                {
                    if (normal_close(e.code()) || e.code() == beast::websocket::error::closed)
                    {
                        co_return;
                    }
                    throw abnormal::protocol("obscura write failed: {}", e.code().message());
                }
                catch (const std::exception &e)
                {
                    throw abnormal::protocol("obscura write failed: {}", e.what());
                }
            }
        }
    };

    class tunnel
    {
    public:
        net::awaitable<void> stream(const tunnel_context &ctx, std::byte *buffer_data, std::size_t buffer_size)
        {
            if (!ctx.valid() || !buffer_data || buffer_size < 2)
            {
                event_tracking(log_level::warn, "[Tunnel] invalid context.");
                co_return;
            }

            using namespace boost::asio::experimental::awaitable_operators;

            const std::size_t half = buffer_size / 2;
            auto left = mutable_buf(buffer_data, half);
            auto right = mutable_buf(buffer_data + half, buffer_size - half);

            auto client_to_server = make_transfer_context<stream_socket, stream_socket>(
                ctx.client_socket, ctx.server_socket, left);
            auto server_to_client = make_transfer_context<stream_socket, stream_socket>(
                ctx.server_socket, ctx.client_socket, right);


            try
            {
                event_tracking(log_level::debug, "[Tunnel] stream start.");
                co_await (transfer::stream(client_to_server) || transfer::stream(server_to_client));
            }
            catch (const std::exception &)
            {
                event_tracking(log_level::error, "[Tunnel] error.");
                throw;
            }
        }

        static net::awaitable<void> obscura(std::shared_ptr<obscura<net::ip::tcp>> proto,
            stream_socket &upstream, std::byte *buffer_data, std::size_t buffer_size)
        {
            if (!proto || !buffer_data || buffer_size < 2)
            {
                event_tracking(log_level::warn, "[Obscura] invalid context.");
                co_return;
            }

            event_tracking(log_level::info, "[Obscura] tunnel started.");

            auto executor = co_await net::this_coro::executor;

            net::cancellation_signal cancel_obscura_to_upstream;
            net::cancellation_signal cancel_upstream_to_obscura;

            const std::size_t half = buffer_size / 2;
            auto upstream_to_obscura_buffer = mutable_buf(buffer_data, half);

            auto outoken = [proto, slot = cancel_obscura_to_upstream.slot(),
                &cancel_upstream_to_obscura, &upstream]() -> net::awaitable<void>
            {
                try
                {
                    event_tracking(log_level::debug, "[Obscura] tunnel: obscura -> upstream started.");
                    co_await transfer::obscura_to_upstream(*proto, upstream, slot);
                    event_tracking(log_level::debug, "[Obscura] tunnel: obscura -> upstream finished.");
                }
                catch (...)
                {
                    cancel_upstream_to_obscura.emit(net::cancellation_type::all);
                    throw;
                }
                cancel_upstream_to_obscura.emit(net::cancellation_type::all);
            };

            auto uotoken = [proto, slot = cancel_upstream_to_obscura.slot(), &cancel_obscura_to_upstream,
                upstream_to_obscura_buffer, &upstream]() -> net::awaitable<void>
            {
                std::exception_ptr error;
                try
                {
                    event_tracking(log_level::debug, "[Obscura] tunnel: upstream -> obscura started.");
                    co_await transfer::upstream_to_obscura(*proto, upstream, slot, upstream_to_obscura_buffer);
                    event_tracking(log_level::debug, "[Obscura] tunnel: upstream -> obscura finished.");
                }
                catch (...)
                {
                    cancel_obscura_to_upstream.emit(net::cancellation_type::all);
                    error = std::current_exception();
                }
                cancel_obscura_to_upstream.emit(net::cancellation_type::all);
                try
                {
                    co_await proto->close();
                }
                catch (const boost::system::system_error &e)
                {
                    if (!normal_close(e.code()) && e.code() != beast::websocket::error::closed)
                    {
                        if (!error)
                        {
                            error = std::make_exception_ptr(abnormal::protocol("obscura close failed: {}", e.code().message()));
                        }
                    }
                }
                catch (const std::exception &e)
                {
                    if (!error)
                    {
                        error = std::make_exception_ptr(abnormal::protocol("obscura close failed: {}", e.what()));
                    }
                }
                if (error)
                {
                    std::rethrow_exception(error);
                }
            };

            auto obscura_to_upstream = net::co_spawn(executor, outoken, net::use_awaitable);
            auto upstream_to_obscura = net::co_spawn(executor, uotoken, net::use_awaitable);

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
                event_tracking(log_level::debug, "[Obscura] tunnel closing obscura protocol.");
                co_await proto->close();
            }
            catch (const boost::system::system_error &e)
            {
                if (!normal_close(e.code()) && e.code() != beast::websocket::error::closed)
                {
                    if (!first_error)
                    {
                        first_error = std::make_exception_ptr(abnormal::protocol("obscura close failed: {}", e.code().message()));
                    }
                }
            }
            catch (const std::exception &e)
            {
                if (!first_error)
                {
                    first_error = std::make_exception_ptr(abnormal::protocol("obscura close failed: {}", e.what()));
                }
            }

            if (first_error)
            {
                event_tracking(log_level::error, "[Obscura] tunnel finished with error.");
                std::rethrow_exception(first_error);
            }

            event_tracking(log_level::info, "[Obscura] tunnel finished.");
        }
    };
}
