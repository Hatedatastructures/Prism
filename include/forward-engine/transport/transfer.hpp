/**
 * @file transfer.hpp
 * @brief 传输与隧道工具
 * @details 提供单向数据传输 (`transfer`) 和双向隧道 (`tunnel`) 的实现，支持 TCP 和 Obscura 协议。
 */
#pragma once
#include <cstddef>
#include <exception>
#include <memory>
#include <string_view>
#include <type_traits>
#include <system_error>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <forward-engine/transport/adaptation.hpp>
#include <forward-engine/transport/obscura.hpp>
#include <forward-engine/gist/code.hpp>
#include <forward-engine/trace/spdlog.hpp>

/**
 * @namespace ngx::transport::detail
 * @brief 传输层实现细节
 * @details 包含底层的 socket 操作、上下文定义以及具体的数据搬运逻辑。
 * 该命名空间下的组件通常由上层 agent 模块直接调用，一般不直接暴露给最终用户。
 */
namespace ngx::transport::detail
{
    namespace net = boost::asio;
    namespace beast = boost::beast;
    using tcp = net::ip::tcp;

    using mutable_buf = net::mutable_buffer;

    using stream_socket = net::ip::tcp::socket;
    using datagram_socket = net::ip::udp::socket;

    /**
     * @brief 关闭套接字
     * @details 关闭套接字，先尝试优雅关闭 (`shutdown`)，再强制关闭 (`close`)。
     * @tparam Socket 套接字类型
     * @param socket 套接字引用
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
     * @param ec 错误码
     * @return bool 是否为正常收尾
     */
    [[nodiscard]] inline bool normal_close(const boost::system::error_code &ec) noexcept
    {
        return ec == boost::asio::error::eof || ec == boost::asio::error::operation_aborted 
        || ec == boost::asio::error::connection_reset || ec == boost::asio::error::connection_aborted 
        || ec == boost::asio::error::broken_pipe || ec == boost::asio::error::not_connected;
    }

    /**
     * @brief 判断 `std::error_code` 是否属于“正常收尾”
     * @details 兼容标准库错误码，内部转换为 `boost::system::error_code` 进行判断。
     * @param ec 错误码
     * @return bool 是否为正常收尾
     */
    [[nodiscard]] inline bool normal_close(const std::error_code &ec) noexcept
    {
        // 转换为 boost::system::error_code 以复用现有逻辑
        const boost::system::error_code boost_ec(ec);
        return normal_close(boost_ec);
    }

    /**
     * @brief 判断 `ngx::gist::code` 是否属于“正常收尾”
     * @details 检查项目自定义错误码中表示正常关闭的枚举值。
     * @param c 错误码
     * @return bool 是否为正常收尾
     */
    [[nodiscard]] inline bool normal_close(const gist::code c) noexcept
    {
        using enum gist::code;
        return c == eof || c == canceled || c == connection_reset || c == connection_aborted;
    }

    /**
     * @brief 传输上下文
     * @details 包含传输过程中的配置、统计信息和状态。
     * @tparam Source 源类型
     * @tparam Dest 目标类型
     */
    template <typename Source, typename Dest>
    struct transfer_context
    {
        using dest_pointer = std::add_pointer_t<Dest>;
        using source_pointer = std::add_pointer_t<Source>;

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
     * @brief 创建 TCP 传输上下文
     * @details 创建一个传输上下文，包含源、目的指针和缓冲区。
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
     * @details 创建一个隧道上下文，包含服务器套接字和客户端套接字。
     * @param server_socket 服务器套接字
     * @param client_socket 客户端套接字
     * @return tunnel_context 隧道上下文
     */
    inline auto make_tunnel_context(stream_socket *server_socket, stream_socket *client_socket)
        -> tunnel_context
    {
        tunnel_context ctx{};
        ctx.server_socket = server_socket;
        ctx.client_socket = client_socket;
        return ctx;
    }

    /**
     * @struct transfer
     * @brief 单向传输工具类 (Stateless Utility)
     * @details 负责在两个端点之间进行单向数据传输。这是一个无状态的工具类，
     * 所有状态都保存在 `transfer_context` 中。
     * @see tunnel
     */
    struct transfer
    {
        /**
         * @brief TCP 流式传输 (单向)
         * @tparam Source 源套接字类型
         * @tparam Dest 目的套接字类型
         * @details 启动一个异步循环，不断从 `Source` 读取数据并写入到 `Dest`，
         * 直到源关闭、目的关闭或发生错误。
         * @param ctx 传输上下文，必须包含有效的源和目的指针以及缓冲区。
         * @warning 如果 `ctx` 无效，将直接返回。
         */
        template <typename Source, typename Dest>
        static net::awaitable<void> stream(const transfer_context<Source, Dest> &ctx)
        {
            if (!ctx.valid())
            {
                trace::warn("[Transfer] invalid context.");
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
                    trace::error("[Transfer] read failed.");
                    shut_close(*ctx.from);
                    shut_close(*ctx.to);
                    co_return;
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
                    trace::error("[Transfer] write failed.");
                    shut_close(*ctx.from);
                    shut_close(*ctx.to);
                    co_return;
                }
            }
        }

        /**
         * @brief Obscura 传输到上游服务器 (单向)
         * @details 这是一个专门适配 Obscura 协议的传输函数。它负责将解密后的 Obscura 流量
         * 转发到普通的 TCP 上游服务器。
         * @param proto Obscura 协议实例
         * @param upstream 上游套接字
         * @param cancel_slot 取消槽位，用于在外部强制终止传输
         */
        static net::awaitable<void> obscura_to_upstream(obscura<net::ip::tcp> &proto, stream_socket &upstream,
                                                        const net::cancellation_slot cancel_slot)
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
                    if (normal_close(e.code()) || e.code() == websocket::error::closed)
                    {
                        co_return;
                    }
                    trace::error("[Obscura] read failed.");
                    co_return;
                }
                catch (const std::exception &e)
                {
                    static_cast<void>(e);
                    trace::error("[Obscura] read failed.");
                    co_return;
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
                    trace::error("[Obscura] upstream write failed.");
                    co_return;
                }

                buffer.consume(n);
            }
        }

        /**
         * @brief 上游传输到 Obscura (单向)
         * @details 将从上游服务器读取的明文数据，通过 Obscura 协议加密后发送给客户端。
         * @param proto Obscura 协议实例
         * @param upstream 上游套接字
         * @param cancel_slot 取消槽位
         * @param buffer 数据缓冲区
         */
        static net::awaitable<void> upstream_to_obscura(obscura<net::ip::tcp> &proto, stream_socket &upstream,
                                                        const net::cancellation_slot cancel_slot, const mutable_buf buffer)
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
                    trace::error("[Obscura] upstream read failed.");
                    co_return;
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
                    if (normal_close(e.code()) || e.code() == websocket::error::closed)
                    {
                        co_return;
                    }
                    trace::error("[Obscura] write failed.");
                    co_return;
                }
                catch (const std::exception &e)
                {
                    static_cast<void>(e);
                    trace::error("[Obscura] write failed.");
                    co_return;
                }
            }
        }
    };

    /**
     * @class tunnel
     * @brief 双向隧道传输工具类
     * @details 通过组合两个单向的 `transfer`，在两个端点之间建立全双工 (`Full-Duplex`) 的数据传输通道。
     * 当任意一个方向的传输结束（连接关闭或出错）时，整个隧道也将关闭。
     * @see transfer
     */
    class tunnel
    {
    public:
        /**
         * @brief TCP 隧道传输
         * @details 在两个套接字之间并发执行双向数据传输。
         * 内部使用 `boost::asio::experimental::awaitable_operators` (`||` 运算符)
         * 来实现"任意一方完成即终止"的逻辑。
         * @param ctx 隧道上下文，包含客户端和服务端 socket
         * @param buffer_data 共享缓冲区指针
         * @param buffer_size 缓冲区总大小 (将被平分为两部分使用)
         * @note 缓冲区大小必须至少为 2 字节。
         */
        static net::awaitable<void> stream(const tunnel_context &ctx, std::byte *buffer_data, const std::size_t buffer_size)
        {
            if (!ctx.valid() || !buffer_data || buffer_size < 2)
            {
                trace::warn("[Tunnel] invalid context.");
                co_return;
            }

            using namespace boost::asio::experimental::awaitable_operators;

            const std::size_t half = buffer_size / 2;
            const auto left = mutable_buf(buffer_data, half);
            const auto right = mutable_buf(buffer_data + half, buffer_size - half);

            const auto client_to_server = make_transfer_context<stream_socket, stream_socket>(
                ctx.client_socket, ctx.server_socket, left);
            const auto server_to_client = make_transfer_context<stream_socket, stream_socket>(
                ctx.server_socket, ctx.client_socket, right);

            trace::debug("[Tunnel] stream start.");
            co_await (transfer::stream(client_to_server) || transfer::stream(server_to_client));
        }

        /**
         * @brief Obscura 协议隧道传输
         * @details 在 Obscura 协议和 TCP 上游服务器之间建立双向隧道。
         * 由于 Obscura 协议的特殊性，需要使用 `cancellation_signal` 来协调两个方向的生命周期。
         * @param proto Obscura 协议实例 (shared_ptr)
         * @param upstream 上游 TCP 套接字
         * @param buffer_data 缓冲区指针 (仅用于上游到 Obscura 的方向)
         * @param buffer_size 缓冲区大小
         */
        static net::awaitable<void> obscura(std::shared_ptr<obscura<net::ip::tcp>> proto,
                                            stream_socket &upstream, std::byte *buffer_data, const std::size_t buffer_size)
        {
            if (!proto || !buffer_data || buffer_size < 2)
            {
                trace::warn("[Obscura] invalid context.");
                co_return;
            }

            trace::info("[Obscura] tunnel started.");

            auto executor = co_await net::this_coro::executor;

            net::cancellation_signal cancel_obscura_to_upstream;
            net::cancellation_signal cancel_upstream_to_obscura;

            const std::size_t half = buffer_size / 2;
            auto upstream_to_obscura_buffer = mutable_buf(buffer_data, half);

            auto outoken = [proto, slot = cancel_obscura_to_upstream.slot(),
                            &cancel_upstream_to_obscura, &upstream]() -> net::awaitable<void>
            {
                trace::debug("[Obscura] tunnel: obscura -> upstream started.");
                co_await transfer::obscura_to_upstream(*proto, upstream, slot);
                trace::debug("[Obscura] tunnel: obscura -> upstream finished.");
                cancel_upstream_to_obscura.emit(net::cancellation_type::all);
            };

            auto uotoken = [proto, slot = cancel_upstream_to_obscura.slot(), &cancel_obscura_to_upstream,
                            upstream_to_obscura_buffer, &upstream]() -> net::awaitable<void>
            {
                trace::debug("[Obscura] tunnel: upstream -> obscura started.");
                co_await transfer::upstream_to_obscura(*proto, upstream, slot, upstream_to_obscura_buffer);
                trace::debug("[Obscura] tunnel: upstream -> obscura finished.");
                cancel_obscura_to_upstream.emit(net::cancellation_type::all);
                try
                {
                    co_await proto->close();
                }
                catch (const boost::system::system_error &e)
                {
                    (void)e;
                }
                catch (const std::exception &e)
                {
                    (void)e;
                }
            };

            auto obscura_to_upstream = net::co_spawn(executor, outoken, net::use_awaitable);
            auto upstream_to_obscura = net::co_spawn(executor, uotoken, net::use_awaitable);

            co_await std::move(obscura_to_upstream);
            co_await std::move(upstream_to_obscura);

            try
            {
                trace::debug("[Obscura] tunnel closing obscura protocol.");
                co_await proto->close();
            }
            catch (const boost::system::system_error &e)
            {
                (void)e;
            }
            catch (const std::exception &e)
            {
                (void)e;
            }

            trace::info("[Obscura] tunnel finished.");
        }
    };
}
