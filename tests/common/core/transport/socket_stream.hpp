/**
 * @file socket_stream.hpp
 * @brief TCP 套接字流（借鉴 Boost.Beast tcp_stream）
 * @details 将 boost::asio::ip::tcp::socket 包装为统一 stream：
 *          - read_some / write_all（内部补写循环）
 *          - shutdown（半关，仅发送侧）
 *          - close / cancel / set_timeout / is_open / executor
 *          - lowest_layer() 访问原生 socket（与 Beast 一致）
 * @note 仅用于性能测试与互操作测试；生产路径走 Prism 主库 transport。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/core/transport/stream.hpp>
#include <common/core/transport/transport_base.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>

namespace psmtest
{

    /// TCP 套接字流
    class socket_stream : public transport_base
    {
    public:
        /// 默认读超时（0 = 禁用）
        static constexpr std::chrono::milliseconds default_timeout{0};

        /// @brief 构造（需后续 connect/accept）
        /// @param ex 执行器
        explicit socket_stream(net::any_io_executor ex)
            : sock_(ex), timer_(ex)
        {
        }

        /// 不可拷贝
        socket_stream(const socket_stream &) = delete;
        auto operator=(const socket_stream &) -> socket_stream & = delete;

        /// 移动构造
        socket_stream(socket_stream &&) noexcept = default;

        /// 移动赋值
        auto operator=(socket_stream &&) noexcept -> socket_stream & = default;

        /// @brief 连接远端（带超时）
        /// @param ep 端点
        /// @param timeout 连接超时
        /// @return 错误码
        auto connect(const net::ip::tcp::endpoint &ep,
                     std::chrono::milliseconds timeout = std::chrono::milliseconds{5000})
            -> net::awaitable<protocol_ec>
        {
            using namespace boost::asio::experimental::awaitable_operators;

            boost::system::error_code ec;
            if (timeout.count() > 0)
            {
                timer_.expires_after(timeout);
                auto result = co_await (
                    sock_.async_connect(ep, net::use_awaitable) ||
                    timer_.async_wait(net::use_awaitable));
                if (result.index() == 1)
                {
                    sock_.close(ec);
                    co_return make_error_code(error::timeout);
                }
            }
            else
            {
                co_await sock_.async_connect(ep, net::use_awaitable);
            }
            co_return boost::system::error_code{};
        }

        /// @brief 读取最多 buf.size() 字节
        /// @return 实际读取字节数；0 = 对端关闭或超时
        auto read_some(std::span<std::uint8_t> buf) -> net::awaitable<std::size_t> override
        {
            using namespace boost::asio::experimental::awaitable_operators;

            boost::system::error_code ec;
            if (timeout_.count() > 0)
            {
                timer_.expires_after(timeout_);
                auto result = co_await (
                    sock_.async_read_some(net::buffer(buf.data(), buf.size()), net::use_awaitable) ||
                    timer_.async_wait(net::use_awaitable));
                if (result.index() == 1) // 超时
                {
                    sock_.cancel(ec);
                    co_return 0;
                }
                co_return std::get<0>(result);
            }
            co_return co_await sock_.async_read_some(net::buffer(buf.data(), buf.size()), net::use_awaitable);
        }

        /// @brief 写入全部 buf 字节
        /// @return 错误码（成功 = 空）
        auto write_all(std::span<const std::uint8_t> buf) -> net::awaitable<protocol_ec> override
        {
            boost::system::error_code ec;
            co_await net::async_write(sock_, net::buffer(buf.data(), buf.size()),
                                      net::redirect_error(net::use_awaitable, ec));
            if (ec)
                co_return ec;
            co_return boost::system::error_code{};
        }

        /// @brief 半关（发送侧）
        auto shutdown() -> net::awaitable<void> override
        {
            boost::system::error_code ec;
            sock_.shutdown(net::ip::tcp::socket::shutdown_send, ec);
            co_return;
        }

        /// @brief 全关
        auto close() -> net::awaitable<void> override
        {
            boost::system::error_code ec;
            sock_.close(ec);
            co_return;
        }

        /// @brief 取消挂起操作
        auto cancel() -> void override
        {
            boost::system::error_code ec;
            sock_.cancel(ec);
            timer_.cancel();
        }

        /// @brief 设置读超时（0 = 禁用）
        auto set_timeout(std::chrono::milliseconds ms) -> void override
        {
            if (ms.count() > 0)
            {
                timeout_ = ms;
                timer_.expires_after(ms);
            }
            else
            {
                timeout_ = std::chrono::milliseconds{0};
                timer_.expires_at(net::steady_timer::time_point::max());
            }
        }

        /// 流是否打开
        [[nodiscard]] auto is_open() const -> bool override
        {
            return sock_.is_open();
        }

        /// 获取执行器
        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return sock_.get_executor();
        }

        /// 访问原生套接字（Beast lowest_layer 语义）
        [[nodiscard]] auto lowest_layer() -> net::ip::tcp::socket &
        {
            return sock_;
        }

        /// 访问原生套接字（const）
        [[nodiscard]] auto lowest_layer() const -> const net::ip::tcp::socket &
        {
            return sock_;
        }

    private:
        mutable net::ip::tcp::socket sock_;
        net::steady_timer timer_;
        std::chrono::milliseconds timeout_{default_timeout};
    };

    static_assert(stream<socket_stream>, "socket_stream 必须满足 stream concept");

} // namespace psmtest
