/**
 * @file socket.hpp
 * @brief 网络流包装器模块
 * @details 封装 Boost.Beast TCP 流，提供统一的异步操作接口。
 *
 * 核心特性：
 * - TCP 支持：封装 boost::beast::tcp_stream
 * - 异步操作：支持协程风格的异步读写
 * - 原生句柄访问：提供对底层 TCP 流的访问
 *
 * @note 设计原则：
 * - RAII 管理：自动管理 TCP 流的生命周期
 * - 移动语义：支持移动构造和移动赋值
 * - 零开销抽象：内联函数减少调用开销
 */

#pragma once

#include <memory>

#include <boost/asio.hpp>
#include <boost/beast.hpp>

namespace srv::socket
{
    namespace net = boost::asio;
    namespace beast = boost::beast;

    /**
     * @class tcp_wrapper
     * @brief TCP 流包装器类
     * @details 封装 TCP 流，提供统一的异步操作接口
     */
    class tcp_wrapper
    {
    public:
        using stream_type = beast::tcp_stream;
        using executor_type = net::any_io_executor;

        explicit tcp_wrapper(net::ip::tcp::socket socket)
            : stream_(std::make_unique<stream_type>(std::move(socket)))
        {
        }

        tcp_wrapper(tcp_wrapper &&) noexcept = default;
        tcp_wrapper &operator=(tcp_wrapper &&) noexcept = default;
        tcp_wrapper(const tcp_wrapper &) = delete;
        tcp_wrapper &operator=(const tcp_wrapper &) = delete;

        [[nodiscard]] executor_type get_executor()
        {
            return stream_->get_executor();
        }

        [[nodiscard]] net::ip::tcp::socket &socket() noexcept
        {
            return stream_->socket();
        }

        [[nodiscard]] const net::ip::tcp::socket &socket() const noexcept
        {
            return stream_->socket();
        }

        void set_option(const auto &option)
        {
            stream_->socket().set_option(option);
        }

        void expires_after(const auto &duration)
        {
            stream_->expires_after(duration);
        }

        void expires_never()
        {
            stream_->expires_never();
        }

        void close()
        {
            if (stream_)
            {
                beast::error_code ec;
                stream_->socket().close(ec);
            }
        }

        [[nodiscard]] stream_type &&release()
        {
            return std::move(*stream_);
        }

        template <typename MutableBufferSequence, typename CompletionToken>
        auto async_read_some(const MutableBufferSequence &buffers, CompletionToken &&token)
        {
            return stream_->async_read_some(buffers, std::forward<CompletionToken>(token));
        }

        template <typename ConstBufferSequence, typename CompletionToken>
        auto async_write_some(const ConstBufferSequence &buffers, CompletionToken &&token)
        {
            return stream_->async_write_some(buffers, std::forward<CompletionToken>(token));
        }

    private:
        std::unique_ptr<stream_type> stream_;
    };
}
