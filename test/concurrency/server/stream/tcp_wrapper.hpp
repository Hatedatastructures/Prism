/**
 * @file tcp_wrapper.hpp
 * @brief TCP 流包装器定义
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
 *
 */
#pragma once

#include <boost/asio.hpp>
#include <boost/beast.hpp>

namespace srv::stream
{
    /**
     * @class tcp_stream_wrapper
     * @brief TCP 流包装器类
     * @details 封装 TCP 流，提供统一的异步操作接口
     */
    class tcp_stream_wrapper
    {
    public:
        using stream_type = boost::beast::tcp_stream;
        using executor_type = boost::asio::any_io_executor;

        explicit tcp_stream_wrapper(boost::asio::ip::tcp::socket socket)
            : stream_(std::move(socket))
        {
        }

        explicit tcp_stream_wrapper(stream_type &&stream)
            : stream_(std::move(stream))
        {
        }

        [[nodiscard]] auto get_executor() -> boost::asio::any_io_executor
        {
            return stream_.get_executor();
        }

        [[nodiscard]] auto next_layer() -> boost::asio::ip::tcp::socket &
        {
            return stream_.socket();
        }

        [[nodiscard]] auto next_layer() const -> const boost::asio::ip::tcp::socket &
        {
            return stream_.socket();
        }

        [[nodiscard]] auto native_handle() -> stream_type &&
        {
            return std::move(stream_);
        }

        auto set_option(const auto &option) -> void
        {
            next_layer().set_option(option);
        }

        auto expires_after(const auto &duration) -> void
        {
            stream_.expires_after(duration);
        }

        auto expires_never() -> void
        {
            stream_.expires_never();
        }

        auto close() -> void
        {
            boost::beast::error_code ec;
            stream_.socket().close(ec);
        }

        template <typename MutableBufferSequence, typename CompletionToken>
        auto async_read_some(const MutableBufferSequence &buffers, CompletionToken &&token)
        {
            return stream_.async_read_some(buffers, std::forward<CompletionToken>(token));
        }

        template <typename ConstBufferSequence, typename CompletionToken>
        auto async_write_some(const ConstBufferSequence &buffers, CompletionToken &&token)
        {
            return stream_.async_write_some(buffers, std::forward<CompletionToken>(token));
        }

    private:
        stream_type stream_;
    };
}
