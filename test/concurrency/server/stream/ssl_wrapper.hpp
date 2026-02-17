/**
 * @file ssl_wrapper.hpp
 * @brief SSL 流包装器定义
 * @details 封装 Boost.Beast 和 Boost.Asio SSL 流，提供统一的异步操作接口。
 *
 * 核心特性：
 * - SSL/TLS 支持：封装 boost::asio::ssl::stream
 * - 异步操作：支持协程风格的异步读写
 * - 原生句柄访问：提供对底层 SSL 流的访问
 *
 * @note 设计原则：
 * - RAII 管理：自动管理 SSL 流的生命周期
 * - 移动语义：支持移动构造和移动赋值
 * - 零开销抽象：内联函数减少调用开销
 *
 */
#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>

namespace srv::stream
{
    /**
     * @class ssl_stream_wrapper
     * @brief SSL 流包装器类
     * @details 封装 SSL 流，提供统一的异步操作接口
     */
    class ssl_stream_wrapper
    {
    public:
        using stream_type = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
        using executor_type = boost::asio::any_io_executor;

        explicit ssl_stream_wrapper(boost::asio::ip::tcp::socket socket, boost::asio::ssl::context &ssl_ctx)
            : stream_(std::move(socket), ssl_ctx)
        {
        }

        explicit ssl_stream_wrapper(stream_type &&stream)
            : stream_(std::move(stream))
        {
        }

        [[nodiscard]] auto get_executor() -> boost::asio::any_io_executor
        {
            return stream_.get_executor();
        }

        [[nodiscard]] auto next_layer() -> boost::asio::ip::tcp::socket &
        {
            return stream_.next_layer();
        }

        [[nodiscard]] auto next_layer() const -> const boost::asio::ip::tcp::socket &
        {
            return stream_.next_layer();
        }

        [[nodiscard]] auto native_handle() -> stream_type &&
        {
            return std::move(stream_);
        }

        auto set_option(const auto &option) -> void
        {
            next_layer().set_option(option);
        }

        auto expires_after([[maybe_unused]] const auto &duration) -> void
        {
        }

        auto close() -> void
        {
            boost::beast::error_code ec;
            stream_.shutdown(ec);
            next_layer().close(ec);
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

        template <typename CompletionToken>
        auto async_handshake(boost::asio::ssl::stream_base::handshake_type type, CompletionToken &&token)
        {
            return stream_.async_handshake(type, std::forward<CompletionToken>(token));
        }

        template <typename CompletionToken>
        auto async_shutdown(CompletionToken &&token)
        {
            return stream_.async_shutdown(std::forward<CompletionToken>(token));
        }

    private:
        stream_type stream_;
    };
}
