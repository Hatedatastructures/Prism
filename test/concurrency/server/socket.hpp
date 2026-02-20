/**
 * @file socket.hpp
 * @brief 网络流包装器模块
 * @details 封装 Boost.Beast 和 Boost.Asio 流，提供统一的异步操作接口。
 *
 * 核心特性：
 * - TCP 支持：封装 boost::beast::tcp_stream
 * - SSL/TLS 支持：封装 boost::asio::ssl::stream
 * - 异步操作：支持协程风格的异步读写
 * - 原生句柄访问：提供对底层流的访问
 *
 * @note 设计原则：
 * - RAII 管理：自动管理流的生命周期
 * - 移动语义：支持移动构造和移动赋值
 * - 零开销抽象：内联函数减少调用开销
 *
 * @see httpsession.hpp
 */
#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>

namespace srv::socket
{
    /**
     * @class tcp_wrapper
     * @brief TCP 流包装器类
     * @details 封装 TCP 流，提供统一的异步操作接口
     */
    class tcp_wrapper
    {
    public:
        using stream_type = boost::beast::tcp_stream;
        using executor_type = boost::asio::any_io_executor;

        /**
         * @brief 从 TCP socket 构造
         * @param socket TCP socket
         */
        explicit tcp_wrapper(boost::asio::ip::tcp::socket socket)
            : stream_(std::move(socket))
        {
        }

        /**
         * @brief 从 tcp_stream 构造
         * @param stream tcp_stream 右值引用
         */
        explicit tcp_wrapper(stream_type &&stream)
            : stream_(std::move(stream))
        {
        }

        /**
         * @brief 获取执行器
         * @return 执行器
         */
        [[nodiscard]] auto get_executor() -> boost::asio::any_io_executor
        {
            return stream_.get_executor();
        }

        /**
         * @brief 获取底层 socket
         * @return socket 引用
         */
        [[nodiscard]] auto next_layer() -> boost::asio::ip::tcp::socket &
        {
            return stream_.socket();
        }

        /**
         * @brief 获取底层 socket（常量版本）
         * @return socket 常量引用
         */
        [[nodiscard]] auto next_layer() const -> const boost::asio::ip::tcp::socket &
        {
            return stream_.socket();
        }

        /**
         * @brief 获取原生句柄
         * @return tcp_stream 右值引用
         */
        [[nodiscard]] auto native_handle() -> stream_type &&
        {
            return std::move(stream_);
        }

        /**
         * @brief 设置 socket 选项
         * @tparam Option 选项类型
         * @param option 选项值
         */
        auto set_option(const auto &option) -> void
        {
            next_layer().set_option(option);
        }

        /**
         * @brief 设置超时时间
         * @tparam Duration 时间类型
         * @param duration 超时时间
         */
        auto expires_after(const auto &duration) -> void
        {
            stream_.expires_after(duration);
        }

        /**
         * @brief 禁用超时
         */
        auto expires_never() -> void
        {
            stream_.expires_never();
        }

        /**
         * @brief 关闭连接
         */
        auto close() -> void
        {
            boost::beast::error_code ec;
            stream_.socket().close(ec);
        }

        /**
         * @brief 异步读取
         * @tparam MutableBufferSequence 可变缓冲区序列
         * @tparam CompletionToken 完成令牌
         * @param buffers 缓冲区
         * @param token 完成令牌
         * @return 异步操作结果
         */
        template <typename MutableBufferSequence, typename CompletionToken>
        auto async_read_some(const MutableBufferSequence &buffers, CompletionToken &&token)
        {
            return stream_.async_read_some(buffers, std::forward<CompletionToken>(token));
        }

        /**
         * @brief 异步写入
         * @tparam ConstBufferSequence 常量缓冲区序列
         * @tparam CompletionToken 完成令牌
         * @param buffers 缓冲区
         * @param token 完成令牌
         * @return 异步操作结果
         */
        template <typename ConstBufferSequence, typename CompletionToken>
        auto async_write_some(const ConstBufferSequence &buffers, CompletionToken &&token)
        {
            return stream_.async_write_some(buffers, std::forward<CompletionToken>(token));
        }

    private:
        stream_type stream_;
    };

    /**
     * @class ssl_wrapper
     * @brief SSL 流包装器类
     * @details 封装 SSL 流，提供统一的异步操作接口
     */
    class ssl_wrapper
    {
    public:
        using stream_type = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
        using executor_type = boost::asio::any_io_executor;

        /**
         * @brief 从 TCP socket 和 SSL 上下文构造
         * @param socket TCP socket
         * @param ssl_ctx SSL 上下文
         */
        explicit ssl_wrapper(boost::asio::ip::tcp::socket socket, boost::asio::ssl::context &ssl_ctx)
            : stream_(std::move(socket), ssl_ctx)
        {
        }

        /**
         * @brief 从 SSL stream 构造
         * @param stream SSL stream 右值引用
         */
        explicit ssl_wrapper(stream_type &&stream)
            : stream_(std::move(stream))
        {
        }

        /**
         * @brief 获取执行器
         * @return 执行器
         */
        [[nodiscard]] auto get_executor() -> boost::asio::any_io_executor
        {
            return stream_.get_executor();
        }

        /**
         * @brief 获取底层 socket
         * @return socket 引用
         */
        [[nodiscard]] auto next_layer() -> boost::asio::ip::tcp::socket &
        {
            return stream_.next_layer();
        }

        /**
         * @brief 获取底层 socket（常量版本）
         * @return socket 常量引用
         */
        [[nodiscard]] auto next_layer() const -> const boost::asio::ip::tcp::socket &
        {
            return stream_.next_layer();
        }

        /**
         * @brief 获取原生句柄
         * @return SSL stream 右值引用
         */
        [[nodiscard]] auto native_handle() -> stream_type &&
        {
            return std::move(stream_);
        }

        /**
         * @brief 设置 socket 选项
         * @tparam Option 选项类型
         * @param option 选项值
         */
        auto set_option(const auto &option) -> void
        {
            next_layer().set_option(option);
        }

        /**
         * @brief 设置超时时间
         * @tparam Duration 时间类型
         * @param duration 超时时间
         * @note 存储超时值供后续定时器使用
         */
        template <typename Duration>
        auto expires_after(const Duration &duration) -> void
        {
            timeout_ = std::chrono::duration_cast<std::chrono::steady_clock::duration>(duration);
        }

        /**
         * @brief 获取超时时间
         * @return 超时时间
         */
        [[nodiscard]] auto get_timeout() const -> std::chrono::steady_clock::duration
        {
            return timeout_;
        }

        /**
         * @brief 禁用超时
         */
        auto expires_never() -> void
        {
            timeout_ = std::chrono::steady_clock::duration::max();
        }

        /**
         * @brief 关闭连接
         */
        auto close() -> void
        {
            boost::beast::error_code ec;
            stream_.shutdown(ec);
            next_layer().close(ec);
        }

        /**
         * @brief 异步读取
         * @tparam MutableBufferSequence 可变缓冲区序列
         * @tparam CompletionToken 完成令牌
         * @param buffers 缓冲区
         * @param token 完成令牌
         * @return 异步操作结果
         */
        template <typename MutableBufferSequence, typename CompletionToken>
        auto async_read_some(const MutableBufferSequence &buffers, CompletionToken &&token)
        {
            return stream_.async_read_some(buffers, std::forward<CompletionToken>(token));
        }

        /**
         * @brief 异步写入
         * @tparam ConstBufferSequence 常量缓冲区序列
         * @tparam CompletionToken 完成令牌
         * @param buffers 缓冲区
         * @param token 完成令牌
         * @return 异步操作结果
         */
        template <typename ConstBufferSequence, typename CompletionToken>
        auto async_write_some(const ConstBufferSequence &buffers, CompletionToken &&token)
        {
            return stream_.async_write_some(buffers, std::forward<CompletionToken>(token));
        }

        /**
         * @brief 异步 SSL 握手
         * @tparam CompletionToken 完成令牌
         * @param type 握手类型
         * @param token 完成令牌
         * @return 异步操作结果
         */
        template <typename CompletionToken>
        auto async_handshake(boost::asio::ssl::stream_base::handshake_type type, CompletionToken &&token)
        {
            return stream_.async_handshake(type, std::forward<CompletionToken>(token));
        }

        /**
         * @brief 异步 SSL 关闭
         * @tparam CompletionToken 完成令牌
         * @param token 完成令牌
         * @return 异步操作结果
         */
        template <typename CompletionToken>
        auto async_shutdown(CompletionToken &&token)
        {
            return stream_.async_shutdown(std::forward<CompletionToken>(token));
        }

    private:
        stream_type stream_;
        std::chrono::steady_clock::duration timeout_{std::chrono::seconds(30)};
    };
}
