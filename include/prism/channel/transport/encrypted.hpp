/**
 * @file encrypted.hpp
 * @brief 加密传输层实现
 * @details 将 ssl::stream 适配为 transmission 接口，供协议装饰器使用。
 * 该适配器允许 trojan::stream 等协议层装饰 TLS 加密流，
 * 实现协议处理与传输层的解耦。
 */

#pragma once

#include <array>
#include <memory>
#include <span>
#include <system_error>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/ssl.h>

#include <prism/channel/transport/transmission.hpp>
#include <prism/channel/adapter/connector.hpp>
#include <prism/fault/handling.hpp>

namespace psm::channel::transport
{
    namespace net = boost::asio;
    namespace ssl = net::ssl;

    /**
     * @class encrypted
     * @brief 加密传输层实现
     * @details 将 ssl::stream<connector> 适配为 transmission 接口，
     * 使协议装饰器（如 trojan::stream）能够装饰 TLS 加密流。
     * 该类持有 ssl::stream 的共享所有权，确保在协议处理期间流对象有效。
     * 核心职责包括传输抽象，继承 transmission 接口实现 TLS 传输层；
     * 协程设计，所有异步操作返回 net::awaitable 简化调用；
     * 错误码映射，自动映射 Boost.System 错误码到项目错误码。
     * @note 该类用于 TLS 加密场景，所有基于 TLS 的协议都应使用此类。
     * @warning 关闭后传输层对象不再可用，不应再调用其任何方法。
     * @throws std::bad_alloc 如果内存分配失败
     */
    class encrypted : public transmission
    {
    public:
        using connector_type = psm::channel::connector;
        using stream_type = ssl::stream<connector_type>;
        using shared_stream = std::shared_ptr<stream_type>;

        /**
         * @brief 构造加密传输层
         * @details 使用已建立的 TLS 流创建加密传输层。
         * TLS 流必须已完成握手。
         * @param ssl_stream TLS 流的共享指针
         */
        explicit encrypted(shared_stream ssl_stream)
            : ssl_stream_(std::move(ssl_stream))
        {
        }

        /**
         * @brief 检查传输是否可靠
         * @details 重写基类虚函数，TLS 基于 TCP，始终返回 true。
         * @return 始终返回 true，TLS 流是可靠的
         */
        [[nodiscard]] bool is_reliable() const noexcept override
        {
            return true;
        }

        /**
         * @brief 获取关联的执行器
         * @details 返回底层 TLS 流关联的执行器，用于调度异步操作。
         * @return 底层 TLS 流的执行器
         */
        [[nodiscard]] executor_type executor() const override
        {
            return const_cast<stream_type &>(*ssl_stream_).get_executor();
        }

        /**
         * @brief 异步读取数据
         * @details 调用底层 TLS 流的 async_read_some 实现异步读取。
         * 返回实际读取的字节数，错误通过 ec 返回。
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回读取的字节数
         */
        auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            boost::system::error_code sys_ec;
            auto token = net::redirect_error(net::use_awaitable, sys_ec);
            const auto n = co_await ssl_stream_->async_read_some(
                net::buffer(buffer.data(), buffer.size()), token);
            ec = psm::fault::make_error_code(psm::fault::to_code(sys_ec));
            co_return n;
        }

        /**
         * @brief 异步写入数据
         * @details 调用底层 TLS 流的 async_write_some 实现异步写入。
         * 返回实际写入的字节数，错误通过 ec 返回。
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回写入的字节数
         */
        auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            boost::system::error_code sys_ec;
            auto token = net::redirect_error(net::use_awaitable, sys_ec);
            const auto n = co_await ssl_stream_->async_write_some(
                net::buffer(buffer.data(), buffer.size()), token);
            ec = psm::fault::make_error_code(psm::fault::to_code(sys_ec));
            co_return n;
        }

        /**
         * @brief Scatter-gather 写入（TLS 优化）
         * @details 将多个缓冲区合并为单次 async_write 写入，底层 SSL_write 将
         * 帧头和载荷合并为一条 TLS 记录，避免两次加密操作和额外的 TLS 帧头开销。
         */
        auto async_write_scatter(const std::span<const std::byte> *buffers, std::size_t count, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (count == 0)
            {
                ec.clear();
                co_return 0;
            }

            boost::system::error_code sys_ec;
            auto token = net::redirect_error(net::use_awaitable, sys_ec);
            std::size_t total = 0;

            if (count == 2) [[likely]]
            {
                const std::array<net::const_buffer, 2> bufs{{net::const_buffer(buffers[0].data(), buffers[0].size()),
                                                             net::const_buffer(buffers[1].data(), buffers[1].size())}};
                total = co_await net::async_write(*ssl_stream_, bufs, token);
            }
            else
            {
                for (std::size_t i = 0; i < count; ++i)
                {
                    const auto n = co_await async_write(buffers[i], ec);
                    total += n;
                    if (ec)
                    {
                        co_return total;
                    }
                }
                co_return total;
            }

            ec = psm::fault::make_error_code(psm::fault::to_code(sys_ec));
            co_return total;
        }

        /**
         * @brief 关闭传输层
         * @details 先发送 TLS close_notify 通知对端，然后关闭底层传输层。
         * SSL_shutdown 在非阻塞模式下立即返回，不等待对端响应。
         */
        void close() override
        {
            // best-effort SSL_shutdown：发送 close_notify 通知对端
            // 非阻塞模式下立即返回，不等待对端响应
            ::SSL_shutdown(ssl_stream_->native_handle());
            ssl_stream_->lowest_layer().transmission().close();
        }

        /**
         * @brief 取消所有未完成的异步操作
         * @details 取消底层传输层当前所有挂起的异步读写操作。
         * 被取消的操作将返回 operation_canceled 错误。
         */
        void cancel() override
        {
            ssl_stream_->lowest_layer().transmission().cancel();
        }

        /**
         * @brief 获取底层 TLS 流引用
         * @details 返回内部 TLS 流的引用，用于直接操作 TLS 层。
         * @return stream_type& TLS 流引用
         */
        [[nodiscard]] stream_type &stream() noexcept
        {
            return *ssl_stream_;
        }

        /**
         * @brief 获取底层 TLS 流常量引用
         * @details 返回内部 TLS 流的常量引用，用于只读访问。
         * @return const stream_type& TLS 流常量引用
         */
        [[nodiscard]] const stream_type &stream() const noexcept
        {
            return *ssl_stream_;
        }

        /**
         * @brief 释放 TLS 流所有权
         * @details 将内部持有的 TLS 流共享指针移动返回，调用后对象不再持有流。
         * @return shared_stream TLS 流共享指针
         */
        shared_stream release()
        {
            return std::move(ssl_stream_);
        }

    private:
        shared_stream ssl_stream_; // TLS 流的共享指针，持有流的所有权
    };

    /**
     * @brief 创建加密传输层
     * @details 使用已建立的 TLS 流创建加密传输层实例。
     * TLS 流必须已完成握手。
     * @param ssl_stream TLS 流的共享指针
     * @return shared_transmission 传输层指针
     */
    inline shared_transmission make_encrypted(encrypted::shared_stream ssl_stream)
    {
        return std::make_shared<encrypted>(std::move(ssl_stream));
    }
}
