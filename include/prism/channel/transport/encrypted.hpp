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
     */
    class encrypted : public transmission
    {
    public:
        using connector_type = psm::channel::connector;
        using stream_type = ssl::stream<connector_type>;
        using shared_stream = std::shared_ptr<stream_type>;

        /**
         * @brief 构造加密传输层
         * @param ssl_stream TLS 流的共享指针
         */
        explicit encrypted(shared_stream ssl_stream)
            : ssl_stream_(std::move(ssl_stream))
        {
        }

        /**
         * @brief 检查传输是否可靠
         * @return 始终返回 true，TLS 流是可靠的
         */
        [[nodiscard]] bool is_reliable() const noexcept override
        {
            return true;
        }

        /**
         * @brief 获取关联的执行器
         * @return 底层 TLS 流的执行器
         */
        [[nodiscard]] executor_type executor() const override
        {
            return const_cast<stream_type &>(*ssl_stream_).get_executor();
        }

        /**
         * @brief 异步读取数据
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
         */
        void cancel() override
        {
            ssl_stream_->lowest_layer().transmission().cancel();
        }

        /**
         * @brief 获取底层 TLS 流引用
         * @return stream_type& TLS 流引用
         */
        [[nodiscard]] stream_type &stream() noexcept
        {
            return *ssl_stream_;
        }

        /**
         * @brief 获取底层 TLS 流常量引用
         * @return const stream_type& TLS 流常量引用
         */
        [[nodiscard]] const stream_type &stream() const noexcept
        {
            return *ssl_stream_;
        }

        /**
         * @brief 释放 TLS 流所有权
         * @return shared_stream TLS 流共享指针
         */
        shared_stream release()
        {
            return std::move(ssl_stream_);
        }

    private:
        shared_stream ssl_stream_;
    };

    /**
     * @brief 创建加密传输层
     * @param ssl_stream TLS 流的共享指针
     * @return shared_transmission 传输层指针
     */
    inline shared_transmission make_encrypted(encrypted::shared_stream ssl_stream)
    {
        return std::make_shared<encrypted>(std::move(ssl_stream));
    }
}
