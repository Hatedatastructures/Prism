/**
 * @file secure.hpp
 * @brief 安全传输层实现
 * @details 将 ssl::stream 适配为 transmission 接口，供协议装饰器使用。
 * 该适配器允许 trojan::stream 等协议层装饰 TLS 加密流，
 * 实现协议处理与传输层的解耦。命名与 reliable.hpp 对应：
 * reliable 表示可靠传输（TCP），secure 表示安全传输（TLS）。
 */

#pragma once

#include <memory>
#include <span>
#include <system_error>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <forward-engine/channel/transport/transmission.hpp>
#include <forward-engine/channel/adapter/adaptation.hpp>
#include <forward-engine/gist/handling.hpp>

namespace ngx::channel::transport
{
    namespace net = boost::asio;
    namespace ssl = net::ssl;

    /**
     * @class secure
     * @brief 安全传输层实现
     * @details 将 ssl::stream<connector> 适配为 transmission 接口，
     * 使协议装饰器（如 trojan::stream）能够装饰 TLS 加密流。
     * 该类持有 ssl::stream 的共享所有权，确保在协议处理期间流对象有效。
     */
    class secure : public transmission
    {
    public:
        using connector_type = ngx::channel::connector<transmission_pointer>;
        using stream_type = ssl::stream<connector_type>;
        using stream_ptr = std::shared_ptr<stream_type>;

        /**
         * @brief 构造安全传输层
         * @param ssl_stream TLS 流的共享指针
         */
        explicit secure(stream_ptr ssl_stream)
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
            ec = ngx::gist::make_error_code(ngx::gist::to_code(sys_ec));
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
            ec = ngx::gist::make_error_code(ngx::gist::to_code(sys_ec));
            co_return n;
        }

        /**
         * @brief 关闭传输层
         */
        void close() override
        {
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
         * @return stream_ptr TLS 流共享指针
         */
        stream_ptr release()
        {
            return std::move(ssl_stream_);
        }

    private:
        stream_ptr ssl_stream_;
    };

    /**
     * @brief 创建安全传输层
     * @param ssl_stream TLS 流的共享指针
     * @return transmission_pointer 传输层指针
     */
    inline transmission_pointer make_secure(secure::stream_ptr ssl_stream)
    {
        return std::make_unique<secure>(std::move(ssl_stream));
    }
}
