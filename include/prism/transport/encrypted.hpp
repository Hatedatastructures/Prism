/**
 * @file encrypted.hpp
 * @brief 加密传输层实现
 * @details 将 ssl::stream 适配为 transmission 接口，供协议装饰器使用。
 * 该适配器允许 trojan::stream 等协议层装饰 TLS 加密流，
 * 实现协议处理与传输层的解耦。
 */

#pragma once

#include <prism/fault/code.hpp>
#include <prism/fault/handling.hpp>
#include <prism/trace.hpp>
#include <prism/transport/adapter/connector.hpp>
#include <prism/transport/transmission.hpp>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/ssl.h>

#include <array>
#include <memory>
#include <span>
#include <system_error>


namespace psm::transport
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
    class encrypted final : public transmission
    {
    public:
        using connector_type = psm::transport::connector;
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
         * @brief 获取传输层类型
         * @return type::tcp TLS 始终基于 TCP
         */
        [[nodiscard]] auto transport_type() const noexcept
            -> type override
        {
            return type::tcp;
        }

        /**
         * @brief 获取内层传输
         * @return nullptr encrypted 持有 ssl::stream 而非 transmission*
         */
        [[nodiscard]] auto next_layer() noexcept -> transmission * override
        {
            return nullptr;
        }

        [[nodiscard]] auto next_layer() const noexcept -> const transmission * override
        {
            return nullptr;
        }

        /**
         * @brief 获取关联的执行器
         * @details 返回底层 TLS 流关联的执行器，用于调度异步操作。
         * @return 底层 TLS 流的执行器
         */
        [[nodiscard]] auto executor() const -> executor_type override
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
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            boost::system::error_code sys_ec;
            auto token = net::redirect_error(trace::use_prefix_awaitable, sys_ec);
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
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            boost::system::error_code sys_ec;
            auto token = net::redirect_error(trace::use_prefix_awaitable, sys_ec);
            const auto n = co_await ssl_stream_->async_write_some(
                net::buffer(buffer.data(), buffer.size()), token);
            ec = psm::fault::make_error_code(psm::fault::to_code(sys_ec));
            co_return n;
        }

        /**
         * @brief 关闭传输层
         * @details 先发起 SSL_shutdown 优雅关闭 TLS 会话，
         * 然后关闭底层 socket，忽略所有错误。
         */
        void close() override
        {
            auto *ssl = ssl_stream_->native_handle();
            if (ssl)
            {
                SSL_set_quiet_shutdown(ssl, 1);
                SSL_shutdown(ssl);
            }
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
        [[nodiscard]] auto stream() noexcept
            -> stream_type &
        {
            return *ssl_stream_;
        }

        /**
         * @brief 获取底层 TLS 流常量引用
         * @details 返回内部 TLS 流的常量引用，用于只读访问。
         * @return const stream_type& TLS 流常量引用
         */
        [[nodiscard]] auto stream() const noexcept
            -> const stream_type &
        {
            return *ssl_stream_;
        }

        /**
         * @brief 释放 TLS 流所有权
         * @details 将内部持有的 TLS 流共享指针移动返回，调用后对象不再持有流。
         * @return shared_stream TLS 流共享指针
         */
        [[nodiscard]] auto release()
            -> shared_stream
        {
            return std::move(ssl_stream_);
        }

        /**
         * @brief 执行 TLS 服务端握手（静态工厂）
         * @param inbound 入站传输层（所有权被转移）
         * @param ssl_ctx SSL 上下文
         * @return 协程对象，完成后返回：错误码、TLS 流（成功时）、
         * 失败时从 connector 恢复的传输层（成功时为 nullptr）
         * @details 将入站传输层包装为 connector，执行 TLS 服务端握手。
         * 握手失败时从 connector 释放传输层所有权，避免 transport 丢失。
         * @note 调用方应确保入站传输已包装 preview（如有预读数据）。
         */
        [[nodiscard]] static auto ssl_handshake(shared_transmission inbound, ssl::context &ssl_ctx)
            -> net::awaitable<std::tuple<fault::code, shared_stream, shared_transmission>>;

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
    [[nodiscard]] inline shared_transmission make_encrypted(encrypted::shared_stream ssl_stream)
    {
        return std::make_shared<encrypted>(std::move(ssl_stream));
    }
}
