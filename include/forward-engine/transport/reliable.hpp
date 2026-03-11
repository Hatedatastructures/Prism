/**
 * @file reliable.hpp
 * @brief 可靠的流式传输实现（TCP）
 * @details 封装 `boost::asio::ip::tcp::socket`，提供基于 TCP 的可靠流式传输。该类继承自 `transmission`，是分层流式架构中的具体传输层实现，支持异步读写、关闭、取消等操作。
 *
 * 架构说明：
 * @details - 传输抽象：继承 `transmission` 接口，实现 TCP 传输层的具体功能；
 * @details - 协程设计：所有异步操作返回 `net::awaitable`，简化异步操作调用；
 * @details - 错误码映射：自动映射 Boost.System 错误码到项目错误码；
 * @details - 智能指针：支持 `std::enable_shared_from_this`，便于生命周期管理。
 *
 * 设计特性：
 * @details - 可靠传输：TCP 保证数据有序送达，不丢失、不重复；
 * @details - 流式语义：提供流式读写接口，支持部分读写；
 * @details - 原生访问：提供 `native_socket()` 方法直接访问底层 socket；
 * @details - 工厂函数：提供 `make_reliable` 工厂函数简化创建。
 *
 * 使用场景：
 * @details - HTTP 代理：作为 HTTP 代理的传输层；
 * @details - SOCKS5 代理：作为 SOCKS5 代理的传输层；
 * @details - Trojan 代理：作为 Trojan 协议的底层传输。
 *
 * @note 该类是传输层的核心实现，所有基于 TCP 的协议都应使用此类。
 * @warning 关闭后传输层对象不再可用，不应再调用其任何方法。
 */

#pragma once

#include <boost/asio.hpp>
#include <forward-engine/transport/transmission.hpp>
#include <forward-engine/gist/handling.hpp>
#include <memory>

namespace ngx::transport
{
    namespace net = boost::asio;

    /**
     * @class reliable
     * @brief 可靠的流式传输实现（TCP）
     * @details 封装 TCP socket，实现 `core::transmission` 接口。
     * 该类支持异步读写、关闭、取消等操作，适用于所有基于 TCP 的协议。
     */
    class reliable : public transmission, public std::enable_shared_from_this<reliable>
    {
    public:
        using socket_type = net::ip::tcp::socket;

        /**
         * @brief 构造函数
         * @param executor 执行器，用于初始化 socket
         */
        explicit reliable(net::any_io_executor executor)
            : socket_(executor)
        {
        }

        /**
         * @brief 构造函数
         * @param socket 已构造的 TCP socket
         */
        explicit reliable(socket_type socket)
            : socket_(std::move(socket))
        {
        }

        /**
         * @brief 获取关联的执行器
         * @return executor_type 执行器
         */
        executor_type executor() const override
        {
            return const_cast<socket_type &>(socket_).get_executor();
        }

        /**
         * @brief 异步读取数据
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @details 调用 `socket_.async_read_some` 实现异步读取。
         * @return std::size_t 异步操作，完成后返回读取的字节数
         */
        auto async_read_some(std::span<std::byte> buffer, std::error_code& ec) 
            -> net::awaitable<std::size_t> override
        {
            boost::system::error_code sys_ec;
            auto token = net::redirect_error(net::use_awaitable, sys_ec);
            const auto n = co_await socket_.async_read_some(net::buffer(buffer.data(), buffer.size()),token);
            ec = ngx::gist::make_error_code(ngx::gist::to_code(sys_ec));
            co_return n;
        }

        /**
         * @brief 异步写入数据
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @details 调用 `socket_.async_write_some` 实现异步写入。
         * @return std::size_t 异步操作，完成后返回写入的字节数
         */
        auto async_write_some(std::span<const std::byte> buffer, std::error_code& ec) 
            -> net::awaitable<std::size_t> override
        {
            boost::system::error_code sys_ec;
            auto token = net::redirect_error(net::use_awaitable, sys_ec);
            const auto n = co_await socket_.async_write_some(net::buffer(buffer.data(), buffer.size()),token);
            ec = ngx::gist::make_error_code(ngx::gist::to_code(sys_ec));
            co_return n;
        }

        /**
         * @brief 关闭传输层
         * @details 关闭底层 TCP socket。
         */
        void close() override
        {
            boost::system::error_code ec;
            socket_.close(ec);
        }

        /**
         * @brief 取消所有未完成的异步操作
         */
        void cancel() override
        {
            boost::system::error_code ec;
            socket_.cancel(ec);
        }

        /**
         * @brief 获取底层 socket 引用
         * @return socket_type& socket 引用
         * @note 用于需要直接操作 socket 的场景（如设置 TCP_NODELAY）。
         */
        socket_type &native_socket() noexcept
        {
            return socket_;
        }

        /**
         * @brief 检查传输是否可靠（如 TCP）
         * @details 重写基类虚函数，返回 true。
         */
        [[nodiscard]] bool is_reliable() const noexcept override
        {
            return true;
        }

        /**
         * @brief 获取底层 socket 常量引用
         * @return const socket_type& socket 常量引用
         */
        const socket_type &native_socket() const noexcept
        {
            return socket_;
        }

    private:
        socket_type socket_;
    };

    /**
     * @brief 创建 reliable 传输层
     * @param executor 执行器
     * @return `transmission_pointer` 创建的 `reliable` 实例
     */
    inline transmission_pointer make_reliable(net::any_io_executor executor)
    {
        return std::make_unique<reliable>(executor);
    }

    /**
     * @brief 创建 reliable 传输层（从现有 socket）
     * @param socket TCP socket
     * @return `transmission_pointer` 创建的 `reliable` 实例
     */
    inline transmission_pointer make_reliable(net::ip::tcp::socket socket)
    {
        return std::make_unique<reliable>(std::move(socket));
    }

} // namespace ngx::transport
