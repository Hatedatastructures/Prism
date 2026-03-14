/**
 * @file reliable.hpp
 * @brief 可靠的流式传输实现（TCP）
 * @details 封装 boost::asio::ip::tcp::socket，提供基于 TCP 的可靠流式传输。
 * 该类继承自 transmission，是分层流式架构中的具体传输层实现，
 * 支持异步读写、关闭、取消等操作。所有异步操作返回 net::awaitable，
 * 简化异步操作调用。设计特性包括可靠传输，TCP 保证数据有序送达；
 * 流式语义，提供流式读写接口，支持部分读写；原生访问，
 * 提供 native_socket 方法直接访问底层 socket。
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
     * @details 封装 TCP socket，实现 core::transmission 接口。
     * 该类支持异步读写、关闭、取消等操作，适用于所有基于 TCP 的协议。
     * 核心职责包括传输抽象，继承 transmission 接口实现 TCP 传输层；
     * 协程设计，所有异步操作返回 net::awaitable 简化调用；
     * 错误码映射，自动映射 Boost.System 错误码到项目错误码；
     * 智能指针支持，通过 std::enable_shared_from_this 管理生命周期。
     * 设计特性包括可靠传输，TCP 保证数据有序送达不丢失不重复；
     * 流式语义，提供流式读写接口支持部分读写；原生访问，
     * 提供 native_socket 方法直接访问底层 socket；
     * 工厂函数，提供 make_reliable 工厂函数简化创建。
     * @note 该类是传输层的核心实现，所有基于 TCP 的协议都应使用此类。
     * @warning 关闭后传输层对象不再可用，不应再调用其任何方法。
     * @throws std::bad_alloc 如果内存分配失败
     */
    class reliable : public transmission, public std::enable_shared_from_this<reliable>
    {
    public:
        using socket_type = net::ip::tcp::socket;

        /**
         * @brief 构造函数
         * @details 使用执行器初始化 TCP socket。Socket 在构造时
         * 不打开，需要在后续调用 open 或 accept 后才能使用。
         * @param executor 执行器，用于初始化 socket
         */
        explicit reliable(net::any_io_executor executor)
            : socket_(executor)
        {
        }

        /**
         * @brief 构造函数
         * @details 使用已构造的 TCP socket 初始化传输层。
         * Socket 必须已打开并连接。
         * @param socket 已构造的 TCP socket
         */
        explicit reliable(socket_type socket)
            : socket_(std::move(socket))
        {
        }

        /**
         * @brief 获取关联的执行器
         * @details 返回底层 socket 关联的执行器，用于调度异步操作。
         * @return executor_type 执行器
         */
        executor_type executor() const override
        {
            return const_cast<socket_type &>(socket_).get_executor();
        }

        /**
         * @brief 异步读取数据
         * @details 调用 socket_.async_read_some 实现异步读取。
         * 返回实际读取的字节数，错误通过 ec 返回。
         * 如果操作成功，ec 为默认值；否则包含错误信息。
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回读取的字节数
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
         * @details 调用 socket_.async_write_some 实现异步写入。
         * 返回实际写入的字节数，错误通过 ec 返回。
         * 如果操作成功，ec 为默认值；否则包含错误信息。
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回写入的字节数
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
         * @details 关闭底层 TCP socket。关闭后所有未完成的异步操作
         * 将被取消，传输层对象不再可用。
         */
        void close() override
        {
            boost::system::error_code ec;
            socket_.close(ec);
        }

        /**
         * @brief 取消所有未完成的异步操作
         * @details 取消当前所有挂起的异步读写操作。
         * 被取消的操作将返回 operation_canceled 错误。
         */
        void cancel() override
        {
            boost::system::error_code ec;
            socket_.cancel(ec);
        }

        /**
         * @brief 获取底层 socket 引用
         * @details 返回底层 TCP socket 的引用，用于直接操作 socket。
         * 可用于设置 socket 选项如 TCP_NODELAY 等。
         * @return socket_type& socket 引用
         * @note 用于需要直接操作 socket 的场景（如设置 TCP_NODELAY）。
         */
        socket_type &native_socket() noexcept
        {
            return socket_;
        }

        /**
         * @brief 检查传输是否可靠（如 TCP）
         * @details 重写基类虚函数，返回 true 表示这是可靠传输。
         * @return bool 始终返回 true
         */
        [[nodiscard]] bool is_reliable() const noexcept override
        {
            return true;
        }

        /**
         * @brief 获取底层 socket 常量引用
         * @details 返回底层 TCP socket 的常量引用，用于只读访问。
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
     * @details 使用执行器创建 TCP 传输层实例。Socket 在构造时不打开，
     * 需要在后续调用 open 或 accept 后才能使用。
     * @param executor 执行器
     * @return transmission_pointer 创建的 reliable 实例
     */
    inline transmission_pointer make_reliable(net::any_io_executor executor)
    {
        return std::make_unique<reliable>(executor);
    }

    /**
     * @brief 创建 reliable 传输层（从现有 socket）
     * @details 使用已构造的 TCP socket 创建传输层实例。
     * Socket 必须已打开并连接。
     * @param socket TCP socket
     * @return transmission_pointer 创建的 reliable 实例
     */
    inline transmission_pointer make_reliable(net::ip::tcp::socket socket)
    {
        return std::make_unique<reliable>(std::move(socket));
    }

}
