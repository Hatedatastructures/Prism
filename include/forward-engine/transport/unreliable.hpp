/**
 * @file unreliable.hpp
 * @brief 不可靠的数据报传输实现（UDP）
 * @details 封装 boost::asio::ip::udp::socket，提供基于 UDP 的数据报传输。
 * 该类继承自 transmission，模拟流式语义，内部记录远程端点以实现连接式操作。
 * 设计特性包括数据报语义，UDP 不保证数据送达、顺序或去重；
 * 连接模拟，通过记录远程端点实现类似 TCP 的连接式操作；
 * 来源过滤，接收时自动过滤非远程端点的数据报。
 * @note UDP 是不可靠传输，不保证数据送达、顺序或去重。
 * @warning 如果未设置远程端点，写入操作将返回错误。
 */
#pragma once

#include <boost/asio.hpp>
#include <forward-engine/transport/transmission.hpp>
#include <forward-engine/gist/handling.hpp>
#include <memory>
#include <optional>

namespace ngx::transport
{
    namespace net = boost::asio;

    /**
     * @class unreliable
     * @brief 不可靠的数据报传输实现（UDP）
     * @details 封装 UDP socket，实现 core::transmission 接口。
     * 由于 UDP 是无连接的，该类内部维护一个远程端点（remote endpoint），
     * 所有发送操作都指向该端点，接收操作则验证来源是否匹配该端点
     *（不匹配则丢弃）。核心职责包括传输抽象，
     * 继承 transmission 接口实现 UDP 传输层；连接模拟，
     * 内部维护远程端点实现连接式 UDP 操作；来源验证，
     * 接收数据时验证来源是否匹配远程端点；协程设计，
     * 所有异步操作返回 net::awaitable 简化调用。
     * 设计特性包括数据报语义，UDP 不保证数据送达顺序或去重；
     * 连接模拟，通过记录远程端点实现类似 TCP 的连接式操作；
     * 来源过滤，接收时自动过滤非远程端点的数据报；
     * 工厂函数，提供 make_unreliable 工厂函数简化创建。
     * @note UDP 是不可靠传输，不保证数据送达、顺序或去重。
     * @warning 如果未设置远程端点，写入操作将返回错误。
     * @throws std::bad_alloc 如果内存分配失败
     */
    class unreliable : public transmission, public std::enable_shared_from_this<unreliable>
    {
    public:
        using socket_type = net::ip::udp::socket;
        using endpoint_type = net::ip::udp::endpoint;

        /**
         * @brief 构造函数
         * @details 使用执行器初始化 UDP socket。Socket 在构造时不打开，
         * 需要在后续调用 open 或 bind 后才能使用。
         * 可选的远程端点用于连接式 UDP 操作。
         * @param executor 执行器，用于初始化 socket
         * @param remote_endpoint 远程端点（可选，可在后续设置）
         */
        explicit unreliable(net::any_io_executor executor, std::optional<endpoint_type> remote_endpoint = std::nullopt)
            : socket_(executor), remote_endpoint_(std::move(remote_endpoint))
        {
        }

        /**
         * @brief 构造函数
         * @details 使用已构造的 UDP socket 初始化传输层。
         * Socket 必须已打开。可选的远程端点用于连接式 UDP 操作。
         * @param socket 已构造的 UDP socket
         * @param remote_endpoint 远程端点（可选）
         */
        explicit unreliable(socket_type socket, std::optional<endpoint_type> remote_endpoint = std::nullopt)
            : socket_(std::move(socket)), remote_endpoint_(std::move(remote_endpoint))
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
         * @brief 设置远程端点
         * @details 设置 UDP 传输的远程端点。所有后续的写入操作
         * 将发送到此端点，读取操作将只接受来自此端点的数据。
         * @param endpoint 远程端点
         * @note 必须在调用 async_read_some 或 async_write_some 前设置。
         */
        void set_remote_endpoint(const endpoint_type &endpoint)
        {
            remote_endpoint_ = endpoint;
        }

        /**
         * @brief 获取远程端点
         * @details 返回当前设置的远程端点。
         * @return std::optional<endpoint_type> 远程端点（如果已设置）
         */
        std::optional<endpoint_type> remote_endpoint() const noexcept
        {
            return remote_endpoint_;
        }

        /**
         * @brief 异步读取数据
         * @details 调用 socket_.async_receive_from 接收数据。
         * 如果设置了远程端点，则验证来源是否匹配；如不匹配，
         * 则继续等待下一个数据报。如果未设置远程端点，
         * 则记录第一次接收到的端点作为远程端点。
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回读取的字节数
         */
        auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            boost::system::error_code sys_ec;
            auto token = net::redirect_error(net::use_awaitable, sys_ec);
            while (true)
            {
                sys_ec.clear();
                std::size_t n = co_await socket_.async_receive_from(
                    net::buffer(buffer.data(), buffer.size()),
                    sender_endpoint_,
                    token);
                if (sys_ec)
                {
                    ec = ngx::gist::make_error_code(ngx::gist::to_code(sys_ec));
                    co_return 0;
                }
                if (!remote_endpoint_)
                {
                    // 记录第一次接收到的端点作为远程端点
                    remote_endpoint_ = sender_endpoint_;
                    ec = ngx::gist::make_error_code(ngx::gist::code::success);
                    co_return n;
                }
                else if (sender_endpoint_ == *remote_endpoint_)
                {
                    // 来源匹配
                    ec = ngx::gist::make_error_code(ngx::gist::code::success);
                    co_return n;
                }
                // 来源不匹配，丢弃并继续读取
                // 循环继续
            }
        }

        /**
         * @brief 异步写入数据
         * @details 调用 socket_.async_send_to 发送数据到远程端点。
         * 如果未设置远程端点，则返回错误。
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回写入的字节数
         */
        auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (!remote_endpoint_)
            {
                // 未设置远程端点，无法发送
                ec = ngx::gist::make_error_code(ngx::gist::code::io_error);
                co_return 0;
            }
            boost::system::error_code sys_ec;
            const auto n = co_await socket_.async_send_to(
                net::buffer(buffer.data(), buffer.size()),
                *remote_endpoint_,
                net::redirect_error(net::use_awaitable, sys_ec));
            ec = ngx::gist::make_error_code(ngx::gist::to_code(sys_ec));
            co_return n;
        }

        /**
         * @brief 关闭传输层
         * @details 关闭底层 UDP socket。关闭后所有未完成的异步操作
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
         * @details 返回底层 UDP socket 的引用，用于直接操作 socket。
         * @return socket_type& socket 引用
         */
        socket_type &native_socket() noexcept
        {
            return socket_;
        }

        /**
         * @brief 获取底层 socket 常量引用
         * @details 返回底层 UDP socket 的常量引用，用于只读访问。
         * @return const socket_type& socket 常量引用
         */
        const socket_type &native_socket() const noexcept
        {
            return socket_;
        }

    private:
        socket_type socket_;
        std::optional<endpoint_type> remote_endpoint_;
        endpoint_type sender_endpoint_; // 临时存储接收到的来源端点
    };

    /**
     * @brief 创建 unreliable 传输层
     * @details 使用执行器创建 UDP 传输层实例。Socket 在构造时不打开，
     * 需要在后续调用 open 或 bind 后才能使用。
     * @param executor 执行器
     * @param remote_endpoint 远程端点（可选）
     * @return transmission_pointer 创建的 unreliable 实例
     */
    inline auto make_unreliable(net::any_io_executor executor, std::optional<net::ip::udp::endpoint> remote_endpoint = std::nullopt)
        -> transmission_pointer
    {
        return std::make_unique<unreliable>(executor, std::move(remote_endpoint));
    }

    /**
     * @brief 创建 unreliable 传输层（从现有 socket）
     * @details 使用已构造的 UDP socket 创建传输层实例。
     * Socket 必须已打开。
     * @param socket UDP socket
     * @param remote_endpoint 远程端点（可选）
     * @return transmission_pointer 创建的 unreliable 实例
     */
    inline auto make_unreliable(net::ip::udp::socket socket, std::optional<net::ip::udp::endpoint> remote_endpoint = std::nullopt)
        -> transmission_pointer
    {
        return std::make_unique<unreliable>(std::move(socket), std::move(remote_endpoint));
    }

}
