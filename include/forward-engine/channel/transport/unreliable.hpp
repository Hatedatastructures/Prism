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
#include <forward-engine/channel/transport/transmission.hpp>
#include <forward-engine/fault/handling.hpp>
#include <memory>
#include <optional>

namespace ngx::channel::transport
{
    namespace net = boost::asio;

    /**
     * @class unreliable
     * @brief 不可靠的数据报传输实现（UDP）
     * @details 封装 UDP socket，实现 core::transmission 接口。
     * 由于 UDP 是无连接的，该类内部维护一个远程端点（remote endpoint），
     * 所有发送操作都指向该端点，接收操作则验证来源是否匹配该端点
     *（不匹配则丢弃）。
     */
    class unreliable : public transmission, public std::enable_shared_from_this<unreliable>
    {
    public:
        using socket_type = net::ip::udp::socket;
        using endpoint_type = net::ip::udp::endpoint;

        /**
         * @brief 构造函数
         * @param executor 执行器，用于初始化 socket
         * @param remote_endpoint 远程端点（可选，可在后续设置）
         */
        explicit unreliable(net::any_io_executor executor, std::optional<endpoint_type> remote_endpoint = std::nullopt)
            : socket_(executor), remote_endpoint_(std::move(remote_endpoint))
        {
        }

        /**
         * @brief 构造函数
         * @param socket 已构造的 UDP socket
         * @param remote_endpoint 远程端点（可选）
         */
        explicit unreliable(socket_type socket, std::optional<endpoint_type> remote_endpoint = std::nullopt)
            : socket_(std::move(socket)), remote_endpoint_(std::move(remote_endpoint))
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
         * @brief 设置远程端点
         * @param endpoint 远程端点
         */
        void set_remote_endpoint(const endpoint_type &endpoint)
        {
            remote_endpoint_ = endpoint;
        }

        /**
         * @brief 获取远程端点
         * @return std::optional<endpoint_type> 远程端点（如果已设置）
         */
        std::optional<endpoint_type> remote_endpoint() const noexcept
        {
            return remote_endpoint_;
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
            while (true)
            {
                sys_ec.clear();
                std::size_t n = co_await socket_.async_receive_from(
                    net::buffer(buffer.data(), buffer.size()),
                    sender_endpoint_, token);
                if (sys_ec)
                {
                    ec = ngx::fault::make_error_code(ngx::fault::to_code(sys_ec));
                    co_return 0;
                }
                if (!remote_endpoint_)
                {
                    remote_endpoint_ = sender_endpoint_;
                    ec = ngx::fault::make_error_code(ngx::fault::code::success);
                    co_return n;
                }
                else if (sender_endpoint_ == *remote_endpoint_)
                {
                    ec = ngx::fault::make_error_code(ngx::fault::code::success);
                    co_return n;
                }
            }
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
            if (!remote_endpoint_)
            {
                ec = ngx::fault::make_error_code(ngx::fault::code::io_error);
                co_return 0;
            }
            boost::system::error_code sys_ec;
            auto token = net::redirect_error(net::use_awaitable, sys_ec);
            const auto n = co_await socket_.async_send_to(
                net::buffer(buffer.data(), buffer.size()), *remote_endpoint_,token);
            ec = ngx::fault::make_error_code(ngx::fault::to_code(sys_ec));
            co_return n;
        }

        /**
         * @brief 完整写入操作（UDP 特化）
         * @details UDP 数据报一次发送完成，无需循环。直接委托给 async_write_some。
         */
        auto async_write(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await async_write_some(buffer, ec);
        }

        /**
         * @brief 关闭传输层
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
         */
        socket_type &native_socket() noexcept
        {
            return socket_;
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
        std::optional<endpoint_type> remote_endpoint_;
        endpoint_type sender_endpoint_;
    };

    /**
     * @brief 创建 unreliable 传输层
     * @param executor 执行器
     * @param remote_endpoint 远程端点（可选）
     * @return shared_transmission 创建的 unreliable 实例
     */
    inline auto make_unreliable(net::any_io_executor executor, std::optional<net::ip::udp::endpoint> remote_endpoint = std::nullopt)
        -> shared_transmission
    {
        return std::make_shared<unreliable>(executor, std::move(remote_endpoint));
    }

    /**
     * @brief 创建 unreliable 传输层（从现有 socket）
     * @param socket UDP socket
     * @param remote_endpoint 远程端点（可选）
     * @return shared_transmission 创建的 unreliable 实例
     */
    inline auto make_unreliable(net::ip::udp::socket socket, std::optional<net::ip::udp::endpoint> remote_endpoint = std::nullopt)
        -> shared_transmission
    {
        return std::make_shared<unreliable>(std::move(socket), std::move(remote_endpoint));
    }
}
