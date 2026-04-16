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
#include <prism/channel/transport/transmission.hpp>
#include <prism/channel/connection/pool.hpp>
#include <prism/fault/handling.hpp>
#include <array>
#include <memory>
#include <optional>
#include <utility>

namespace psm::channel::transport
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
     * 连接池复用支持，通过 unique_sock 构造函数接收来自连接池的连接，
     * 在 close() 时自动归还到连接池而非直接关闭。
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
         * @brief 构造函数（连接池复用）
         * @details 从连接池获取的连接创建传输层。该构造函数接收 pooled_connection，
         * 析构或 close() 时 socket 将被归还到连接池而非直接关闭，实现连接复用。
         * @param pooled 来自连接池的连接
         * @note pooled_ 持有 socket 的所有权，native_socket() 返回 *pooled_
         */
        explicit reliable(psm::channel::pooled_connection pooled)
            : pooled_(std::move(pooled))
        {
        }

        /**
         * @brief 获取关联的执行器
         * @details 返回底层 socket 关联的执行器，用于调度异步操作。
         * @return executor_type 执行器
         */
        executor_type executor() const override
        {
            return const_cast<socket_type &>(native_socket()).get_executor();
        }

        /**
         * @brief 异步读取数据
         * @details 调用底层 socket 的 async_read_some 实现异步读取。
         * 返回实际读取的字节数，错误通过 ec 返回。
         * 如果操作成功，ec 为默认值；否则包含错误信息。
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回读取的字节数
         */
        auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            boost::system::error_code sys_ec;
            auto token = net::redirect_error(net::use_awaitable, sys_ec);
            const auto n = co_await native_socket().async_read_some(
                net::buffer(buffer.data(), buffer.size()), token);
            ec = psm::fault::make_error_code(psm::fault::to_code(sys_ec));
            co_return n;
        }

        /**
         * @brief 异步写入数据
         * @details 调用底层 socket 的 async_write_some 实现异步写入。
         * 返回实际写入的字节数，错误通过 ec 返回。
         * 如果操作成功，ec 为默认值；否则包含错误信息。
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回写入的字节数
         */
        auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            boost::system::error_code sys_ec;
            auto token = net::redirect_error(net::use_awaitable, sys_ec);
            const auto n = co_await native_socket().async_write_some(
                net::buffer(buffer.data(), buffer.size()), token);
            ec = psm::fault::make_error_code(psm::fault::to_code(sys_ec));
            co_return n;
        }

        /**
         * @brief Scatter-gather 写入（TCP 原生优化）
         * @details 将多个缓冲区通过一次 async_write 写入，底层 async_write_some 携带
         * 完整 ConstBufferSequence 可映射为单次 WSASend/writev 系统调用，
         * 避免帧头与载荷分两次写入导致的额外系统调用和 TLS 记录开销。
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
                total = co_await net::async_write(native_socket(), bufs, token);
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
         * @details 关闭底层 TCP socket。关闭后所有未完成的异步操作
         * 将被取消，传输层对象不再可用。如果连接来自连接池（pooled_ 非空），
         * 则将连接归还到连接池而非直接关闭，实现连接复用。
         * @note 池连接归还时，socket 保持打开状态，由连接池管理生命周期
         */
        void close() override
        {
            if (pooled_.valid())
            {
                // 取消挂起的异步操作，但不关闭 socket。
                // 保持 socket 打开状态，让析构函数通过 pooled_.reset() → recycle() 归还连接池。
                // recycle() 会通过 healthy_fast() 检测 socket 健康状态，
                // 不健康的连接会被自动销毁而非复用。
                boost::system::error_code ec;
                if (auto *sock = pooled_.get())
                {
                    sock->cancel(ec);
                }
                return;
            }
            if (socket_)
            {
                boost::system::error_code ec;
                socket_->close(ec);
            }
        }

        /**
         * @brief 取消所有未完成的异步操作
         * @details 取消当前所有挂起的异步读写操作。
         * 被取消的操作将返回 operation_canceled 错误。
         */
        void cancel() override
        {
            boost::system::error_code ec;
            native_socket().cancel(ec);
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
            if (pooled_.valid())
            {
                return *pooled_.get();
            }
            return *socket_;
        }

        /**
         * @brief 关闭写端（半关闭）
         * @details 调用 socket 的 shutdown_send，通知对端不再发送数据。
         */
        void shutdown_write() override
        {
            boost::system::error_code ec;
            native_socket().shutdown(net::ip::tcp::socket::shutdown_send, ec);
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
            if (pooled_.valid())
            {
                return *pooled_.get();
            }
            return *socket_;
        }

    private:
        std::optional<socket_type> socket_;      ///< 非池连接的 socket 存储
        psm::channel::pooled_connection pooled_; ///< 池连接，RAII 包装器
    };

    /**
     * @brief 创建 reliable 传输层
     * @details 使用执行器创建 TCP 传输层实例。Socket 在构造时不打开，
     * 需要在后续调用 open 或 accept 后才能使用。
     * @param executor 执行器
     * @return shared_transmission 创建的 reliable 实例
     */
    inline shared_transmission make_reliable(net::any_io_executor executor)
    {
        return std::make_shared<reliable>(executor);
    }

    /**
     * @brief 创建 reliable 传输层（从现有 socket）
     * @details 使用已构造的 TCP socket 创建传输层实例。
     * Socket 必须已打开并连接。
     * @param socket TCP socket
     * @return shared_transmission 创建的 reliable 实例
     */
    inline shared_transmission make_reliable(net::ip::tcp::socket socket)
    {
        return std::make_shared<reliable>(std::move(socket));
    }

    /**
     * @brief 创建 reliable 传输层（从连接池连接）
     * @details 使用来自连接池的连接创建传输层实例。
     * pooled_connection 是 RAII 包装器，在 close() 时将自动归还到连接池。
     * @param pooled 来自连接池的连接
     * @return shared_transmission 创建的 reliable 实例
     * @note 该重载用于连接池复用场景
     */
    inline shared_transmission make_reliable(psm::channel::pooled_connection pooled)
    {
        return std::make_shared<reliable>(std::move(pooled));
    }
}
