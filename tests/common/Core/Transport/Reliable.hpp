/**
 * @file Reliable.hpp
 * @brief 可靠的流式传输实现（TCP）
 * @details 封装 boost::asio::ip::tcp::socket，提供基于 TCP 的可靠流式传输。
 * 该类继承自 Transmission，是分层流式架构中的具体传输层实现，
 * 支持异步读写、关闭、取消等操作。所有异步操作返回 net::awaitable，
 * 简化异步操作调用。设计特性包括可靠传输，TCP 保证数据有序送达；
 * 流式语义，提供流式读写接口，支持部分读写；原生访问，
 * 提供 NativeSocket 方法直接访问底层 socket。
 * @note 该类是传输层的核心实现，所有基于 TCP 的协议都应使用此类。
 * @warning 关闭后传输层对象不再可用，不应再调用其任何方法。
 */
#pragma once

#include <common/Core/Diagnose/Log.hpp>
#include <common/Core/Fault/Handling.hpp>
#include <common/Core/Transmission.hpp>

#include <boost/asio.hpp>
#include <boost/asio/any_completion_handler.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <array>
#include <chrono>
#include <cassert>
#include <memory>
#include <optional>
#include <utility>

namespace Preview::Transport
{

    namespace net = boost::asio;

    /**
     * @class Reliable
     * @brief 可靠的流式传输实现（TCP）
     * @details 封装 TCP socket，实现 core::Transmission 接口。
     * 该类支持异步读写、关闭、取消等操作，适用于所有基于 TCP 的协议。
     * 核心职责包括传输抽象，继承 Transmission 接口实现 TCP 传输层；
     * 协程设计，所有异步操作返回 net::awaitable 简化调用；
     * 错误码映射，自动映射 Boost.System 错误码到项目错误码；
     * 智能指针支持，通过 std::enable_shared_from_this 管理生命周期。
     * 设计特性包括可靠传输，TCP 保证数据有序送达不丢失不重复；
     * 流式语义，提供流式读写接口支持部分读写；原生访问，
     * 提供 NativeSocket 方法直接访问底层 socket；
     * 工厂函数，提供 make_reliable 工厂函数简化创建。
     * @note 该类是传输层的核心实现，所有基于 TCP 的协议都应使用此类。
     *       同步可靠封装：无连接池语义，Close() 直接关闭底层 socket。
     * @warning 关闭后传输层对象不再可用，不应再调用其任何方法。
     * @throws std::bad_alloc 如果内存分配失败
     */
    class Reliable final : public Transmission, public std::enable_shared_from_this<Reliable>
    {
    public:
        using SocketType = net::ip::tcp::socket;

        /**
         * @brief 构造函数
         * @details 使用执行器初始化 TCP socket。Socket 在构造时
         * 不打开，需要在后续调用 Open 或 Accept 后才能使用。
         * @param Executor 执行器，用于初始化 socket
         */
        explicit Reliable(net::any_io_executor Executor) : socket_(Executor)
        {
        }

        /**
         * @brief 构造函数
         * @details 使用已构造的 TCP socket 初始化传输层。
         * Socket 必须已打开并连接。
         * @param socket 已构造的 TCP socket
         */
        explicit Reliable(SocketType socket) : socket_(std::move(socket))
        {
        }

        /**
         * @brief 连接远端（带超时）
         * @param ep 端点
         * @param timeout 连接超时（0 = 禁用）
         * @return 错误码（timeout = 连接超时）
         */
        auto Connect(const net::ip::tcp::endpoint &ep,
                     std::chrono::milliseconds timeout = std::chrono::milliseconds{5000})
            -> net::awaitable<boost::system::error_code>
        {
            using namespace boost::asio::experimental::awaitable_operators;

            if (timeout.count() > 0)
            {
                net::steady_timer timer(socket_->get_executor());
                timer.expires_after(timeout);
                auto Result = co_await (socket_->async_connect(ep, net::use_awaitable) ||
                                        timer.async_wait(net::use_awaitable));
                if (Result.index() == 1)
                {
                    boost::system::error_code ec;
                    socket_->close(ec);
                    co_return boost::system::errc::make_error_code(boost::system::errc::timed_out);
                }
            }
            else
            {
                co_await socket_->async_connect(ep, net::use_awaitable);
            }
            co_return boost::system::error_code{};
        }

        /**
         * @brief 获取传输层类型
         * @return Type::Tcp 可靠传输始终为 TCP
         */
        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Tcp;
        }

        /**
         * @brief 获取关联的执行器
         * @details 返回底层 socket 关联的执行器，用于调度异步操作。
         * @return ExecutorType 执行器
         */
        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return const_cast<SocketType &>(NativeSocket()).get_executor();
        }

        /**
         * @brief 获取内层传输
         * @return nullptr Reliable 是叶子节点，没有内层
         */
        [[nodiscard]] auto NextLayer() noexcept -> Transmission * override
        {
            return nullptr;
        }

        /**
         * @brief 获取内层传输（const 版本）
         * @return nullptr Reliable 是叶子节点，没有内层
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission * override
        {
            return nullptr;
        }

        /**
         * @brief 异步读取数据
         * @details 调用底层 socket 的 AsyncReadSome 实现异步读取。
         * 返回实际读取的字节数，错误通过 ec 返回。
         * 如果操作成功，ec 为默认值；否则包含错误信息。
         * @param Buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回读取的字节数
         */
        [[nodiscard]] auto AsyncReadSome(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            boost::system::error_code SysEc;
            auto token = net::redirect_error(net::use_awaitable, SysEc);
            const auto n =
                co_await NativeSocket().async_read_some(net::buffer(Buffer.data(), Buffer.size()), token);
            ec = ::Preview::Fault::make_error_code(::Preview::Fault::ToCode(SysEc));
            co_return n;
        }

        /**
         * @brief Completion-handler 风格异步读取（零协程路径）
         * @details 直接委托给底层 TCP socket 的 AsyncReadSome，
         * 消除所有中间协程帧和 Executor 队列投递开销。
         * @param Buffer 目标缓冲区
         * @param handler 完成处理器
         */
        void AsyncReadSome(
            std::span<std::byte> Buffer,
            net::any_completion_handler<void(boost::system::error_code, std::size_t)> handler) override
        {
            NativeSocket().async_read_some(net::buffer(Buffer.data(), Buffer.size()), std::move(handler));
        }

        /**
         * @brief Completion-handler 风格异步写入（零协程路径）
         * @details 直接委托给底层 TCP socket 的 AsyncWriteSome，
         * 消除所有中间协程帧和 Executor 队列投递开销。
         * @param Buffer 源数据缓冲区
         * @param handler 完成处理器
         */
        void AsyncWriteSome(
            std::span<const std::byte> Buffer,
            net::any_completion_handler<void(boost::system::error_code, std::size_t)> handler) override
        {
            NativeSocket().async_write_some(net::buffer(Buffer.data(), Buffer.size()), std::move(handler));
        }

        /**
         * @brief 异步写入数据
         * @details 调用底层 socket 的 AsyncWriteSome 实现异步写入。
         * 返回实际写入的字节数，错误通过 ec 返回。
         * 如果操作成功，ec 为默认值；否则包含错误信息。
         * @param Buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回写入的字节数
         */
        [[nodiscard]] auto AsyncWriteSome(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            boost::system::error_code SysEc;
            auto token = net::redirect_error(net::use_awaitable, SysEc);
            const auto n =
                co_await NativeSocket().async_write_some(net::buffer(Buffer.data(), Buffer.size()), token);
            ec = ::Preview::Fault::make_error_code(::Preview::Fault::ToCode(SysEc));
            co_return n;
        }

        /**
         * @brief 关闭传输层
         * @details 关闭底层 TCP socket。关闭后所有未完成的异步操作
         * 将被取消，传输层对象不再可用。本类不涉及连接池：
         * Close() 直接关闭 socket，与连接复用无关。
         */
        void Close() override
        {
            if (socket_)
            {
                boost::system::error_code ec;
                socket_->close(ec);
            }
        }

        /**
         * @brief 检查底层 TCP socket 是否打开
         * @return 打开返回 true
         */
        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return socket_ && socket_->is_open();
        }

        /**
         * @brief 半关写方向（向对端发送 EOF）
         * @details 关闭 TCP socket 的写半端，通知对端不再有数据发送。
         * 读取方向仍可继续接收数据，直到对端也关闭或 EOF。
         * @note 非 virtual，仅 Reliable 自身持有此能力
         */
        void ShutdownWrite()
        {
            if (socket_)
            {
                boost::system::error_code ec;
                NativeSocket().shutdown(SocketType::shutdown_send, ec);
            }
        }

        /**
         * @brief 半关写方向（Transmission 接口契约）
         * @details 叶子节点必须实现：沿装饰器链的 Shutdown() 最终落到此处，
         * 向对端发送 FIN（EOF）。本端仍可读，对端读返回 0（EOF）。
         */
        void Shutdown() override
        {
            ShutdownWrite();
        }

        /**
         * @brief 取消所有未完成的异步操作
         * @details 取消当前所有挂起的异步读写操作。
         * 被取消的操作将返回 operation_canceled 错误。
         */
        void Cancel() override
        {
            boost::system::error_code ec;
            NativeSocket().cancel(ec);
        }

        /**
         * @brief 获取底层 socket 引用
         * @details 返回底层 TCP socket 的引用，用于直接操作 socket。
         * 可用于设置 socket 选项如 TCP_NODELAY 等。
         * @return SocketType& socket 引用
         * @note 用于需要直接操作 socket 的场景（如设置 TCP_NODELAY）。
         */
        [[nodiscard]] auto NativeSocket() noexcept -> SocketType &
        {
            assert(socket_.has_value());
            return *socket_;
        }

        /**
         * @brief 获取底层 socket 常量引用
         * @details 返回底层 TCP socket 的常量引用，用于只读访问。
         * @return const SocketType& socket 常量引用
         */
        [[nodiscard]] auto NativeSocket() const noexcept -> const SocketType &
        {
            assert(socket_.has_value());
            return *socket_;
        }

        /**
         * @brief 释放底层 socket 的所有权
         * @details 将 socket 从 Reliable transport 中移出，transport 变为无效状态。
         * 用于 ShadowTLS/Restls 等需要接管 socket 所有权的场景。
         * @return SocketType socket（可能已移动），池连接或无 socket 时返回 std::nullopt
         * @warning 调用后 Reliable transport 不再可用
         */
        [[nodiscard]] auto ReleaseSocket() noexcept -> std::optional<SocketType>
        {
            if (socket_)
            {
                auto s = std::move(*socket_);
                socket_.reset();
                return s;
            }
            // 没有 socket
            return std::nullopt;
        }

    private:
        std::optional<SocketType> socket_; // socket 存储
    };

    /**
     * @brief 创建 Reliable 传输层
     * @details 使用执行器创建 TCP 传输层实例。Socket 在构造时不打开，
     * 需要在后续调用 Open 或 Accept 后才能使用。
     * @param Executor 执行器
     * @return SharedTransmission 创建的 Reliable 实例
     */
    [[nodiscard]] inline SharedTransmission make_reliable(const net::any_io_executor &Executor)
    {
        return std::make_shared<Reliable>(Executor);
    }

    /**
     * @brief 创建 Reliable 传输层（从现有 socket）
     * @details 使用已构造的 TCP socket 创建传输层实例。
     * Socket 必须已打开并连接。
     * @param socket TCP socket
     * @return SharedTransmission 创建的 Reliable 实例
     */
    [[nodiscard]] inline SharedTransmission make_reliable(net::ip::tcp::socket socket)
    {
        return std::make_shared<Reliable>(std::move(socket));
    }

} // namespace Preview::Transport
