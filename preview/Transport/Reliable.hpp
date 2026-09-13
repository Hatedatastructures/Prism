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

#include <preview/Foundation/Utility/Diagnose/Log.hpp>
#include <preview/Foundation/Fault/Handling.hpp>
#include <preview/Transport/Transmission.hpp>

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

    namespace Net = boost::asio;

    /**
     * @class Reliable
     * @brief 可靠的流式传输实现（TCP）
     * @details 封装 TCP socket，实现 core::Transmission 接口。
     * 该类支持异步读写、关闭、取消等操作，适用于所有基于 TCP 的协议。
     * 核心职责包括传输抽象，继承 Transmission 接口实现 TCP 传输层；
     * 协程设计，所有异步操作返回 net::awaitable 简化调用；
     * 错误码映射，自动映射 Boost.System 错误码到项目错误码；
     * 智能指针支持，通过 Transmission 的共享所有权管理生命周期。
     * 设计特性包括可靠传输，TCP 保证数据有序送达不丢失不重复；
     * 流式语义，提供流式读写接口支持部分读写；原生访问，
     * 提供 NativeSocket 方法直接访问底层 socket；
     * 工厂函数，提供 MakeReliable 工厂函数简化创建。
     * @note 该类是传输层的核心实现，所有基于 TCP 的协议都应使用此类。
     *       同步可靠封装：无连接池语义，Close() 直接关闭底层 socket。
     * @warning 关闭后传输层对象不再可用，不应再调用其任何方法。
     * @throws std::bad_alloc 如果内存分配失败
     */
    class Reliable final : public Transmission
    {
    public:
        using SocketType = Net::ip::tcp::socket;

        /**
         * @brief 构造函数
         * @details 使用执行器初始化 TCP socket。Socket 在构造时
         * 不打开，需要在后续调用 Open 或 Accept 后才能使用。
         * @param Executor 执行器，用于初始化 socket
         */
        explicit Reliable(Net::any_io_executor Executor) : Socket_(Executor)
        {
        }

        /**
         * @brief 构造函数
         * @details 使用已构造的 TCP socket 初始化传输层。
         * Socket 必须已打开并连接。
         * @param socket 已构造的 TCP socket
         */
        explicit Reliable(SocketType Socket) : Socket_(std::move(Socket))
        {
        }

        /**
         * @brief 连接远端（带超时）
         * @param ep 端点
         * @param timeout 连接超时（0 = 禁用）
         * @return 错误码（timeout = 连接超时）
         */
        auto Connect(const Net::ip::tcp::endpoint &Endpoint,
                     std::chrono::milliseconds Timeout = std::chrono::milliseconds{5000})
            -> Net::awaitable<boost::system::error_code>
        {
            using boost::asio::experimental::awaitable_operators::operator||;

            if (Timeout.count() > 0)
            {
                Net::steady_timer Timer(Socket_->get_executor());
                Timer.expires_after(Timeout);
                boost::system::error_code ConnectError;
                auto Result = co_await (Socket_->async_connect(
                                            Endpoint, Net::redirect_error(Net::use_awaitable, ConnectError)) ||
                                        Timer.async_wait(Net::use_awaitable));
                if (Result.index() == 1)
                {
                    boost::system::error_code CloseError;
                    Socket_->close(CloseError);
                    co_return boost::system::errc::make_error_code(boost::system::errc::timed_out);
                }
                if (ConnectError)
                {
                    boost::system::error_code CloseError;
                    Socket_->close(CloseError);
                    co_return ConnectError;
                }
            }
            else
            {
                boost::system::error_code ConnectError;
                co_await Socket_->async_connect(
                    Endpoint, Net::redirect_error(Net::use_awaitable, ConnectError));
                if (ConnectError)
                {
                    boost::system::error_code CloseError;
                    Socket_->close(CloseError);
                    co_return ConnectError;
                }
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
         * @details 调用底层 socket 的 async_read_some 实现异步读取。
         * 返回实际读取的字节数，错误通过 ec 返回。
         * 如果操作成功，ec 为默认值；否则包含错误信息。
         * @param Buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回读取的字节数
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t> override
        {
            if (Timeout_.count() > 0)
            {
                using boost::asio::experimental::awaitable_operators::operator||;
                boost::system::error_code SysEc;
                Net::steady_timer Timer(Socket_->get_executor());
                Timer.expires_after(Timeout_);
                auto Result = co_await (NativeSocket().async_read_some(
                                            Net::buffer(Buffer.data(), Buffer.size()),
                                            Net::redirect_error(Net::use_awaitable, SysEc)) ||
                                        Timer.async_wait(Net::use_awaitable));
                if (Result.index() == 1)
                {
                    ErrorCode = std::make_error_code(std::errc::timed_out);
                    co_return 0;
                }
                ErrorCode = ::Preview::Fault::make_error_code(::Preview::Fault::ToCode(SysEc));
                co_return std::get<0>(Result);
            }
            boost::system::error_code SysEc;
            auto Token = Net::redirect_error(Net::use_awaitable, SysEc);
            const auto N =
                co_await NativeSocket().async_read_some(Net::buffer(Buffer.data(), Buffer.size()), Token);
            ErrorCode = ::Preview::Fault::make_error_code(::Preview::Fault::ToCode(SysEc));
            co_return N;
        }

        /**
         * @brief Completion-handler 风格异步读取（零协程路径）
         * @details 直接委托给底层 TCP socket 的 async_read_some，
         * 消除所有中间协程帧和 Executor 队列投递开销。
         * @param Buffer 目标缓冲区
         * @param handler 完成处理器
         */
        void async_read_some(
            std::span<std::byte> Buffer,
            Net::any_completion_handler<void(boost::system::error_code, std::size_t)> Handler) override
        {
            if (Timeout_.count() <= 0)
            {
                NativeSocket().async_read_some(Net::buffer(Buffer.data(), Buffer.size()), std::move(Handler));
                return;
            }

            // 超时竞速：定时器先到则取消挂起的 socket 读，并等待该读操作真正
            // 完成后再以 timed_out 调用用户 handler，保证缓冲区生命周期不越过
            // socket 操作；socket 读先完成时取消定时器并原样返回结果。
            struct RaceState
            {
                RaceState(Net::any_io_executor Ex,
                          Net::any_completion_handler<void(boost::system::error_code, std::size_t)> Completion)
                    : Handler(std::move(Completion)), Timer(std::move(Ex))
                {
                }

                Net::any_completion_handler<void(boost::system::error_code, std::size_t)> Handler;
                Net::steady_timer Timer;
                bool TimedOut{false};
                bool Completed{false};
            };

            auto *Socket = &NativeSocket();
            auto State = std::make_shared<RaceState>(Socket->get_executor(), std::move(Handler));
            State->Timer.expires_after(Timeout_);
            auto ReadCompletion =
                [State](const boost::system::error_code Ec, const std::size_t N)
                {
                    if (State->TimedOut)
                    {
                        State->Timer.cancel();
                        std::move(State->Handler)(Net::error::timed_out, 0);
                        return;
                    }
                    State->Completed = true;
                    State->Timer.cancel();
                    std::move(State->Handler)(Ec, N);
                };
            Socket->async_read_some(Net::buffer(Buffer.data(), Buffer.size()), std::move(ReadCompletion));
            auto TimeoutCompletion =
                [State, Socket](const boost::system::error_code Ec)
                {
                    if (Ec || State->Completed)
                    {
                        return;
                    }
                    State->TimedOut = true;
                    boost::system::error_code Ignored;
                    Socket->cancel(Ignored);
                };
            State->Timer.async_wait(std::move(TimeoutCompletion));
        }

        /**
         * @brief Completion-handler 风格异步写入（零协程路径）
         * @details 直接委托给底层 TCP socket 的 async_write_some，
         * 消除所有中间协程帧和 Executor 队列投递开销。
         * @param Buffer 源数据缓冲区
         * @param handler 完成处理器
         */
        void async_write_some(
            std::span<const std::byte> Buffer,
            Net::any_completion_handler<void(boost::system::error_code, std::size_t)> Handler) override
        {
            NativeSocket().async_write_some(Net::buffer(Buffer.data(), Buffer.size()), std::move(Handler));
        }

        /**
         * @brief 异步写入数据
         * @details 调用底层 socket 的 async_write_some 实现异步写入。
         * 返回实际写入的字节数，错误通过 ec 返回。
         * 如果操作成功，ec 为默认值；否则包含错误信息。
         * @param Buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回写入的字节数
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer,
                                            std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t> override
        {
            boost::system::error_code SysEc;
            auto Token = Net::redirect_error(Net::use_awaitable, SysEc);
            const auto N =
                co_await NativeSocket().async_write_some(Net::buffer(Buffer.data(), Buffer.size()), Token);
            ErrorCode = ::Preview::Fault::make_error_code(::Preview::Fault::ToCode(SysEc));
            co_return N;
        }

        /**
         * @brief 关闭传输层
         * @details 关闭底层 TCP socket。关闭后所有未完成的异步操作
         * 将被取消，传输层对象不再可用。本类不涉及连接池：
         * Close() 直接关闭 socket，与连接复用无关。
         */
        void Close() override
        {
            if (Socket_)
            {
                boost::system::error_code CloseError;
                Socket_->close(CloseError);
            }
        }

        /**
         * @brief 检查底层 TCP socket 是否打开
         * @return 打开返回 true
         */
        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return Socket_ && Socket_->is_open();
        }

        /**
         * @brief 半关写方向（向对端发送 EOF）
         * @details 关闭 TCP socket 的写半端，通知对端不再有数据发送。
         * 读取方向仍可继续接收数据，直到对端也关闭或 EOF。
         * @note 非 virtual，仅 Reliable 自身持有此能力
         */
        void ShutdownWrite()
        {
            if (Socket_)
            {
                boost::system::error_code ShutdownError;
                NativeSocket().shutdown(SocketType::shutdown_send, ShutdownError);
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
         * @brief 设置读超时（0 = 禁用）
         */
        void SetTimeout(std::chrono::milliseconds ms) override
        {
            Timeout_ = ms;
        }

        /**
         * @brief 取消所有未完成的异步操作
         * @details 取消当前所有挂起的异步读写操作。
         * 被取消的操作将返回 operation_canceled 错误。
         */
        void Cancel() override
        {
            boost::system::error_code CancelError;
            NativeSocket().cancel(CancelError);
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
            assert(Socket_.has_value());
            return *Socket_;
        }

        /**
         * @brief 获取底层 socket 常量引用
         * @details 返回底层 TCP socket 的常量引用，用于只读访问。
         * @return const SocketType& socket 常量引用
         */
        [[nodiscard]] auto NativeSocket() const noexcept -> const SocketType &
        {
            assert(Socket_.has_value());
            return *Socket_;
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
            if (Socket_)
            {
                auto S = std::move(*Socket_);
                Socket_.reset();
                return S;
            }
            // 没有 socket
            return std::nullopt;
        }

    private:
        std::optional<SocketType> Socket_; // socket 存储
        std::chrono::milliseconds Timeout_{0}; // 读超时（0 = 禁用）
    };

    /**
     * @brief 创建 Reliable 传输层
     * @details 使用执行器创建 TCP 传输层实例。Socket 在构造时不打开，
     * 需要在后续调用 Open 或 Accept 后才能使用。
     * @param Executor 执行器
     * @return SharedTransmission 创建的 Reliable 实例
     */
    [[nodiscard]] inline SharedTransmission MakeReliable(const Net::any_io_executor &Executor)
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
    [[nodiscard]] inline SharedTransmission MakeReliable(Net::ip::tcp::socket Socket)
    {
        return std::make_shared<Reliable>(std::move(Socket));
    }

} // namespace Preview::Transport
