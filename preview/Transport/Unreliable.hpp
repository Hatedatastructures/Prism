/**
 * @file Unreliable.hpp
 * @brief 不可靠的数据报传输实现（UDP）
 * @details 封装 boost::asio::ip::udp::socket，提供基于 UDP 的数据报传输。
 * 该类继承自 Transmission，模拟流式语义，内部记录远程端点以实现连接式操作。
 * 设计特性包括数据报语义，UDP 不保证数据送达、顺序或去重；
 * 连接模拟，通过记录远程端点实现类似 TCP 的连接式操作；
 * 来源过滤，接收时自动过滤非远程端点的数据报。AllowAnyPeer 模式下，
 * 收发端点必须通过显式的 AsyncReceiveFrom/AsyncSendTo 传递，避免多个
 * 对端共享一个“最近发送者”状态。
 * @note UDP 是不可靠传输，不保证数据送达、顺序或去重。
 * @warning 如果未设置远程端点，写入操作将返回错误。
 */
#pragma once

#include <preview/Foundation/Utility/Diagnose/Log.hpp>
#include <preview/Foundation/Fault/Handling.hpp>
#include <preview/Transport/Transmission.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <memory>
#include <optional>

namespace Preview::Transport
{

    namespace net = boost::asio;

    /**
     * @class Unreliable
     * @brief 不可靠的数据报传输实现（UDP）
     * @details 封装 UDP socket，实现 core::Transmission 接口。
     * 由于 UDP 是无连接的，该类内部维护一个可选远程端点（remote Endpoint），
     * 连接式发送操作都指向该端点，接收操作则验证来源是否匹配该端点
     *（不匹配则丢弃）。任意来源模式不会把接收者写回这个共享端点。
     * 设计特性包括数据报语义，UDP 不保证数据送达、顺序或去重；
     * 连接模拟，通过记录远程端点实现类似 TCP 的连接式操作；
     * 来源过滤，接收时自动过滤非远程端点的数据报。
     * @note UDP 是不可靠传输，不保证数据送达、顺序或去重。
     * @warning 如果未设置远程端点，写入操作将返回错误。
     */
    class Unreliable final : public Transmission, public std::enable_shared_from_this<Unreliable>
    {
    public:
        using SocketType = net::ip::udp::socket;
        using EndpointType = net::ip::udp::endpoint;

        /**
         * @brief 构造函数
         * @details 使用执行器初始化 UDP socket。Socket 在构造时不打开，
         * 需要在后续调用 Open 或 Bind 后才能使用。远程端点可选，
         * 未设置时首次接收的数据报来源将自动设为远程端点。
         * @param Executor 执行器，用于初始化 socket
         * @param RemoteEndpoint 远程端点（可选，可在后续设置）
         */
        explicit Unreliable(net::any_io_executor Executor,
                            std::optional<EndpointType> RemoteEndpoint = std::nullopt)
            : Socket_(Executor), RemoteEndpoint_(std::move(RemoteEndpoint)),
              FilterRemote_(RemoteEndpoint_.has_value()),
              CaptureRemote_(!RemoteEndpoint_.has_value())
        {
        }

        /**
         * @brief 构造函数
         * @details 使用已构造的 UDP socket 初始化传输层。
         * Socket 必须已打开。远程端点可选。
         * @param socket 已构造的 UDP socket
         * @param RemoteEndpoint 远程端点（可选）
         */
        explicit Unreliable(SocketType socket, std::optional<EndpointType> RemoteEndpoint = std::nullopt)
            : Socket_(std::move(socket)), RemoteEndpoint_(std::move(RemoteEndpoint)),
              FilterRemote_(RemoteEndpoint_.has_value()),
              CaptureRemote_(!RemoteEndpoint_.has_value())
        {
        }

        /**
         * @brief 连接远端（host:port 解析 + 设置发送目标）
         * @param remote 远端地址（"host:port"）
         * @return 解析成功返回 true
         */
        auto Connect(const std::string &remote) -> bool
        {
            const auto Colon = remote.rfind(':');
            if (Colon == std::string::npos)
            {
                return false;
            }
            boost::system::error_code ec;
            const auto Host = remote.substr(0, Colon);
            const auto Port = static_cast<unsigned short>(std::strtoul(remote.c_str() + Colon + 1, nullptr, 10));
            const auto Ep = net::ip::udp::endpoint(net::ip::make_address(Host, ec), Port);
            if (ec)
            {
                return false;
            }
            if (!Socket_.is_open())
            {
                Socket_.open(Ep.protocol(), ec);
                if (ec)
                {
                    return false;
                }
            }
            RemoteEndpoint_ = Ep;
            FilterRemote_ = true;
            CaptureRemote_ = false;
            return true;
        }

        /**
         * @brief 绑定本地端口（IPv4）
         * @param port 端口（0 = 系统分配）
         * @return 绑定成功返回 true
         */
        auto Bind(const unsigned short Port) -> bool
        {
            boost::system::error_code ec;
            if (!Socket_.is_open())
            {
                Socket_.open(net::ip::udp::v4(), ec);
                if (ec)
                {
                    return false;
                }
            }
            Socket_.bind(net::ip::udp::endpoint(net::ip::udp::v4(), Port), ec);
            if (!ec)
            {
                RemoteEndpoint_.reset();
                FilterRemote_ = false;
                CaptureRemote_ = true;
            }
            return !ec;
        }

        /**
         * @brief 获取本地绑定端点（Bind 成功后有效）
         * @return 本地 UDP 端点（未绑定时返回空端点）
         * @note 支持端口 0 由系统分配后回读实际端口。
         */
        [[nodiscard]] auto LocalEndpoint() const -> EndpointType
        {
            boost::system::error_code ec;
            const auto Ep = Socket_.local_endpoint(ec);
            return ec ? EndpointType{} : Ep;
        }

        /**
         * @brief 获取传输层类型
         * @return Type::Udp 不可靠传输始终为 UDP
         */
        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Udp;
        }

        /**
         * @brief 获取内层传输
         * @return nullptr Unreliable 是叶子节点，没有内层
         */
        [[nodiscard]] auto NextLayer() noexcept -> Transmission * override
        {
            return nullptr;
        }

        /**
         * @brief 获取内层传输（const 版本）
         * @return nullptr Unreliable 是叶子节点，没有内层
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission * override
        {
            return nullptr;
        }

        /**
         * @brief 获取关联的执行器
         * @details 返回底层 socket 关联的执行器，用于调度异步操作。
         * @return ExecutorType 执行器
         */
        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return const_cast<SocketType &>(Socket_).get_executor();
        }

        /**
         * @brief 设置远程端点
         * @details 设置发送操作的目标端点。设置后所有发送操作都指向该端点，
         * 接收操作验证来源是否匹配该端点，不匹配则丢弃。
         * @param Endpoint 远程端点
         */
        void SetRemote(const EndpointType &Endpoint)
        {
            RemoteEndpoint_ = Endpoint;
            FilterRemote_ = true;
            CaptureRemote_ = false;
        }

        /**
         * @brief 允许接收任意来源的数据报
         * @details 服务端监听时允许来自任意来源的数据报。来源端点通过
         *          AsyncReceiveFrom 返回，响应必须调用 AsyncSendTo 指定目标。
         *          不会更新连接式写入使用的共享远端端点。
         */
        void AllowAnyPeer() noexcept
        {
            RemoteEndpoint_.reset();
            FilterRemote_ = false;
            CaptureRemote_ = false;
        }

        /**
         * @brief 获取远程端点
         * @details 返回当前设置的远程端点。如果未设置则返回空。
         * @return std::optional<EndpointType> 远程端点（如果已设置）
         */
        [[nodiscard]] auto RemoteEndpoint() const noexcept -> std::optional<EndpointType>
        {
            return RemoteEndpoint_;
        }

        /**
         * @brief 异步读取数据
         * @details 调用底层 socket 的 AsyncReceiveFrom 实现异步读取。
         * 接收时自动过滤非远程端点的数据报，不匹配则丢弃并继续等待。
         * AllowAnyPeer 模式下来源端点不会写回连接式发送目标。
         * @param Buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回读取的字节数
         */
        [[nodiscard]] auto AsyncReceiveFrom(std::span<std::byte> Buffer, EndpointType &SenderEndpoint,
                                            std::error_code &ec) -> net::awaitable<std::size_t>
        {
            boost::system::error_code SysEc;
            auto Token = net::redirect_error(net::use_awaitable, SysEc);
            while (true)
            {
                SysEc.clear();
                std::size_t N = co_await Socket_.async_receive_from(net::buffer(Buffer.data(), Buffer.size()),
                                                                    SenderEndpoint, Token);
                if (SysEc)
                {
                    ec = ::Preview::Fault::make_error_code(::Preview::Fault::ToCode(SysEc));
                    co_return 0;
                }
                if (!FilterRemote_ || (RemoteEndpoint_ && SenderEndpoint == *RemoteEndpoint_))
                {
                    if (!FilterRemote_ && CaptureRemote_)
                    {
                        RemoteEndpoint_ = SenderEndpoint;
                        FilterRemote_ = true;
                        CaptureRemote_ = false;
                    }
                    ec = ::Preview::Fault::make_error_code(::Preview::Fault::Code::Success);
                    co_return N;
                }
            }
        }

        /**
         * @brief 从指定端点异步发送一个数据报
         * @param Buffer 待发送数据
         * @param Endpoint 目标端点
         * @param ec 错误码输出参数
         * @return 实际发送的字节数
         * @details 该接口不修改连接式发送使用的 RemoteEndpoint，适用于
         *          AllowAnyPeer 模式下按接收来源逐包响应。
         */
        [[nodiscard]] auto AsyncSendTo(std::span<const std::byte> Buffer, const EndpointType &Endpoint,
                                       std::error_code &ec) -> net::awaitable<std::size_t>
        {
            boost::system::error_code SysEc;
            const auto N = co_await Socket_.async_send_to(
                net::buffer(Buffer.data(), Buffer.size()), Endpoint,
                net::redirect_error(net::use_awaitable, SysEc));
            ec = ::Preview::Fault::make_error_code(::Preview::Fault::ToCode(SysEc));
            co_return N;
        }

        /**
         * @brief 异步读取数据
         * @details 连接式模式按 RemoteEndpoint 过滤来源；AllowAnyPeer 模式
         *          不会把本次来源写入共享 RemoteEndpoint。
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await AsyncReceiveFrom(Buffer, SenderEndpoint_, ec);
        }

        /**
         * @brief 异步写入数据
         * @details 调用底层 socket 的 AsyncSendTo 实现异步写入。
         * 如果未设置远程端点则返回 io_error 错误。
         * @param Buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回写入的字节数
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (!RemoteEndpoint_)
            {
                ec = ::Preview::Fault::make_error_code(::Preview::Fault::Code::IoError);
                co_return 0;
            }
            co_return co_await AsyncSendTo(Buffer, *RemoteEndpoint_, ec);
        }

        /**
         * @brief 关闭传输层
         * @details 关闭底层 UDP socket。关闭后所有未完成的异步操作
         * 将被取消，传输层对象不再可用。
         */
        void Close() override
        {
            boost::system::error_code ec;
            Socket_.close(ec);
        }

        /**
         * @brief 取消所有未完成的异步操作
         * @details 取消当前所有挂起的异步读写操作。
         * 被取消的操作将返回 operation_canceled 错误。
         */
        void Cancel() override
        {
            boost::system::error_code ec;
            Socket_.cancel(ec);
        }

        /**
         * @brief 半关（UDP 无连接语义，空操作）
         */
        void Shutdown() override
        {
        }

        /**
         * @brief 设置读超时（UDP 叶子由上层处理，空操作）
         * @param ms 超时毫秒数（0 = 禁用）
         */
        void SetTimeout(std::chrono::milliseconds /*ms*/) override
        {
        }

        /**
         * @brief 检查底层 socket 是否打开
         * @return 打开返回 true
         */
        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return Socket_.is_open();
        }

        /**
         * @brief 获取底层 socket 引用
         * @details 返回底层 UDP socket 的引用，用于直接操作 socket。
         * @return SocketType& socket 引用
         */
        [[nodiscard]] auto NativeSocket() noexcept -> SocketType &
        {
            return Socket_;
        }

        /**
         * @brief 获取底层 socket 常量引用
         * @details 返回底层 UDP socket 的常量引用，用于只读访问。
         * @return const SocketType& socket 常量引用
         */
        [[nodiscard]] auto NativeSocket() const noexcept -> const SocketType &
        {
            return Socket_;
        }

    private:
        SocketType Socket_;                           // UDP socket
        std::optional<EndpointType> RemoteEndpoint_; // 远程端点，发送目标和接收过滤依据
        bool FilterRemote_{false};                   // 是否只接收指定远端
        bool CaptureRemote_{true};                  // 首次兼容式读取是否绑定来源
        EndpointType SenderEndpoint_;                // 兼容 async_read_some 的来源端点
    };

    /**
     * @brief 创建 Unreliable 传输层
     * @details 使用执行器创建 UDP 传输层实例。Socket 在构造时不打开，
     * 需要在后续调用 Open 或 Bind 后才能使用。
     * @param Executor 执行器
     * @param RemoteEndpoint 远程端点（可选）
     * @return SharedTransmission 创建的 Unreliable 实例
     */
    [[nodiscard]] inline auto
    MakeUnreliable(net::any_io_executor Executor,
                    std::optional<net::ip::udp::endpoint> RemoteEndpoint = std::nullopt)
        -> SharedTransmission
    {
        return std::make_shared<Unreliable>(Executor, std::move(RemoteEndpoint));
    }

    /**
     * @brief 创建 Unreliable 传输层（从现有 socket）
     * @details 使用已构造的 UDP socket 创建传输层实例。
     * Socket 必须已打开。远程端点可选。
     * @param socket UDP socket
     * @param RemoteEndpoint 远程端点（可选）
     * @return SharedTransmission 创建的 Unreliable 实例
     */
    [[nodiscard]] inline auto
    MakeUnreliable(net::ip::udp::socket socket,
                    std::optional<net::ip::udp::endpoint> RemoteEndpoint = std::nullopt)
        -> SharedTransmission
    {
        return std::make_shared<Unreliable>(std::move(socket), std::move(RemoteEndpoint));
    }
} // namespace Preview::Transport
