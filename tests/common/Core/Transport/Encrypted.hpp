/**
 * @file Encrypted.hpp
 * @brief 加密传输层实现
 * @details 将 ssl::Stream 适配为 Transmission 接口，供协议装饰器使用。
 * 该适配器允许 Trojan::Stream 等协议层装饰 TLS 加密流，
 * 实现协议处理与传输层的解耦。
 */

#pragma once

#include <common/Core/Diagnose/Log.hpp>
#include <common/Core/Fault/Code.hpp>
#include <common/Core/Fault/Handling.hpp>
#include <common/Core/Transport/Connector.hpp>
#include <common/Core/Transmission.hpp>

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/ssl.h>

#include <array>
#include <memory>
#include <span>
#include <system_error>

namespace Preview::Transport {


    namespace net = boost::asio;
    namespace ssl = net::ssl;

    /**
     * @class Encrypted
     * @brief 加密传输层实现
     * @details 将 boost::asio::ssl::stream<Connector> 适配为 Transmission 接口，
     * 使协议装饰器（如 Trojan::Stream）能够装饰 TLS 加密流。
     * 该类持有 ssl::Stream 的共享所有权，确保在协议处理期间流对象有效。
     * 核心职责包括传输抽象，继承 Transmission 接口实现 TLS 传输层；
     * 协程设计，所有异步操作返回 net::awaitable 简化调用；
     * 错误码映射，自动映射 Boost.System 错误码到项目错误码。
     * @note 该类用于 TLS 加密场景，所有基于 TLS 的协议都应使用此类。
     * @warning 关闭后传输层对象不再可用，不应再调用其任何方法。
     * @throws std::bad_alloc 如果内存分配失败
     */
    class Encrypted final : public Transmission
    {
    public:
        using ConnectorType = ::Preview::Transport::Connector;
        using StreamType = boost::asio::ssl::stream<ConnectorType>;
        using SharedStream = std::shared_ptr<StreamType>;

        /**
         * @brief 构造加密传输层
         * @details 使用已建立的 TLS 流创建加密传输层。
         * TLS 流必须已完成握手。
         * @param SslStream TLS 流的共享指针
         */
        explicit Encrypted(SharedStream SslStream) : SslStream_(std::move(SslStream))
        {
        }

        /**
         * @brief 获取传输层类型
         * @return Type::Tcp TLS 始终基于 TCP
         */
        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Tcp;
        }

        /**
         * @brief 获取内层传输
         * @return 底层传输（穿透 ssl::Stream → Connector 链）
         */
        [[nodiscard]] auto NextLayer() noexcept -> Transmission * override
        {
            return SslStream_->next_layer().NextLayer();
        }

        /**
         * @brief 获取内层传输（const 版本）
         * @return 底层传输（穿透 ssl::Stream → Connector 链）
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission * override
        {
            return SslStream_->next_layer().NextLayer();
        }

        /**
         * @brief 获取关联的执行器
         * @details 返回底层 TLS 流关联的执行器，用于调度异步操作。
         * @return 底层 TLS 流的执行器
         */
        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return const_cast<StreamType &>(*SslStream_).get_executor();
        }

        /**
         * @brief 异步读取数据
         * @details 调用底层 TLS 流的 AsyncReadSome 实现异步读取。
         * 返回实际读取的字节数，错误通过 ec 返回。
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
                co_await SslStream_->async_read_some(net::buffer(Buffer.data(), Buffer.size()), token);
            ec = ::Preview::Fault::make_error_code(::Preview::Fault::ToCode(SysEc));
            co_return n;
        }

        /**
         * @brief 异步写入数据
         * @details 调用底层 TLS 流的 AsyncWriteSome 实现异步写入。
         * 返回实际写入的字节数，错误通过 ec 返回。
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
                co_await SslStream_->async_write_some(net::buffer(Buffer.data(), Buffer.size()), token);
            ec = ::Preview::Fault::make_error_code(::Preview::Fault::ToCode(SysEc));
            co_return n;
        }

        /**
         * @brief 关闭传输层
         * @details 先发起 SSL_shutdown 优雅关闭 TLS 会话，
         * 然后关闭底层 socket，忽略所有错误。
         */
        void Close() override
        {
            auto *ssl = SslStream_->native_handle();
            if (ssl)
            {
                SSL_set_quiet_shutdown(ssl, 1);
                SSL_shutdown(ssl);
            }
            SslStream_->next_layer().NextLayer()->Close();
        }

        /**
         * @brief 取消所有未完成的异步操作
         * @details 取消底层传输层当前所有挂起的异步读写操作。
         * 被取消的操作将返回 operation_canceled 错误。
         */
        void Cancel() override
        {
            SslStream_->next_layer().NextLayer()->Cancel();
        }

        /**
         * @brief 获取底层 TLS 流引用
         * @details 返回内部 TLS 流的引用，用于直接操作 TLS 层。
         * @return StreamType& TLS 流引用
         */
        [[nodiscard]] auto Stream() noexcept -> StreamType &
        {
            return *SslStream_;
        }

        /**
         * @brief 获取底层 TLS 流常量引用
         * @details 返回内部 TLS 流的常量引用，用于只读访问。
         * @return const StreamType& TLS 流常量引用
         */
        [[nodiscard]] auto Stream() const noexcept -> const StreamType &
        {
            return *SslStream_;
        }

        /**
         * @brief 释放 TLS 流所有权
         * @details 将内部持有的 TLS 流共享指针移动返回，调用后对象不再持有流。
         * @note 与基类 virtual Release()（返回 SharedTransmission）签名冲突，
         * 故命名为 ReleaseStream()。
         * @return SharedStream TLS 流共享指针
         */
        [[nodiscard]] auto ReleaseStream() -> SharedStream
        {
            return std::move(SslStream_);
        }

        /**
         * @brief 执行 TLS 服务端握手（静态工厂）
         * @param inbound 入站传输层（所有权被转移）
         * @param ssl_ctx SSL 上下文
         * @return 协程对象，完成后返回：错误码、TLS 流（成功时）、
         * 失败时从 Connector 恢复的传输层（成功时为 nullptr）
         * @details 将入站传输层包装为 Connector，执行 TLS 服务端握手。
         * 握手失败时从 Connector 释放传输层所有权，避免 transport 丢失。
         * @note 调用方应确保入站传输已包装 Preview（如有预读数据）。
         */
        [[nodiscard]] static auto SslHandshake(SharedTransmission inbound, ssl::context &ssl_ctx)
            -> net::awaitable<std::tuple<Fault::Code, SharedStream, SharedTransmission>>;

    private:
        SharedStream SslStream_; // TLS 流的共享指针，持有流的所有权
    };

    /**
     * @brief 创建加密传输层
     * @details 使用已建立的 TLS 流创建加密传输层实例。
     * TLS 流必须已完成握手。
     * @param SslStream TLS 流的共享指针
     * @return SharedTransmission 传输层指针
     */
    [[nodiscard]] inline SharedTransmission make_encrypted(Encrypted::SharedStream SslStream)
    {
        return std::make_shared<Encrypted>(std::move(SslStream));
    }



    inline auto Encrypted::SslHandshake(SharedTransmission inbound, ssl::context &ssl_ctx)
        -> net::awaitable<std::tuple<Fault::Code, Encrypted::SharedStream, SharedTransmission>>
    {
        if (!inbound)
        {
            Diagnose::Warn("No inbound Transmission for TLS handshake");
            co_return std::make_tuple(Fault::Code::io_error, nullptr, nullptr);
        }

        ConnectorType Connector(std::move(inbound), {});
        auto Stream = std::make_shared<StreamType>(std::move(Connector), ssl_ctx);

        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);

        // TLS 握手超时（30 秒）：防恶意客户端连接后不发 ClientHello 挂起
        using boost::asio::experimental::awaitable_operators::operator||;
        net::steady_timer deadline(Stream->get_executor(), std::chrono::seconds(30));
        auto DoHandshake = [&Stream]() -> net::awaitable<boost::system::error_code>
        {
            boost::system::error_code HEc;
            co_await Stream->async_handshake(boost::asio::ssl::stream_base::server,
                                             net::redirect_error(net::use_awaitable, HEc));
            co_return HEc;
        };
        const auto Result = co_await (DoHandshake() || deadline.async_wait(net::use_awaitable));
        if (Result.index() == 1)
        {
            Diagnose::Warn("TLS handshake timeout");
            auto recovered = Stream->lowest_layer().Release();
            co_return std::make_tuple(Fault::Code::timeout, nullptr, std::move(recovered));
        }
        const auto HEc = std::get<0>(Result);
        if (HEc)
        {
            Diagnose::Warn("TLS handshake Failed: {} ({})", HEc.message(), HEc.value());
            auto recovered = Stream->lowest_layer().Release();
            co_return std::make_tuple(Fault::ToCode(HEc), nullptr, std::move(recovered));
        }

        Diagnose::Debug("TLS handshake Succeeded");
        co_return std::make_tuple(Fault::Code::success, Stream, nullptr);
    }


} // namespace Preview::Transport
