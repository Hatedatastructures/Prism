/**
 * @file Transport.hpp
 * @brief DNS 上游传输层（UDP / TCP / DoT 三传输 + 分层概念）
 * @details 只负责"把一段 DNS 报文字节送到上游、把应答字节完整拿回来"，
 *          不感知 DNS 语义（不解析报文、不校验 Id/RCODE/TC）：
 *          - 分层小概念：TransportLink（收发单元）→ PoolableTransport（可池化）
 *          - UdpTransport：数据报单发单收（不入池，connect 成本 µs 级）
 *          - TcpTransport / TlsTransport：2 字节长度前缀帧（可入池复用）
 *          - 每操作超时：arm 定时器回调 cancel 套接字，无阻塞无轮询；
 *            操作完成后立刻 disarm，避免残留回调误伤下一次操作
 *          - 全部 async（含建连），错误以 error_code 返回，不抛异常
 * @note DoH（HTTP 承载）见 Doh.hpp；连接池见 ConnPool.hpp
 */

#pragma once

#include "Config.hpp"
#include "Format.hpp"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace Preview::Network::Dns
{

    namespace Net = boost::asio;
    namespace Ssl = Net::ssl;

    /// 以 error_code 表达成败的结果类型（传输层不抛异常）
    template <typename T>
    using EcResult = std::expected<T, boost::system::error_code>;

    /**
     * @concept TransportLink
     * @brief 一次 DNS 字节帧的收发单元
     * @details Send 写入一段 DNS 报文字节（帧封装由实现内部完成），
     *          Receive 返回剥离封装后的应答字节，Close 释放底层套接字
     */
    template <typename T>
    concept TransportLink = requires(T LinkObject, std::span<const std::uint8_t> Wire) {
        LinkObject.Send(Wire);
        LinkObject.Receive();
        LinkObject.Close();
        LinkObject.IsOpen();
    };

    /**
     * @concept PoolableTransport
     * @brief 可入池的传输：在收发之上追加建连能力
     * @details Connect 建立底层连接（endpoint 由上层解析缓存提供），
     *          上层据此判定能否复用
     */
    template <typename T>
    concept PoolableTransport =
        TransportLink<T> && requires(T LinkObject, const Net::ip::tcp::endpoint &Endpoint,
                                     const Server &ServerConfig) {
            LinkObject.Connect(Endpoint, ServerConfig);
        };

    namespace Detail
    {
        /// 帧体长度上限（DNS over TCP 单帧 65535 字节上限）
        constexpr std::size_t MaxFrameBytes = 65535;

        /// TCP/DoT 共享的 2 字节大端长度前缀封装
        [[nodiscard]] inline auto MakeTcpFrame(std::span<const std::uint8_t> Wire)
            -> EcResult<std::vector<std::uint8_t>>
        {
            if (Wire.size() > MaxFrameBytes)
            {
                return std::unexpected(
                    boost::system::errc::make_error_code(boost::system::errc::message_size));
            }
            std::vector<std::uint8_t> frame;
            frame.reserve(Wire.size() + 2);
            frame.push_back(static_cast<std::uint8_t>(Wire.size() >> 8));
            frame.push_back(static_cast<std::uint8_t>(Wire.size() & 0xFF));
            frame.insert(frame.end(), Wire.begin(), Wire.end());
            return frame;
        }

    } // namespace Detail

    /**
     * @class UdpTransport
     * @brief 数据报传输（单发单收，不入池）
     */
    class UdpTransport
    {
    public:
        UdpTransport(Net::any_io_executor Executor, const std::chrono::milliseconds Timeout)
            : Ex_(std::move(Executor)), Timer_(Ex_), Timeout_(Timeout)
        {
        }

        /// 建立已连接 UDP 套接字（内核级过滤非对端数据报，防伪造）
        auto Connect(const Net::ip::udp::endpoint &Endpoint, const Server & /*ServerConfig*/)
            -> Net::awaitable<boost::system::error_code>
        {
            boost::system::error_code ErrorCode;
            Sock_.emplace(Ex_, Endpoint.protocol());
            Arm();
            co_await Sock_->async_connect(Endpoint,
                                          Net::redirect_error(Net::use_awaitable, ErrorCode));
            Disarm();
            co_return ErrorCode;
        }

        auto Send(std::span<const std::uint8_t> Wire) -> Net::awaitable<boost::system::error_code>
        {
            boost::system::error_code ErrorCode;
            Arm();
            co_await Sock_->async_send(Net::buffer(Wire),
                                       Net::redirect_error(Net::use_awaitable, ErrorCode));
            Disarm();
            co_return ErrorCode;
        }

        auto Receive() -> Net::awaitable<EcResult<std::vector<std::uint8_t>>>
        {
            std::array<std::uint8_t, 4096> Buffer{};
            boost::system::error_code ErrorCode;
            Arm();
            const auto Count = co_await Sock_->async_receive(Net::buffer(Buffer),
                                                         Net::redirect_error(Net::use_awaitable, ErrorCode));
            Disarm();
            if (ErrorCode)
            {
                co_return std::unexpected(ErrorCode);
            }
            co_return std::vector<std::uint8_t>(Buffer.begin(),
                                                Buffer.begin() + static_cast<std::ptrdiff_t>(Count));
        }

        auto IsOpen() const -> bool
        {
            return Sock_ && Sock_->is_open();
        }

        auto Close() -> void
        {
            Timer_.cancel();
            if (Sock_)
            {
                boost::system::error_code CloseError;
                Sock_->close(CloseError);
            }
        }

    private:
        /// 武装超时定时器：到期取消套接字上未完成的操作
        void Arm()
        {
            Timer_.expires_after(Timeout_);
            auto TimeoutOperation = [this](boost::system::error_code ErrorCode)
                              {
                                  if (ErrorCode != Net::error::operation_aborted && Sock_)
                                  {
                                      boost::system::error_code ignore;
                                      Sock_->cancel(ignore);
                                  } };
            Timer_.async_wait(std::move(TimeoutOperation));
        }

        /// 操作完成即解除定时器，防残留回调误伤后续操作
        void Disarm()
        {
            Timer_.cancel();
        }

        Net::any_io_executor Ex_;
        Net::steady_timer Timer_;
        std::chrono::milliseconds Timeout_;
        std::optional<Net::ip::udp::socket> Sock_;
    };

    /// 帧级传输的共享实现骨架：定时器武装 + 帧编解码（Tcp/Tls 复用）
    template <typename Derived>
    class FrameTransportBase
    {
    public:
        auto Send(std::span<const std::uint8_t> Wire) -> Net::awaitable<boost::system::error_code>
        {
            const auto FrameResult = Detail::MakeTcpFrame(Wire);
            if (!FrameResult)
            {
                co_return FrameResult.error();
            }
            const auto &Frame = *FrameResult;
            boost::system::error_code ErrorCode;
            Self().Arm();
            co_await Net::async_write(Self().Stream(), Net::buffer(Frame),
                                      Net::redirect_error(Net::use_awaitable, ErrorCode));
            Self().Disarm();
            co_return ErrorCode;
        }

        auto Receive() -> Net::awaitable<EcResult<std::vector<std::uint8_t>>>
        {
            std::array<std::uint8_t, 2> LengthBuffer{};
            boost::system::error_code ErrorCode;
            Self().Arm();
            co_await Net::async_read(Self().Stream(), Net::buffer(LengthBuffer),
                                     Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (!ErrorCode)
            {
                const auto Len = static_cast<std::size_t>((LengthBuffer[0] << 8) | LengthBuffer[1]);
                if (Len == 0 || Len > Detail::MaxFrameBytes)
                {
                    Self().Disarm();
                    co_return std::unexpected(
                        boost::system::errc::make_error_code(boost::system::errc::bad_message));
                }
                std::vector<std::uint8_t> body(Len);
                co_await Net::async_read(Self().Stream(), Net::buffer(body),
                                         Net::redirect_error(Net::use_awaitable, ErrorCode));
                Self().Disarm();
                if (ErrorCode)
                {
                    co_return std::unexpected(ErrorCode);
                }
                co_return body;
            }
            Self().Disarm();
            co_return std::unexpected(ErrorCode);
        }

        auto IsOpen() const -> bool
        {
            return Self().IsOpenImpl();
        }

        auto Close() -> void
        {
            Self().Disarm();
            Self().CloseImpl();
        }

    private:
        [[nodiscard]] auto Self() -> Derived &
        {
            return static_cast<Derived &>(*this);
        }
        [[nodiscard]] auto Self() const -> const Derived &
        {
            return static_cast<const Derived &>(*this);
        }
    };

    /**
     * @class TcpTransport
     * @brief TCP 帧传输（2 字节长度前缀，可入池）
     */
    class TcpTransport : public FrameTransportBase<TcpTransport>
    {
    public:
        TcpTransport(Net::any_io_executor Executor, const std::chrono::milliseconds Timeout)
            : Ex_(std::move(Executor)), Timer_(Ex_), Timeout_(Timeout), Sock_(Ex_)
        {
        }

        auto Connect(const Net::ip::tcp::endpoint &Endpoint, const Server & /*ServerConfig*/)
            -> Net::awaitable<boost::system::error_code>
        {
            boost::system::error_code ErrorCode;
            Arm();
            co_await Sock_.async_connect(Endpoint,
                                         Net::redirect_error(Net::use_awaitable, ErrorCode));
            Disarm();
            co_return ErrorCode;
        }

        [[nodiscard]] auto Stream() -> Net::ip::tcp::socket &
        {
            return Sock_;
        }

        auto IsOpenImpl() const -> bool
        {
            return Sock_.is_open();
        }

        auto CloseImpl() -> void
        {
            boost::system::error_code CloseError;
            Sock_.close(CloseError);
        }

        void Arm()
        {
            Timer_.expires_after(Timeout_);
            auto TimeoutOperation = [this](boost::system::error_code ErrorCode)
                              {
                                  if (ErrorCode != Net::error::operation_aborted)
                                  {
                                      boost::system::error_code ignore;
                                      Sock_.cancel(ignore);
                                  } };
            Timer_.async_wait(std::move(TimeoutOperation));
        }

        void Disarm()
        {
            Timer_.cancel();
        }

    private:
        Net::any_io_executor Ex_;
        Net::steady_timer Timer_;
        std::chrono::milliseconds Timeout_;
        Net::ip::tcp::socket Sock_;
    };

    /**
     * @class TlsTransport
     * @brief DoT 传输（TLS 承载 TCP 帧，可入池）
     * @details SNI 无条件发送（SkipCertCheck 的服务器同样可能要求 SNI）；
     *          证书校验策略由上层缓存的 ssl::context 决定
     */
    class TlsTransport : public FrameTransportBase<TlsTransport>
    {
    public:
        TlsTransport(Net::any_io_executor Executor, const std::chrono::milliseconds Timeout,
                     std::shared_ptr<Ssl::context> Context)
            : Ex_(std::move(Executor)), Timer_(Ex_), Timeout_(Timeout), Ctx_(std::move(Context))
        {
        }

        auto Connect(const Net::ip::tcp::endpoint &Endpoint, const Server &ServerConfig)
            -> Net::awaitable<boost::system::error_code>
        {
            boost::system::error_code ErrorCode;
            Stream_.emplace(Ex_, *Ctx_);
            std::string SniName = ServerConfig.Address;
            if (!ServerConfig.Hostname.empty())
            {
                SniName = ServerConfig.Hostname;
            }
            SSL_set_tlsext_host_name(Stream_->native_handle(), SniName.c_str());
            if (!ServerConfig.SkipCertCheck)
            {
                Stream_->set_verify_callback(Ssl::host_name_verification(SniName), ErrorCode);
                if (ErrorCode)
                {
                    co_return ErrorCode;
                }
            }
            Arm();
            co_await Stream_->lowest_layer().async_connect(
                Endpoint, Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (!ErrorCode)
            {
                co_await Stream_->async_handshake(Ssl::stream_base::client,
                                                  Net::redirect_error(Net::use_awaitable, ErrorCode));
            }
            Disarm();
            co_return ErrorCode;
        }

        [[nodiscard]] auto Stream() -> Ssl::stream<Net::ip::tcp::socket> &
        {
            return *Stream_;
        }

        auto IsOpenImpl() const -> bool
        {
            return Stream_ && Stream_->lowest_layer().is_open();
        }

        auto CloseImpl() -> void
        {
            if (Stream_)
            {
                boost::system::error_code CloseError;
                Stream_->lowest_layer().close(CloseError);
            }
        }

        void Arm()
        {
            Timer_.expires_after(Timeout_);
            auto TimeoutOperation = [this](boost::system::error_code ErrorCode)
                              {
                                  if (ErrorCode != Net::error::operation_aborted && Stream_)
                                  {
                                      boost::system::error_code ignore;
                                      Stream_->lowest_layer().cancel(ignore);
                                  } };
            Timer_.async_wait(std::move(TimeoutOperation));
        }

        void Disarm()
        {
            Timer_.cancel();
        }

    private:
        Net::any_io_executor Ex_;
        Net::steady_timer Timer_;
        std::chrono::milliseconds Timeout_;
        std::shared_ptr<Ssl::context> Ctx_;
        std::optional<Ssl::stream<Net::ip::tcp::socket>> Stream_;
    };

    // 编译期概念自检：三类传输均满足收发语义，Tcp/Tls 满足可池化语义
    static_assert(TransportLink<UdpTransport>);
    static_assert(TransportLink<TcpTransport> && PoolableTransport<TcpTransport>);
    static_assert(TransportLink<TlsTransport> && PoolableTransport<TlsTransport>);

} // namespace Preview::Network::Dns
