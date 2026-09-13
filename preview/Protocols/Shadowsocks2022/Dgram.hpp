/**
 * @file Dgram.hpp
 * @brief SS2022 UDP 包连接对象（Transmission 装饰器）
 * @details UDP 数据面连接：将底层数据报传输（Unreliable，
 * 或任意包边界的传输）包装为 SS2022（SIP022）逐包 AEAD 编解码层。
 * - 客户端：底层 Unreliable Connect(remote) 后，本类逐包加密发送
 * - 服务端：底层 Unreliable Bind(port) 后，本类逐包解密
 * 每个包独立加密（SeparateHeader 含 SessionID/PacketID，Nonce 派生），
 * 目标地址内嵌于包内，无状态。编解码逻辑复用 Codec.hpp 纯函数
 * （BuildUdpPacket / ParseUdpPacket）。
 * @note 继承 Preview::Transmission，构造函数传入底层传输（相当于
 * socket 收发的持有者），对齐 Conn 的装饰器链模式。
 * @note 对齐 mihomo adapter/Outbound/shadowsocks.go：
 *          ListenPacketContext 创建真实 UDP socket + DialPacketConn
 *          （逐包 AEAD），UDPOverTCP 才是可选的 TCP 封装模式。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <openssl/rand.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Foundation/Memory/Pointer.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Transport/Unreliable.hpp>
#include <preview/Protocols/Shadowsocks2022/Codec.hpp>
#include <preview/Protocols/Shadowsocks2022/Types.hpp>

namespace Preview::Shadowsocks2022
{

    namespace Net = boost::asio;

    /**
     * @class Dgram
     * @brief SS2022 UDP 包连接对象（Transmission 装饰器）
     * @details 持有底层数据报传输的独占所有权，对外暴露包级 API
     * （AsyncSendTo / AsyncReceiveFrom），内部完成逐包 AEAD
     * 编解码（Codec.hpp 纯函数）。由工厂（ConnectPacket /
     * AcceptPacket）创建。
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Dgram : public Preview::Transmission, public std::enable_shared_from_this<Dgram<Memory>>
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param Upstream 底层数据报传输（已 Connect/Bind，所有权移交）
         * @param Key 16 字节 UDP 密钥（PSK 派生）
         */
        explicit Dgram(
            SharedTransmission Upstream,
            std::array<std::uint8_t, 16> Key,
            UdpRole Role = UdpRole::Client)
            : NextLayer_(std::move(Upstream)), Key_(Key), Role_(Role)
        {
            SessionIdReady_ = RAND_bytes(LocalSessionId_.data(), static_cast<int>(LocalSessionId_.size())) == 1;
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            if (!NextLayer_)
            {
                return {};
            }
            return NextLayer_->Executor();
        }

        /**
         * @brief 传输类型（数据报）
         */
        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Udp;
        }

        /**
         * @brief 发送一个 UDP 数据报（WriteTo 语义，逐包 AEAD）
         * @param Target 目标地址（内嵌于包）
         * @param Payload 载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncSendTo(
            const Address &Target,
            std::span<const std::uint8_t> Payload) -> Net::awaitable<Error>
        {
            if (!NextLayer_ || !NextLayer_->IsOpen() || !SessionIdReady_)
            {
                co_return Error::NotOpen;
            }
            if (Role_ == UdpRole::Server && !HasPeer_)
            {
                co_return Error::BadMessage;
            }
            std::uint8_t PacketType = HeaderTypeClient;
            std::span<const std::uint8_t> PeerSession;
            if (Role_ == UdpRole::Server)
            {
                PacketType = HeaderTypeServer;
                PeerSession = std::span<const std::uint8_t>(PeerSessionId_);
            }
            const auto PacketId = NextPacketId_;
            if (!BuildUdpPacket(
                    UdpBuildInput{
                        Key_, PacketId, &Target, Payload, LocalSessionId_, 0, PeerSession, PacketType},
                    TxWire_))
            {
                co_return Error::BadLength;
            }
            std::error_code ErrorCode;
            if (auto *Udp = dynamic_cast<Preview::Transport::Unreliable *>(NextLayer_.get()); Udp != nullptr)
            {
                std::size_t Sent = 0;
                if (PeerEndpoint_.has_value())
                {
                    Sent = co_await Udp->AsyncSendTo(
                        AsBytes(std::span<const std::uint8_t>(TxWire_)), *PeerEndpoint_, ErrorCode);
                }
                else
                {
                    Sent = co_await NextLayer_->async_write_some(
                        AsBytes(std::span<const std::uint8_t>(TxWire_)), ErrorCode);
                }
                if (ErrorCode)
                {
                    co_return Error::IoError;
                }
                if (Sent > TxWire_.size())
                {
                    co_return Error::BadLength;
                }
                if (Sent != TxWire_.size())
                {
                    co_return Error::IoError;
                }
            }
            else
            {
                const auto Sent = co_await NextLayer_->async_write_some(
                    AsBytes(std::span<const std::uint8_t>(TxWire_)), ErrorCode);
                if (ErrorCode)
                {
                    co_return Error::IoError;
                }
                if (Sent > TxWire_.size())
                {
                    co_return Error::BadLength;
                }
                if (Sent != TxWire_.size())
                {
                    co_return Error::IoError;
                }
            }
            ++NextPacketId_;
            co_return Error::None;
        }

        /**
         * @brief 接收一个 UDP 数据报（ReadFrom 语义，逐包 AEAD）
         * @param Source 输出源地址（包内目标）
         * @param Payload 输出载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncReceiveFrom(
            Address &Source,
            std::vector<std::uint8_t> &Payload) -> Net::awaitable<Error>
        {
            if (!NextLayer_ || !SessionIdReady_)
            {
                co_return Error::NotOpen;
            }
            constexpr std::size_t MaxAddressWireSize = 1 + 1 + 0xFF + 2;
            constexpr std::size_t MaxWireSize =
                SeparateHdrLen + 1 + UdpTsLen + MaxAddressWireSize + 2 + MaxUdpPayload + AeadTagLen;
            std::array<std::uint8_t, MaxWireSize> Buffer{};
            std::error_code ErrorCode;
            std::size_t Received = 0;
            std::optional<Preview::Transport::Unreliable::EndpointType> SenderEndpoint;
            if (auto *Udp = dynamic_cast<Preview::Transport::Unreliable *>(NextLayer_.get());
                Udp != nullptr)
            {
                Preview::Transport::Unreliable::EndpointType Sender;
                ErrorCode.clear();
                Received = co_await Udp->AsyncReceiveFrom(
                    AsBytes(std::span<std::uint8_t>(Buffer)), Sender, ErrorCode);
                if (!ErrorCode)
                {
                    SenderEndpoint = Sender;
                }
            }
            else
            {
                ErrorCode.clear();
                Received = co_await NextLayer_->async_read_some(
                    AsBytes(std::span<std::uint8_t>(Buffer)), ErrorCode);
            }
            if (ErrorCode)
            {
                co_return Error::IoError;
            }
            if (Received == 0)
            {
                co_return Error::UnexpectedEof;
            }
            if (Received > Buffer.size())
            {
                co_return Error::BadLength;
            }
            std::array<std::uint8_t, SessionIdLen> PacketSessionId{};
            std::array<std::uint8_t, SessionIdLen> RemoteSessionId{};
            std::uint64_t PacketId = 0;
            std::uint64_t Timestamp = 0;
            std::uint8_t PacketType = 0;
            const auto ParseError = ParseUdpPacket(UdpParseInput{
                Key_,
                std::span<const std::uint8_t>(Buffer.data(), Received),
                &Source,
                &Payload,
                &PacketSessionId,
                &PacketId,
                &Timestamp,
                &PacketType,
                &RemoteSessionId});
            if (ParseError != Error::None)
            {
                co_return ParseError;
            }
            const auto Now = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count());
            std::uint64_t Difference = 0;
            if (Now >= Timestamp)
            {
                Difference = Now - Timestamp;
            }
            else
            {
                Difference = Timestamp - Now;
            }
            if (Difference > 30)
            {
                co_return Error::BadMessage;
            }
            if (Role_ == UdpRole::Server)
            {
                if (PacketType != HeaderTypeClient)
                {
                    co_return Error::BadMessage;
                }
                if (!HasPeer_ || PacketSessionId != PeerSessionId_)
                {
                    PeerSessionId_ = PacketSessionId;
                    HasPeer_ = true;
                    ResetReplay();
                }
            }
            else
            {
                if (PacketType != HeaderTypeServer || RemoteSessionId != LocalSessionId_)
                {
                    co_return Error::BadMessage;
                }
                if (!HasPeer_ || PacketSessionId != PeerSessionId_)
                {
                    PeerSessionId_ = PacketSessionId;
                    HasPeer_ = true;
                    ResetReplay();
                }
            }
            if (!AcceptPacketId(PacketId))
            {
                co_return Error::BadMessage;
            }
            // 仅在整包完成密钥、时间戳、角色、会话和重放校验后
            // 绑定网络来源，避免坏包劫持后续服务端回包端点。
            if (SenderEndpoint)
            {
                PeerEndpoint_ = *SenderEndpoint;
            }
            co_return Error::None;
        }

        /**
         * @brief 透传读取（底层数据报原样）
         */
        [[nodiscard]] auto async_read_some(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            ErrorCode.clear();
            if (!NextLayer_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            co_return co_await NextLayer_->async_read_some(Buffer, ErrorCode);
        }

        /**
         * @brief 透传写入（底层数据报原样）
         */
        [[nodiscard]] auto async_write_some(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            ErrorCode.clear();
            if (!NextLayer_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            co_return co_await NextLayer_->async_write_some(Buffer, ErrorCode);
        }

        /**
         * @brief 关闭底层传输
         */
        auto Close() -> void override
        {
            if (NextLayer_)
            {
                NextLayer_->Close();
            }
        }

        /**
         * @brief 取消挂起操作
         */
        auto Cancel() -> void override
        {
            if (NextLayer_)
            {
                NextLayer_->Cancel();
            }
        }

        /**
         * @brief 获取底层传输（装饰器链导航）
         */
        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         */
        [[nodiscard]] auto Release() -> SharedTransmission override
        {
            return std::move(NextLayer_);
        }

        /**
         * @brief 获取底层传输
         */
        [[nodiscard]] auto Stream() const noexcept -> SharedTransmission
        {
            return NextLayer_;
        }

        /**
         * @brief 获取本地 UDP Session ID
         * @return 只读的 8 字节会话标识
         */
        [[nodiscard]] auto SessionId() const noexcept
            -> const std::array<std::uint8_t, SessionIdLen> &
        {
            return LocalSessionId_;
        }

        /**
         * @brief 获取最近认证的对端 Session ID
         * @return 对端会话标识；尚未收到数据时报全零
         */
        [[nodiscard]] auto PeerSessionId() const noexcept
            -> const std::array<std::uint8_t, SessionIdLen> &
        {
            return PeerSessionId_;
        }

    private:
        SharedTransmission NextLayer_;   ///< 底层数据报传输（独占所有权）
        std::array<std::uint8_t, 16> Key_; ///< UDP 会话密钥（PSK 派生）
        UdpRole Role_{UdpRole::Client};    ///< UDP 端点角色
        std::array<std::uint8_t, SessionIdLen> LocalSessionId_{}; ///< 本地随机 Session ID
        std::array<std::uint8_t, SessionIdLen> PeerSessionId_{};  ///< 对端 Session ID
        std::uint64_t NextPacketId_{0};    ///< 下一个发送 Packet ID（从 0 开始）
        std::uint64_t HighestPacketId_{0}; ///< 接收窗口最高 Packet ID
        std::uint64_t ReplayBits_{0};      ///< 最近 64 个 Packet ID 位图
        bool HasPeer_{false};              ///< 是否已绑定对端 Session ID
        bool HasReceivedPacket_{false};    ///< 是否已初始化接收窗口
        bool SessionIdReady_{false};       ///< CSPRNG 是否成功生成 Session ID
        std::optional<Preview::Transport::Unreliable::EndpointType> PeerEndpoint_;
                                               ///< 最近认证数据报的来源端点
        Memory Mem_;                       ///< 会话内存策略（Arena，热路径零释放分配）
        typename Memory::template Buffer<std::uint8_t> TxWire_{Mem_.Arena()}; ///< 发送缓冲（Arena 复用，热路径零分配）

        auto ResetReplay() -> void
        {
            HighestPacketId_ = 0;
            ReplayBits_ = 0;
            HasReceivedPacket_ = false;
        }

        [[nodiscard]] auto AcceptPacketId(const std::uint64_t PacketId) -> bool
        {
            if (!HasReceivedPacket_)
            {
                HighestPacketId_ = PacketId;
                ReplayBits_ = 1;
                HasReceivedPacket_ = true;
                return true;
            }
            if (PacketId > HighestPacketId_)
            {
                const auto Shift = PacketId - HighestPacketId_;
                if (Shift >= 64)
                {
                    ReplayBits_ = 1ULL;
                }
                else
                {
                    ReplayBits_ = (ReplayBits_ << Shift) | 1ULL;
                }
                HighestPacketId_ = PacketId;
                return true;
            }
            const auto Distance = HighestPacketId_ - PacketId;
            if (Distance >= 64)
            {
                return false;
            }
            const auto Mask = 1ULL << Distance;
            if ((ReplayBits_ & Mask) != 0)
            {
                return false;
            }
            ReplayBits_ |= Mask;
            return true;
        }
    };

    /// 包连接共享指针
    using SharedDgram = std::shared_ptr<Dgram<>>;

} // namespace Preview::Shadowsocks2022
