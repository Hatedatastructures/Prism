/**
 * @file Conn.hpp
 * @brief TUIC 会话连接对象（Transmission 装饰器）
 * @details 将底层传输包装为 TUIC 连接：
 * 1. WriteHandshake / ReadHandshake：客户端发 Connect 帧
 *    （目标地址）；服务端解析校验（简化：不做 UUID 认证）
 * 2. 隧道：async_read_some / async_write_some 透传 TCP 帧载荷
 * 3. UDP 数据面：AsyncSendDatagram / AsyncReceiveDatagram
 *    逐帧编解码（Codec.hpp 纯函数，packet 命令）
 * @note 与 TUIC 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Authenticator.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Protocols/Common/Address.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Tuic/Codec.hpp>
#include <Preview/Protocols/Tuic/Types.hpp>

namespace Preview::Tuic
{

    /**
     * @class Conn
      * @brief TUIC 会话连接（Transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后通过
     * Transmission 接口透传 TCP 帧载荷，或通过 AsyncSendDatagram
     * / AsyncReceiveDatagram 收发 UDP 数据报。
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Conn : public Preview::Transmission, public std::enable_shared_from_this<Conn<Memory>>
    {
    public:
        /**
         * @brief 构造函数
         * @param Upstream 底层传输（所有权移交）
         * @param Uuid 客户端 UUID（16 字节）
         */
        explicit Conn(
            SharedTransmission Upstream,
            std::array<std::uint8_t, 16> Uuid,
            const Preview::Authenticator *Auth = nullptr,
            Preview::SharedAuthenticator AuthOwner = {})
            : NextLayer_(std::move(Upstream)),
              Uuid_(Uuid),
              AuthOwner_(std::move(AuthOwner)),
              Auth_(Auth)
        {
            if (AuthOwner_)
            {
                Auth_ = AuthOwner_.get();
            }
        }

        /**
         * @brief 在独立 uni stream 发送 TUIC v5 认证帧
         * @param AuthStream 已打开的 uni stream
         * @param Exporter 当前 TLS 会话 exporter
         * @param Password 用户密码（作为 exporter context）
         * @return 错误码
         */
        [[nodiscard]] auto WriteAuthentication(
            SharedTransmission AuthStream,
            const KeyingMaterialExporter &Exporter,
            std::string_view Password) -> Net::awaitable<Error>
        {
            Authenticated_ = false;
            Handshaken_ = false;
            if (!AuthStream || !Exporter)
            {
                co_return Error::NotSupported;
            }
            std::array<std::uint8_t, TokenLen> Token{};
            if (!Exporter(std::span<std::uint8_t>(Token), std::span<const std::uint8_t>(Uuid_), Password))
            {
                co_return Error::KdfError;
            }
            const auto Wire = BuildAuthenticate(Uuid_, Token);
            if (co_await SendBytes(AuthStream, std::span<const std::uint8_t>(Wire)))
            {
                co_return Error::IoError;
            }
            AuthStream->Shutdown();
            Authenticated_ = true;
            co_return Error::None;
        }

        /**
         * @brief 从独立 uni stream 校验 TUIC v5 认证帧
         * @param AuthStream 收到认证帧的 uni stream
         * @param Exporter 当前 TLS 会话 exporter
         * @param Password 用户密码（作为 exporter context）
         * @return 错误码
         */
        [[nodiscard]] auto ReadAuthentication(
            SharedTransmission AuthStream,
            const KeyingMaterialExporter &Exporter,
            std::string_view Password) -> Net::awaitable<Error>
        {
            Authenticated_ = false;
            Handshaken_ = false;
            if (!AuthStream || !Exporter)
            {
                co_return Error::NotSupported;
            }
            std::array<std::uint8_t, AuthenticateFrameLen> Wire{};
            if (co_await ReadExactFrom(AuthStream, std::span<std::uint8_t>(Wire)))
            {
                co_return Error::UnexpectedEof;
            }
            AuthenticateFrame Frame{};
            std::size_t Consumed = 0;
            const auto ParseErr = ParseAuthenticate(Wire, Frame, Consumed);
            const std::string_view GotUuid(reinterpret_cast<const char *>(Frame.Uuid.data()), Frame.Uuid.size());
            const std::string_view ExpectedUuid(reinterpret_cast<const char *>(Uuid_.data()), Uuid_.size());
            if (ParseErr != Error::None || Consumed != Wire.size() ||
                !Preview::ConstantTimeEqual(GotUuid, ExpectedUuid))
            {
                co_return Error::BadAuth;
            }
            const std::string_view GotToken(reinterpret_cast<const char *>(Frame.Token.data()), Frame.Token.size());
            if (Auth_)
            {
                auto AuthenticationResult = Auth_->Authenticate(Preview::AuthenticationRequest{
                    .AccountId = {},
                    .Identity = {},
                    .Credential = Preview::Account::CredentialView::Token(GotToken),
                    .Rate = {}});
                if (!AuthenticationResult.Accepted)
                {
                    co_return Error::BadAuth;
                }
                AuthLease_ = std::move(AuthenticationResult.Lease);
                AccountId_ = AuthenticationResult.AccountId;
                Identity_ = std::move(AuthenticationResult.Identity);
            }
            else
            {
                std::array<std::uint8_t, TokenLen> Expected{};
                if (!Exporter(std::span<std::uint8_t>(Expected),
                               std::span<const std::uint8_t>(Uuid_), Password))
                {
                    co_return Error::KdfError;
                }
                const std::string_view ExpectedToken(
                    reinterpret_cast<const char *>(Expected.data()), Expected.size());
                if (!Preview::ConstantTimeEqual(GotToken, ExpectedToken))
                {
                    co_return Error::BadAuth;
                }
            }
            Authenticated_ = true;
            co_return Error::None;
        }

        /** @brief 获取认证后的账户租约。 */
        [[nodiscard]] auto TakeAuthLease() -> Preview::Account::AccountLease
        {
            return std::move(AuthLease_);
        }

        /** @brief 获取认证后的 typed 账户身份。 */
        [[nodiscard]] auto AccountId() const noexcept -> Preview::AccountId
        {
            return AccountId_;
        }

        /** @brief 获取认证后的非敏感身份文本。 */
        [[nodiscard]] auto Identity() const noexcept -> std::string_view
        {
            return Identity_;
        }

        /** @brief 复用已完成的连接级认证结果接入后续 bidi stream。 */
        auto MarkAuthenticated(Preview::AccountId AccountId = {},
                               Preview::Account::AccountLease Lease = {},
                               std::string Identity = {}) -> void
        {
            Authenticated_ = true;
            AccountId_ = AccountId;
            AuthLease_ = std::move(Lease);
            Identity_ = std::move(Identity);
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
         * @brief 客户端握手：发 Connect 帧
         * @param Target 目标地址
         * @return 错误码
         */
        [[nodiscard]] auto WriteHandshake(const Address &Target) -> Net::awaitable<Error>
        {
            co_await DispatchToExecutor();
            if (!Authenticated_)
            {
                co_return Error::BadAuth;
            }
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }
            Message MessageValue;
            MessageValue.Cmd = CmdConnect;
            MessageValue.dst = Target;
            const auto Wire = Build(MessageValue);
            if (Wire.empty())
            {
                co_return Error::BadAddress;
            }
            if (co_await SendBytes(NextLayer_, std::span<const std::uint8_t>(Wire)))
            {
                co_return Error::IoError;
            }
            Target_ = Target;
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 服务端握手：读 Connect 帧
         * @return 错误码与解析的消息
         */
        [[nodiscard]] auto ReadHandshake() -> Net::awaitable<std::pair<Error, Message>>
        {
            co_await DispatchToExecutor();
            if (!Authenticated_)
            {
                co_return std::pair{Error::BadAuth, Message{}};
            }
            if (!NextLayer_)
            {
                co_return std::pair{Error::NotOpen, Message{}};
            }
            Message MessageValue;
            const auto FrameError = co_await ReadFrame(MessageValue);
            if (FrameError != Error::None)
            {
                co_return std::pair{FrameError, Message{}};
            }
            if (MessageValue.Cmd != CmdConnect)
            {
                co_return std::pair{Error::BadMessage, Message{}};
            }
            Target_ = MessageValue.dst;
            Parsed_ = MessageValue;
            Handshaken_ = true;
            co_return std::pair{Error::None, std::move(MessageValue)};
        }

        /**
         * @brief 获取服务端握手解析的消息
         */
        [[nodiscard]] auto Parsed() const -> const Message &
        {
            return Parsed_;
        }

        /**
         * @brief 发送一个 UDP 数据报（packet 命令）
         * @param Target 目标地址（帧内携带）
         * @param Payload 载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncSendDatagram(
            const Address &Target,
            std::span<const std::uint8_t> Payload) -> Net::awaitable<Error>
        {
            co_await DispatchToExecutor();
            if (!Handshaken_)
            {
                co_return Error::NotOpen;
            }
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }
            if (Payload.size() > 0xFFFF)
            {
                co_return Error::BadLength;
            }
            Message MessageValue;
            MessageValue.Cmd = CmdPacket;
            MessageValue.AssocId = AssocId_;
            MessageValue.PktId = PacketId_;
            MessageValue.dst = Target;
            MessageValue.payload.assign(
                reinterpret_cast<const char *>(Payload.data()),
                Payload.size());
            const auto Wire = Build(MessageValue);
            if (Wire.empty())
            {
                co_return Error::BadAddress;
            }
            ++PacketId_;
            if (co_await SendBytes(NextLayer_, std::span<const std::uint8_t>(Wire)))
            {
                co_return Error::IoError;
            }
            co_return Error::None;
        }

        /**
         * @brief 接收一个 UDP 数据报（packet 命令）
         * @param Target 输出目标地址
         * @param Payload 输出载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncReceiveDatagram(
            Address &Target,
            std::vector<std::uint8_t> &Payload) -> Net::awaitable<Error>
        {
            co_await DispatchToExecutor();
            if (!Handshaken_)
            {
                co_return Error::NotOpen;
            }
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }
            Message MessageValue;
            const auto FrameError = co_await ReadFrame(MessageValue);
            if (FrameError != Error::None)
            {
                co_return FrameError;
            }
            if (MessageValue.Cmd != CmdPacket)
            {
                co_return Error::BadMessage;
            }
            Target = MessageValue.dst;
            Payload.assign(MessageValue.payload.begin(), MessageValue.payload.end());
            co_return Error::None;
        }

        /**
         * @brief 透传读取（握手后数据面为裸流）
         */
        [[nodiscard]] auto async_read_some(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            co_await DispatchToExecutor();
            if (!NextLayer_ || !Handshaken_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            co_return co_await NextLayer_->async_read_some(Buffer, ErrorCode);
        }

        /**
         * @brief 透传写入（握手后数据面为裸流）
         */
        [[nodiscard]] auto async_write_some(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            co_await DispatchToExecutor();
            if (!NextLayer_ || !Handshaken_)
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
            Handshaken_ = false;
            Authenticated_ = false;
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
            Handshaken_ = false;
            Authenticated_ = false;
            return std::move(NextLayer_);
        }
        /**
         * @brief 会话是否有效（已握手且底层存在）
         * @return 有效返回 true
         */
        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            return NextLayer_ != nullptr && Handshaken_;
        }

        /**
         * @brief 获取底层传输共享引用
         * @return 底层传输共享指针
         */
        [[nodiscard]] auto Underlying() noexcept -> SharedTransmission
        {
            return NextLayer_;
        }

        /**
         * @brief 获取会话级内存竞技场
         * @return 非拥有资源指针（供握手/解析的临时分配）
         * @note 分配的对象随 Conn 存活，Conn 析构时一次性回收
         */
        [[nodiscard]] auto Arena() noexcept -> Preview::Memory::ResourcePointer
        {
            return Mem_.Arena();
        }

    private:
        [[nodiscard]] auto DispatchToExecutor() -> Net::awaitable<void>
        {
            if (NextLayer_)
            {
                co_await Net::dispatch(NextLayer_->Executor(), Net::use_awaitable);
            }
        }

        /**
         * @brief 读取一帧（Ver + Cmd + [Id] + [地址] + [载荷]）
         * @param MessageValue 输出消息
         * @return 错误码
         * @details 帧无长度字段：精确分段读取头部，剩余一次读为
         * 载荷（packet 命令）。
         */
        [[nodiscard]] auto ReadFrame(Message &MessageValue) -> Net::awaitable<Error>
        {
            std::array<std::uint8_t, 2> Head{};
            if (co_await ReadExact(std::span<std::uint8_t>(Head)))
            {
                co_return Error::UnexpectedEof;
            }
            if (Head[0] != ProtocolVersion)
            {
                co_return Error::BadMagic;
            }
            MessageValue.Cmd = Head[1];
            if (MessageValue.Cmd == CmdPacket)
            {
                std::array<std::uint8_t, 8> PacketHeader{};
                if (co_await ReadExact(std::span<std::uint8_t>(PacketHeader)))
                {
                    co_return Error::UnexpectedEof;
                }
                MessageValue.AssocId =
                    static_cast<std::uint16_t>(PacketHeader[0]) << 8 | PacketHeader[1];
                MessageValue.PktId =
                    static_cast<std::uint16_t>(PacketHeader[2]) << 8 | PacketHeader[3];
                MessageValue.FragTotal = PacketHeader[4];
                MessageValue.FragId = PacketHeader[5];
                MessageValue.Size =
                    static_cast<std::uint16_t>(PacketHeader[6]) << 8 | PacketHeader[7];
                if (MessageValue.FragTotal == 0 || MessageValue.FragId >= MessageValue.FragTotal)
                {
                    co_return Error::BadMessage;
                }
            }
            if (MessageValue.Cmd == CmdConnect || MessageValue.Cmd == CmdPacket)
            {
                // 地址体：ATYP(1) + ADDR + PORT(2)
                std::array<std::uint8_t, 1> Atyp{};
                if (co_await ReadExact(std::span<std::uint8_t>(Atyp)))
                {
                    co_return Error::UnexpectedEof;
                }
                const auto IsPacketContinuation =
                    MessageValue.Cmd == CmdPacket && MessageValue.FragId != 0;
                if (IsPacketContinuation)
                {
                    if (Atyp[0] != static_cast<std::uint8_t>(AddressType::None))
                    {
                        co_return Error::BadMessage;
                    }
                    MessageValue.dst.Type = AddressType::None;
                    MessageValue.dst.Host.clear();
                    MessageValue.dst.Port = 0;
                }
                else
                {
                    MessageValue.dst.Type = static_cast<AddressType>(Atyp[0]);
                    const auto AddressError = co_await ReadAddressBody(MessageValue.dst);
                    if (AddressError != Error::None)
                    {
                        co_return AddressError;
                    }
                    std::array<std::uint8_t, 2> Port{};
                    if (co_await ReadExact(std::span<std::uint8_t>(Port)))
                    {
                        co_return Error::UnexpectedEof;
                    }
                    MessageValue.dst.Port = static_cast<std::uint16_t>(Port[0]) << 8 | Port[1];
                }
            }
            if (MessageValue.Cmd == CmdPacket)
            {
                if (MessageValue.FragId == 0)
                {
                    if (MessageValue.dst.Type == AddressType::None)
                    {
                        co_return Error::BadMessage;
                    }
                }
                else if (MessageValue.dst.Type != AddressType::None)
                {
                    co_return Error::BadMessage;
                }
                std::vector<std::uint8_t> Payload(MessageValue.Size);
                if (co_await ReadExact(std::span<std::uint8_t>(Payload)))
                {
                    co_return Error::UnexpectedEof;
                }
                MessageValue.payload.assign(Payload.begin(), Payload.end());
            }
            co_return Error::None;
        }

        /**
         * @brief 精确读取指定字节数
         * @param Dst 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         */
        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> Dst) -> Net::awaitable<bool>
        {
            if (!NextLayer_)
            {
                co_return true;
            }
            std::size_t Done = 0;
            while (Done < Dst.size())
            {
                std::error_code ErrorCode;
                const auto N = co_await NextLayer_->async_read_some(
                    AsBytes(Dst.subspan(Done)),
                    ErrorCode);
                if (ErrorCode || N == 0)
                {
                    co_return true;
                }
                if (N > Dst.size() - Done)
                {
                    co_return true;
                }
                Done += N;
            }
            co_return false;
        }

        /**
         * @brief 发送全部字节
         * @param Data 数据
         * @return true = 失败
         */
        [[nodiscard]] static auto SendBytes(
            const SharedTransmission &Upstream,
            std::span<const std::uint8_t> Data) -> Net::awaitable<bool>
        {
            if (!Upstream)
            {
                co_return true;
            }
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                std::error_code ErrorCode;
                const auto N = co_await Upstream->async_write_some(
                    AsBytes(Data.subspan(Done)),
                    ErrorCode);
                if (ErrorCode || N == 0)
                {
                    co_return true;
                }
                if (N > Data.size() - Done)
                {
                    co_return true;
                }
                Done += N;
            }
            co_return false;
        }

        /**
         * @brief 从指定传输精确读取
         */
        [[nodiscard]] static auto ReadExactFrom(
            const SharedTransmission &Upstream,
            std::span<std::uint8_t> Data) -> Net::awaitable<bool>
        {
            if (!Upstream)
            {
                co_return true;
            }
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                std::error_code ErrorCode;
                const auto N = co_await Upstream->async_read_some(
                    AsBytes(Data.subspan(Done)),
                    ErrorCode);
                if (ErrorCode || N == 0)
                {
                    co_return true;
                }
                if (N > Data.size() - Done)
                {
                    co_return true;
                }
                Done += N;
            }
            co_return false;
        }

        /**
         * @brief 读取地址体（ATYP 已由调用方解析）
         * @param AddressValue 输出地址
         * @return 错误码
         * @note 转发层：统一实现见 Protocol/common::ReadAddressBody
         */
        [[nodiscard]] auto ReadAddressBody(Address &AddressValue) -> Net::awaitable<Error>
        {
            return Preview::Protocol::Common::ReadAddressBody(
                AddressValue,
                [this](std::span<std::uint8_t> Buffer) -> Net::awaitable<bool>
                {
                    return ReadExact(Buffer);
                });
        }

        SharedTransmission NextLayer_;      ///< 底层传输（独占所有权）
        std::array<std::uint8_t, 16> Uuid_{}; ///< 客户端 UUID（凭据）
        Preview::SharedAuthenticator AuthOwner_{}; ///< 认证器共享所有权
        const Preview::Authenticator *Auth_{nullptr}; ///< 认证器（非拥有）
        Preview::Account::AccountLease AuthLease_{}; ///< 协议认证租约
        Preview::AccountId AccountId_{};             ///< typed 账户身份
        std::string Identity_{};                     ///< 非敏感身份文本
        Address Target_;                      ///< TCP 目标地址（握手后）
        Message Parsed_{};                    ///< 服务端握手解析结果
        std::uint32_t AssocId_{0};           ///< UDP 关联 ID
        std::uint16_t PacketId_{0};          ///< UDP 包 ID（自增）
        bool Handshaken_{false};              ///< 握手完成标志
        bool Authenticated_{false};           ///< TUIC v5 uni stream 已认证
        Memory Mem_;     ///< 会话级内存竞技场（热路径零释放分配）
    };


    /// 流连接共享指针
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Tuic
