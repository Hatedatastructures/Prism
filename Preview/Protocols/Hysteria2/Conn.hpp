/**
 * @file Conn.hpp
 * @brief Hysteria2 会话连接对象（Transmission 装饰器）
 * @details 将底层传输包装为 Hysteria2 连接：
 * 1. WriteHandshake / ReadHandshake：客户端发认证帧（HTTP/3
 *    HEADERS 风格）与 TCP 目标帧；服务端解析校验（简化：不严格
 *    校验认证内容）
 * 2. 隧道：ReadSome / WriteSome 正式前门透传 TCP 帧载荷
 * 3. UDP 数据面：AsyncSendDatagram / AsyncReceiveDatagram
 *    逐帧编解码（Codec.hpp 纯函数），目标地址随帧携带
 * @note 与 hysteria2.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Protocols/Common/Address.hpp>
#include <Preview/Protocols/Common/IoBridge.hpp>
#include <Preview/Transport/Detail/IoCompletion.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Hysteria2/Codec.hpp>
#include <Preview/Protocols/Hysteria2/Http3Auth.hpp>
#include <Preview/Protocols/Hysteria2/Io.hpp>
#include <Preview/Protocols/Hysteria2/Types.hpp>

namespace Preview::Hysteria2
{

    /**
     * @class Conn
     * @brief Hysteria2 会话连接（Transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后通过
     * Transmission 接口透传 TCP 帧载荷，或通过 AsyncSendDatagram
     * / AsyncReceiveDatagram 收发 UDP 数据报。
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Conn : public Preview::Transmission
    {
    public:
        /**
         * @brief 构造函数
         * @param Upstream 底层传输（所有权移交）
         * @param Password 认证密码
         * @param AuthOwner 认证器共享所有权
         */
        explicit Conn(
            SharedTransmission Upstream,
            std::string Password,
            Preview::SharedAuthenticator AuthOwner = {})
            : Preview::Transmission(Upstream ? Upstream->Executor() : Net::any_io_executor{}),
              NextLayer_(std::move(Upstream)), Password_(std::move(Password)),
              AuthOwner_(std::move(AuthOwner))
        {
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            if (!NextLayer_)
            {
                return Preview::Transmission::Executor();
            }
            return NextLayer_->Executor();
        }

        /**
         * @brief 客户端握手：发认证帧 + TCP 目标帧
         * @param Target 目标地址
         * @return 错误码
         * @details 认证帧（MakeAuthRequest）后紧跟 TCP 帧
         * （目标 + 空载荷），对齐 sing-hysteria2 客户端行为。
         */
        [[nodiscard]] auto WriteHandshake(const Address &Target) -> Net::awaitable<Error>
        {
            co_await DispatchToExecutor();
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }
            Handshaken_ = false;
            const auto Auth = MakeAuthRequest(Password_);
            if (Auth.empty())
            {
                co_return Error::BadLength;
            }
            const auto Tcp = BuildTcp(Target, {});
            if (Tcp.empty())
            {
                co_return Error::BadAddress;
            }
            if (co_await SendBytes(AsU8Span(Auth)))
            {
                co_return Error::IoError;
            }
            if (co_await SendBytes(Tcp))
            {
                co_return Error::IoError;
            }
            Target_ = Target;
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 服务端握手：读认证帧（校验） + TCP 目标帧
         * @return 错误码与解析的消息
         * @details 读取认证帧（简化：仅校验 HEADERS 首字节 0x01），
         * 再读 TCP 目标帧解析地址与初始载荷。
         */
        [[nodiscard]] auto ReadHandshake() -> Net::awaitable<std::pair<Error, Message>>
        {
            co_await DispatchToExecutor();
            if (!NextLayer_)
            {
                co_return std::pair{Error::NotOpen, Message{}};
            }
            Handshaken_ = false;
            // 1. 认证帧：HTTP/3 HEADERS 类型和长度均为 varint，随后是 QPACK 头块。
            std::array<std::uint8_t, 1> AuthType{};
            if (co_await ReadExact(std::span<std::uint8_t>(AuthType)))
            {
                co_return std::pair{Error::IoError, Message{}};
            }
            if (AuthType[0] != static_cast<std::uint8_t>(AuthFrameHeaders))
            {
                co_return std::pair{Error::BadMagic, Message{}};
            }
            std::array<std::uint8_t, 8> AuthLenBytes{};
            std::size_t AuthLenSize = 1;
            if (co_await ReadExact(std::span<std::uint8_t>(AuthLenBytes).first(1)))
            {
                co_return std::pair{Error::IoError, Message{}};
            }
            const auto LengthTag = AuthLenBytes[0] >> 6;
            AuthLenSize = static_cast<std::size_t>(1U << LengthTag);
            if (AuthLenSize > 1 &&
                co_await ReadExact(
                    std::span<std::uint8_t>(AuthLenBytes).subspan(1, AuthLenSize - 1)))
            {
                co_return std::pair{Error::IoError, Message{}};
            }
            std::uint64_t AuthLength = AuthLenBytes[0] & 0x3F;
            for (std::size_t I = 1; I < AuthLenSize; ++I)
            {
                AuthLength = (AuthLength << 8) | AuthLenBytes[I];
            }
            if (AuthLength > 64 * 1024)
            {
                co_return std::pair{Error::BadLength, Message{}};
            }
            std::vector<std::uint8_t> AuthBody(static_cast<std::size_t>(AuthLength));
            if (co_await ReadExact(AuthBody))
            {
                co_return std::pair{Error::IoError, Message{}};
            }
            WireAuthRequest AuthRequest;
            if (!ParseAuthRequestWire(
                    AuthBody, AuthRequest, Preview::Memory::CurrentResource()))
            {
                co_return std::pair{Error::BadAuth, Message{}};
            }
            const std::string Credential = AuthRequest.Credential;
            bool Ok;
            if (const auto *Authenticator = AuthOwner_.get())
            {
                auto AuthenticationResult = Authenticator->Authenticate(Preview::AuthenticationRequest{
                    .AccountId = {},
                    .Identity = {},
                    .Credential = Preview::Account::CredentialView::Token(Credential),
                    .Rate = {}});
                Ok = static_cast<bool>(AuthenticationResult);
                if (Ok)
                {
                    AuthLease_ = std::move(*AuthenticationResult);
                    AccountId_ = AuthLease_.AccountId();
                    Identity_ = std::string(AuthLease_.Identity());
                }
            }
            else
            {
                Ok = Preview::ConstantTimeEqual(Credential, Password_);
            }
            if (!Ok)
            {
                co_return std::pair{Error::BadAuth, Message{}};
            }

            // 2. TCP 目标帧
            Message MessageValue;
            const auto FrameError = co_await ReadFrame(MessageValue);
            if (FrameError != Error::None)
            {
                co_return std::pair{FrameError, Message{}};
            }
            if (MessageValue.Type != Message::Kind::Tcp)
            {
                co_return std::pair{Error::Unsupported, Message{}};
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

        /**
         * @brief 发送一个 UDP 数据报（UDP 数据面）
         * @param Target 目标地址（帧内携带）
         * @param Payload 载荷
         * @return 错误码
         * @details 逐帧编解码（BuildUdp），Session/packet Id 递增。
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
            if (!NextLayer_ || NextLayer_->TransportType() != Preview::Transmission::Type::Udp)
            {
                co_return Error::Unsupported;
            }
            const auto NextPacketId = static_cast<std::uint32_t>(PacketId_ + 1);
            const auto Wire = BuildUdp(UdpFrameInput{SessionId_, NextPacketId, &Target, Payload});
            if (Wire.empty())
            {
                co_return Error::BadAddress;
            }
            PacketId_ = NextPacketId;
            if (co_await SendBytes(Wire))
            {
                co_return Error::IoError;
            }
            co_return Error::None;
        }

        /**
         * @brief 接收一个 UDP 数据报（UDP 数据面）
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
            if (!NextLayer_ || NextLayer_->TransportType() != Preview::Transmission::Type::Udp)
            {
                co_return Error::Unsupported;
            }
            std::array<std::uint8_t, 64 * 1024> Datagram{};
            const auto Part = co_await NextLayer_->ReadSome(
                AsBytes(std::span<std::uint8_t>(Datagram)));
            const auto N = Part.Bytes;
            if (Part.Failure.Failed())
            {
                co_return Error::IoError;
            }
            if (N == 0)
            {
                co_return Error::UnexpectedEof;
            }
            if (N > Datagram.size())
            {
                co_return Error::BadLength;
            }
            Message MessageValue;
            std::size_t Consumed = 0;
            auto ParseError = Parse(
                std::span<const std::uint8_t>(Datagram.data(), N),
                MessageValue,
                Consumed);
            if (ParseError == Error::None && Consumed != N)
            {
                ParseError = Error::BadMessage;
            }
            if (ParseError != Error::None)
            {
                co_return ParseError;
            }
            if (MessageValue.Type != Message::Kind::Udp)
            {
                co_return Error::BadMessage;
            }
            Target = MessageValue.dst;
            Payload.assign(MessageValue.payload.begin(), MessageValue.payload.end());
            co_return Error::None;
        }

        /**
         * @brief 透传读取（握手后数据面为裸流）
         * @details executor 已在原域；未握手或底层缺失时交付一次 NotOpen。
         */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Preview::Protocols::StartPartialRead(
                Preview::Protocols::PartialReadInput<Conn>{Owner(), Buffer, Executor()},
                std::move(Handler));
        }

        /**
         * @brief 透传写入（握手后数据面为裸流）
         */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Preview::Protocols::StartPartialWrite(
                Preview::Protocols::PartialWriteInput<Conn>{Owner(), Buffer, Executor()},
                std::move(Handler));
        }

        /**
         * @brief 真实写半关闭转交底层载体；反向读取仍然可用。
         */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Preview::Transport::Detail::PostResult(
                    Executor(),
                    std::move(Handler),
                    Preview::IoResult{0, Preview::Fault::FromNative(make_error_code(Error::NotOpen))});
                return;
            }
            NextLayer_->WriteShutdown(std::move(Handler));
        }

        /**
         * @brief 清除握手状态并交付底层关闭
         * @return 命令接管成功；实际退出由 Activity()->Drain() 另行等待。
         */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Handshaken_ = false;
            if (!NextLayer_)
            {
                return {};
            }
            return NextLayer_->Close();
        }

        /**
         * @brief 可重复取消底层挂起操作
         * @return 命令接管成功只表示取消请求已排入原 executor，不宣称已经关闭。
         */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            if (!NextLayer_)
            {
                return {};
            }
            return NextLayer_->Cancel();
        }

        /**
         * @brief 数据面部分读取实现，由正式前门复用
         * @param Buffer 目标缓冲区；借用期限到本次 completion 返回，不复制。
         * @return 本次字节数和 typed failure；借用缓冲仅在 completion 返回前有效。
         */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer)
            -> Net::awaitable<Preview::IoResult>
        {
            co_await DispatchToExecutor();
            if (!NextLayer_ || !Handshaken_)
            {
                co_return Preview::IoResult{0, Preview::Fault::FromNative(make_error_code(Error::NotOpen))};
            }
            co_return co_await NextLayer_->ReadSome(Buffer);
        }

        /** @brief 数据面部分写入实现，由正式前门复用；保留底层短写事实。 */
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
            -> Net::awaitable<Preview::IoResult>
        {
            co_await DispatchToExecutor();
            if (!NextLayer_ || !Handshaken_)
            {
                co_return Preview::IoResult{0, Preview::Fault::FromNative(make_error_code(Error::NotOpen))};
            }
            co_return co_await NextLayer_->WriteSome(Buffer);
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
        /** @brief 完成交付前的 owner 借用；存活由本次传输预约与调用者共同保证。 */
        [[nodiscard]] auto Owner() -> std::shared_ptr<Conn>
        {
            return std::static_pointer_cast<Conn>(Transmission::shared_from_this());
        }
        [[nodiscard]] auto DispatchToExecutor() -> Net::awaitable<void>
        {
            if (NextLayer_)
            {
                co_await Net::dispatch(NextLayer_->Executor(), Net::use_awaitable);
            }
        }

        /**
         * @brief 读取一帧（Kind + [Id] + 地址 + 载荷）
         * @param MessageValue 输出消息
         * @return 错误码
         * @details 帧无长度字段：精确分段读取头部（Kind/Id/地址），
         * 剩余一次读为载荷。
         */
        [[nodiscard]] auto ReadFrame(Message &MessageValue) -> Net::awaitable<Error>
        {
            return Detail::ReadFrame(NextLayer_, MessageValue);
        }

        /**
         * @brief 精确读取指定字节数
         * @param Dst 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         */
        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> Dst) -> Net::awaitable<bool>
        {
            return Detail::ReadExact(NextLayer_, Dst);
        }

        /**
         * @brief 发送全部字节
         * @param Data 数据
         * @return true = 失败
         */
        [[nodiscard]] auto SendBytes(std::span<const std::uint8_t> Data) const -> Net::awaitable<bool>
        {
            return Detail::SendBytes(NextLayer_, Data);
        }

        SharedTransmission NextLayer_; ///< 底层传输（独占所有权）
        std::string Password_;           ///< 认证密码
        Preview::SharedAuthenticator AuthOwner_{}; ///< 认证器共享所有权
        Preview::Account::AccountLease AuthLease_{}; ///< 协议认证租约
        Preview::AccountId AccountId_{};             ///< typed 账户身份
        std::string Identity_{};                     ///< 非敏感身份文本
        Address Target_;                 ///< TCP 目标地址（握手后）
        Message Parsed_{};               ///< 服务端握手解析结果
        std::uint32_t SessionId_{0};    ///< UDP 会话 ID（测试简化：固定 0）
        std::uint32_t PacketId_{0};     ///< UDP 包 ID（逐包自增）
        bool Handshaken_{false};         ///< 握手完成标志
        Memory Mem_; ///< 会话级内存竞技场（热路径零释放分配）
    };


    /// 流连接共享指针
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Hysteria2
