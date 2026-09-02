/**
 * @file Conn.hpp
 * @brief Hysteria2 会话连接对象（Transmission 装饰器）
 * @details 将底层传输包装为 Hysteria2 连接：
 * 1. WriteHandshake / ReadHandshake：客户端发认证帧（HTTP/3
 *    HEADERS 风格）与 TCP 目标帧；服务端解析校验（简化：不严格
 *    校验认证内容）
 * 2. 隧道：async_read_some / async_write_some 透传 TCP 帧载荷
 * 3. UDP 数据面：AsyncSendDatagram / AsyncReceiveDatagram
 *    逐帧编解码（Codec.hpp 纯函数），目标地址随帧携带
 * @note 与 hysteria2.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Memory/Pointer.hpp>
#include <preview/Protocols/Common/Address.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Hysteria2/Codec.hpp>
#include <preview/Protocols/Hysteria2/Types.hpp>

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
    class Conn : public Preview::Transmission, public std::enable_shared_from_this<Conn<Memory>>
    {
    public:
        /**
         * @brief 构造函数
         * @param upstream 底层传输（所有权移交）
         * @param password 认证密码
         */
        explicit Conn(SharedTransmission upstream, std::string password,
                      const Preview::Authenticator *Auth = nullptr)
            : NextLayer_(std::move(upstream)), Password_(std::move(password)), Auth_(Auth)
        {
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return NextLayer_->Executor();
        }

        /**
         * @brief 客户端握手：发认证帧 + TCP 目标帧
         * @param Target 目标地址
         * @return 错误码
         * @details 认证帧（MakeAuthRequest）后紧跟 TCP 帧
         * （目标 + 空载荷），对齐 sing-hysteria2 客户端行为。
         */
        [[nodiscard]] auto WriteHandshake(const Address &Target) -> net::awaitable<Error>
        {
            const auto Auth = MakeAuthRequest(Password_);
            if (co_await SendBytes(AsU8Span(Auth)))
            {
                co_return Error::IoError;
            }
            const auto Tcp = BuildTcp(Target, {});
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
        [[nodiscard]] auto ReadHandshake() -> net::awaitable<std::pair<Error, Message>>
        {
            // 1. 认证帧：HTTP/3 HEADERS 类型和长度均为 varint，随后是 QPACK 头块。
            std::array<std::uint8_t, 1> AuthType{};
            if (co_await ReadExact(std::span<std::uint8_t>(AuthType)))
            {
                co_return std::pair{Error::IoError, Message{}};
            }
            if (AuthType[0] != static_cast<std::uint8_t>(Http3::FrameHeaders))
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
            if (AuthLenSize > 1 && co_await ReadExact(std::span<std::uint8_t>(AuthLenBytes).subspan(1, AuthLenSize - 1)))
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
            Http3::AuthRequest AuthRequest(Preview::Memory::CurrentResource());
            if (!Http3::ParseAuthRequest(AuthBody, AuthRequest, Preview::Memory::CurrentResource()))
            {
                co_return std::pair{Error::BadAuth, Message{}};
            }
            const std::string Credential(AuthRequest.Auth.data(), AuthRequest.Auth.size());
            bool Ok;
            if (Auth_)
            {
                Ok = Auth_->Check("", Credential).Ok;
            }
            else
            {
                Ok = (Credential == Password_);
            }
            if (!Ok)
            {
                co_return std::pair{Error::BadAuth, Message{}};
            }

            // 2. TCP 目标帧
            Message msg;
            auto Err = co_await ReadFrame(msg);
            if (Err != Error::None)
            {
                co_return std::pair{Err, Message{}};
            }
            if (msg.Type != Message::Kind::Tcp)
            {
                co_return std::pair{Error::NotSupported, Message{}};
            }
            Target_ = msg.dst;
            Parsed_ = msg;
            Handshaken_ = true;
            co_return std::pair{Error::None, std::move(msg)};
        }

        /**
         * @brief 获取服务端握手解析的消息
         */
        [[nodiscard]] auto Parsed() const -> const Message &
        {
            return Parsed_;
        }

        /**
         * @brief 发送一个 UDP 数据报（UDP 数据面）
         * @param Target 目标地址（帧内携带）
         * @param payload 载荷
         * @return 错误码
         * @details 逐帧编解码（BuildUdp），Session/packet Id 递增。
         */
        [[nodiscard]] auto AsyncSendDatagram(const Address &Target, std::span<const std::uint8_t> payload)
            -> net::awaitable<Error>
        {
            if (!Handshaken_)
            {
                co_return Error::NotOpen;
            }
            if (!NextLayer_ || NextLayer_->TransportType() != Preview::Transmission::Type::Udp)
            {
                co_return Error::NotSupported;
            }
            const auto Wire = BuildUdp(UdpFrameInput{SessionId_, ++PacketId_, &Target, payload});
            if (co_await SendBytes(Wire))
            {
                co_return Error::IoError;
            }
            co_return Error::None;
        }

        /**
         * @brief 接收一个 UDP 数据报（UDP 数据面）
         * @param Target 输出目标地址
         * @param payload 输出载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncReceiveDatagram(Address &Target, std::vector<std::uint8_t> &payload)
            -> net::awaitable<Error>
        {
            if (!Handshaken_)
            {
                co_return Error::NotOpen;
            }
            if (!NextLayer_ || NextLayer_->TransportType() != Preview::Transmission::Type::Udp)
            {
                co_return Error::NotSupported;
            }
            std::array<std::uint8_t, 64 * 1024> Datagram{};
            std::error_code ec;
            const auto N = co_await NextLayer_->async_read_some(
                AsBytes(std::span<std::uint8_t>(Datagram)), ec);
            if (ec)
            {
                co_return Error::IoError;
            }
            if (N == 0)
            {
                co_return Error::UnexpectedEof;
            }
            Message msg;
            std::size_t Consumed = 0;
            auto Err = Parse(std::span<const std::uint8_t>(Datagram.data(), N), msg, Consumed);
            if (Err == Error::None && Consumed != N)
            {
                Err = Error::BadMessage;
            }
            if (Err != Error::None)
            {
                co_return Err;
            }
            if (msg.Type != Message::Kind::Udp)
            {
                co_return Error::BadMessage;
            }
            Target = msg.dst;
            payload.assign(msg.payload.begin(), msg.payload.end());
            co_return Error::None;
        }

        /**
         * @brief 透传读取（握手后数据面为裸流）
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (!Handshaken_)
            {
                ec = make_error_code(Error::NotOpen);
                co_return 0;
            }
            co_return co_await NextLayer_->async_read_some(Buffer, ec);
        }

        /**
         * @brief 透传写入（握手后数据面为裸流）
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (!Handshaken_)
            {
                ec = make_error_code(Error::NotOpen);
                co_return 0;
            }
            co_return co_await NextLayer_->async_write_some(Buffer, ec);
        }

        /**
         * @brief 关闭底层传输
         */
        void Close() override
        {
            NextLayer_->Close();
        }

        /**
         * @brief 取消挂起操作
         */
        void Cancel() override
        {
            NextLayer_->Cancel();
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
         * @brief 会话是否有效（已握手且底层存在）
         * @return 有效返回 true
         */
        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            return NextLayer_ != nullptr && Handshaken_;
        }

        /**
         * @brief 获取底层传输引用（非拥有）
         * @return 底层传输
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
        /**
         * @brief 读取一帧（Kind + [Id] + 地址 + 载荷）
         * @param msg 输出消息
         * @return 错误码
         * @details 帧无长度字段：精确分段读取头部（Kind/Id/地址），
         * 剩余一次读为载荷。
         */
        [[nodiscard]] auto ReadFrame(Message &msg) -> net::awaitable<Error>
        {
            std::array<std::uint8_t, 1> Kind{};
            if (co_await ReadExact(std::span<std::uint8_t>(Kind)))
            {
                co_return Error::UnexpectedEof;
            }
            msg.Type = static_cast<Message::Kind>(Kind[0]);
            if (msg.Type == Message::Kind::Udp)
            {
                std::array<std::uint8_t, 8> ids{};
                if (co_await ReadExact(std::span<std::uint8_t>(ids)))
                {
                    co_return Error::UnexpectedEof;
                }

                msg.SessionId =
                    static_cast<std::uint32_t>(ids[0]) | static_cast<std::uint32_t>(ids[1]) << 8 |
                    static_cast<std::uint32_t>(ids[2]) << 16 | static_cast<std::uint32_t>(ids[3]) << 24;
                msg.PacketId = static_cast<std::uint32_t>(ids[4]) | static_cast<std::uint32_t>(ids[5]) << 8 |
                                static_cast<std::uint32_t>(ids[6]) << 16 |
                                static_cast<std::uint32_t>(ids[7]) << 24;
            }
            // 地址体：ATYP(1) + ADDR + PORT(2)
            std::array<std::uint8_t, 1> atyp{};
            if (co_await ReadExact(std::span<std::uint8_t>(atyp)))
            {
                co_return Error::UnexpectedEof;
            }
            msg.dst.Type = static_cast<AddressType>(atyp[0]);
            auto Err = co_await ReadAddressBody(msg.dst);
            if (Err != Error::None)
            {
                co_return Err;
            }
            std::array<std::uint8_t, 2> port{};
            if (co_await ReadExact(std::span<std::uint8_t>(port)))
            {
                co_return Error::UnexpectedEof;
            }
            msg.dst.Port = static_cast<std::uint16_t>(port[0]) << 8 | port[1];
            if (msg.Type != Message::Kind::Udp)
            {
                co_return Error::None;
            }
            // 载荷：剩余一次读（帧边界由调用方约定）
            std::array<std::uint8_t, 512> chunk{};
            std::error_code ec;
            const auto N =
                co_await NextLayer_->async_read_some(AsBytes(std::span<std::uint8_t>(chunk)), ec);
            if (ec)
            {
                co_return Error::IoError;
            }
            msg.payload.assign(chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(N));
            co_return Error::None;
        }

        /**
         * @brief 精确读取指定字节数
         * @param dst 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         */
        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> dst) -> net::awaitable<bool>
        {
            std::size_t Done = 0;
            while (Done < dst.size())
            {
                std::error_code ec;
                const auto N = co_await NextLayer_->async_read_some(AsBytes(dst.subspan(Done)), ec);
                if (ec || N == 0)
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
        [[nodiscard]] auto SendBytes(std::span<const std::uint8_t> Data) const -> net::awaitable<bool>
        {
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                std::error_code ec;
                const auto N = co_await NextLayer_->async_write_some(AsBytes(Data.subspan(Done)), ec);
                if (ec || N == 0)
                {
                    co_return true;
                }
                Done += N;
            }
            co_return false;
        }

        /**
         * @brief 读取地址体（ATYP 已由调用方解析）
         * @param addr 输出地址
         * @return 错误码
         * @note 转发层：统一实现见 Protocol/common::ReadAddressBody
         */
        [[nodiscard]] auto ReadAddressBody(Address &addr) -> net::awaitable<Error>
        {
            return Preview::Protocol::Common::ReadAddressBody(
                addr, [this](std::span<std::uint8_t> dst) -> net::awaitable<bool> { return ReadExact(dst); });
        }

        SharedTransmission NextLayer_; ///< 底层传输（独占所有权）
        std::string Password_;           ///< 认证密码
        const Preview::Authenticator *Auth_{nullptr}; ///< 认证器（非拥有）
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
