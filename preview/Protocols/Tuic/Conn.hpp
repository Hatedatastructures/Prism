/**
 * @file Conn.hpp
 * @brief Tuic 会话连接对象（Transmission 装饰器）
 * @details 将底层传输包装为 Tuic 连接：
 * 1. WriteHandshake / ReadHandshake：客户端发 Connect 帧
 *    （目标地址）；服务端解析校验（简化：不做 UUID 认证）
 * 2. 隧道：async_read_some / async_write_some 透传 TCP 帧载荷
 * 3. UDP 数据面：AsyncSendDatagram / AsyncReceiveDatagram
 *    逐帧编解码（Codec.hpp 纯函数，packet 命令）
 * @note 与 tuic.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Memory/Pointer.hpp>
#include <preview/Protocols/Common/Address.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Tuic/Codec.hpp>
#include <preview/Protocols/Tuic/Types.hpp>

namespace Preview::Tuic
{

    /**
     * @class Conn
     * @brief Tuic 会话连接（Transmission 装饰器）
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
         * @param uuid 客户端 UUID（16 字节）
         */
        explicit Conn(SharedTransmission upstream, std::array<std::uint8_t, 16> uuid)
            : NextLayer_(std::move(upstream)), Uuid_(uuid)
        {
        }

        /**
         * @brief 在独立 uni stream 发送 TUIC v5 认证帧
         * @param AuthStream 已打开的 uni stream
         * @param Exporter 当前 TLS 会话 exporter
         * @param Password 用户密码（作为 exporter context）
         * @return 错误码
         */
        [[nodiscard]] auto WriteAuthentication(SharedTransmission AuthStream,
                                                const KeyingMaterialExporter &Exporter,
                                                std::string_view Password) -> net::awaitable<Error>
        {
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
            AuthStream->Close();
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
        [[nodiscard]] auto ReadAuthentication(SharedTransmission AuthStream,
                                               const KeyingMaterialExporter &Exporter,
                                               std::string_view Password) -> net::awaitable<Error>
        {
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
            if (ParseErr != Error::None || Consumed != Wire.size() || Frame.Uuid != Uuid_)
            {
                co_return Error::BadAuth;
            }
            std::array<std::uint8_t, TokenLen> Expected{};
            if (!Exporter(std::span<std::uint8_t>(Expected), std::span<const std::uint8_t>(Uuid_), Password))
            {
                co_return Error::KdfError;
            }
            if (!std::equal(Frame.Token.begin(), Frame.Token.end(), Expected.begin()))
            {
                co_return Error::BadAuth;
            }
            Authenticated_ = true;
            co_return Error::None;
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return NextLayer_->Executor();
        }

        /**
         * @brief 客户端握手：发 Connect 帧
         * @param Target 目标地址
         * @return 错误码
         */
        [[nodiscard]] auto WriteHandshake(const Address &Target) -> net::awaitable<Error>
        {
            if (!Authenticated_)
            {
                co_return Error::BadAuth;
            }
            Message msg;
            msg.Cmd = CmdConnect;
            msg.dst = Target;
            const auto Wire = Build(msg);
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
        [[nodiscard]] auto ReadHandshake() -> net::awaitable<std::pair<Error, Message>>
        {
            if (!Authenticated_)
            {
                co_return std::pair{Error::BadAuth, Message{}};
            }
            Message msg;
            auto Err = co_await ReadFrame(msg);
            if (Err != Error::None)
            {
                co_return std::pair{Err, Message{}};
            }
            if (msg.Cmd != CmdConnect)
            {
                co_return std::pair{Error::BadMessage, Message{}};
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
         * @brief 发送一个 UDP 数据报（packet 命令）
         * @param Target 目标地址（帧内携带）
         * @param payload 载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncSendDatagram(const Address &Target, std::span<const std::uint8_t> payload)
            -> net::awaitable<Error>
        {
            if (!Handshaken_)
            {
                co_return Error::NotOpen;
            }
            Message msg;
            msg.Cmd = CmdPacket;
            msg.AssocId = AssocId_;
            msg.PktId = PacketId_++;
            msg.dst = Target;
            msg.payload.assign(reinterpret_cast<const char *>(payload.data()), payload.size());
            const auto Wire = Build(msg);
            if (co_await SendBytes(NextLayer_, std::span<const std::uint8_t>(Wire)))
            {
                co_return Error::IoError;
            }
            co_return Error::None;
        }

        /**
         * @brief 接收一个 UDP 数据报（packet 命令）
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
            Message msg;
            auto Err = co_await ReadFrame(msg);
            if (Err != Error::None)
            {
                co_return Err;
            }
            if (msg.Cmd != CmdPacket)
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
         * @brief 读取一帧（Ver + Cmd + [Id] + [地址] + [载荷]）
         * @param msg 输出消息
         * @return 错误码
         * @details 帧无长度字段：精确分段读取头部，剩余一次读为
         * 载荷（packet 命令）。
         */
        [[nodiscard]] auto ReadFrame(Message &msg) -> net::awaitable<Error>
        {
            std::array<std::uint8_t, 2> head{};
            if (co_await ReadExact(std::span<std::uint8_t>(head)))
            {
                co_return Error::UnexpectedEof;
            }
            if (head[0] != ProtocolVersion)
            {
                co_return Error::BadMagic;
            }
            msg.Cmd = head[1];
            if (msg.Cmd == CmdPacket)
            {
                std::array<std::uint8_t, 8> Header{};
                if (co_await ReadExact(std::span<std::uint8_t>(Header)))
                {
                    co_return Error::UnexpectedEof;
                }
                msg.AssocId = static_cast<std::uint16_t>(Header[0]) << 8 | Header[1];
                msg.PktId = static_cast<std::uint16_t>(Header[2]) << 8 | Header[3];
                msg.FragTotal = Header[4];
                msg.FragId = Header[5];
                msg.Size = static_cast<std::uint16_t>(Header[6]) << 8 | Header[7];
                if (msg.FragTotal == 0 || msg.FragId >= msg.FragTotal)
                {
                    co_return Error::BadMessage;
                }
            }
            if (msg.Cmd == CmdConnect || msg.Cmd == CmdPacket)
            {
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
            }
            if (msg.Cmd == CmdPacket)
            {
                if (msg.FragId == 0)
                {
                    if (msg.dst.Type == AddressType::None)
                    {
                        co_return Error::BadMessage;
                    }
                }
                else if (msg.dst.Type != AddressType::None)
                {
                    co_return Error::BadMessage;
                }
                std::vector<std::uint8_t> Payload(msg.Size);
                if (co_await ReadExact(std::span<std::uint8_t>(Payload)))
                {
                    co_return Error::UnexpectedEof;
                }
                msg.payload.assign(Payload.begin(), Payload.end());
            }
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
        [[nodiscard]] static auto SendBytes(const SharedTransmission &Upstream,
                                            std::span<const std::uint8_t> Data) -> net::awaitable<bool>
        {
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                std::error_code ec;
                const auto N = co_await Upstream->async_write_some(AsBytes(Data.subspan(Done)), ec);
                if (ec || N == 0)
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
        [[nodiscard]] static auto ReadExactFrom(const SharedTransmission &Upstream,
                                                 std::span<std::uint8_t> Data) -> net::awaitable<bool>
        {
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                std::error_code ec;
                const auto N = co_await Upstream->async_read_some(AsBytes(Data.subspan(Done)), ec);
                if (ec || N == 0)
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
         * @param addr 输出地址
         * @return 错误码
         * @note 转发层：统一实现见 Protocol/common::ReadAddressBody
         */
        [[nodiscard]] auto ReadAddressBody(Address &addr) -> net::awaitable<Error>
        {
            return Preview::Protocol::Common::ReadAddressBody(
                addr, [this](std::span<std::uint8_t> dst) -> net::awaitable<bool> { return ReadExact(dst); });
        }

        SharedTransmission NextLayer_;      ///< 底层传输（独占所有权）
        std::array<std::uint8_t, 16> Uuid_{}; ///< 客户端 UUID（凭据）
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
