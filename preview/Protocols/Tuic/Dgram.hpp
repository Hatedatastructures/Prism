/**
 * @file Dgram.hpp
 * @brief Tuic UDP 包连接对象（Transmission 装饰器）
 * @details UDP 数据面连接：将底层数据报传输（Unreliable，
 * 或任意包边界的传输）包装为 Tuic packet 帧编解码层。
 * 帧格式：[Ver 1B][Cmd 1B=0x07][AssocID 4B LE][PktID 4B LE]
 *          [ATYP 1B][ADDR][PORT 2B BE][payload]。
 * 目标地址内嵌于帧内，assoc/pkt Id 由本对象自增维护。
 * @note 继承 Preview::Transmission，构造函数传入底层传输（相当于
 * socket 收发的持有者），对齐 Conn 的装饰器链模式。
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
#include <utility>
#include <vector>

#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Foundation/Memory/Pointer.hpp>
#include <preview/Protocols/Common/Address.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Tuic/Codec.hpp>
#include <preview/Protocols/Tuic/Types.hpp>

namespace Preview::Tuic
{

    /**
     * @class Dgram
     * @brief Tuic UDP 包连接对象（Transmission 装饰器）
     * @details 持有底层数据报传输的独占所有权，对外暴露包级 API
     * （AsyncSendTo / AsyncReceiveFrom），内部完成 packet 帧
     * 编解码（Codec.hpp 纯函数）。由工厂（ConnectPacket /
     * AcceptPacket）创建。
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Dgram : public Preview::Transmission, public std::enable_shared_from_this<Dgram<Memory>>
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param upstream 底层数据报或已认证 QUIC 数据流（所有权移交）
         */
        explicit Dgram(SharedTransmission upstream)
            : NextLayer_(std::move(upstream))
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
         * @brief 传输类型（数据报）
         */
        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Udp;
        }

        /**
         * @brief 发送一个 UDP 数据报（WriteTo 语义）
         * @param dest 目标地址（帧内携带）
         * @param payload 载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncSendTo(const Address &dest, std::span<const std::uint8_t> payload)
            -> net::awaitable<Error>
        {
            Message msg;
            msg.Cmd = CmdPacket;
            msg.AssocId = AssocId_;
            msg.PktId = PacketId_++;
            msg.dst = dest;
            msg.payload.assign(reinterpret_cast<const char *>(payload.data()), payload.size());
            Build(msg, TxWire_);
            if (TxWire_.empty())
            {
                co_return Error::BadLength;
            }
            std::size_t Done = 0;
            while (Done < TxWire_.size())
            {
                std::error_code ec;
                const auto N = co_await NextLayer_->async_write_some(
                    AsBytes(std::span<const std::uint8_t>(TxWire_)).subspan(Done), ec);
                if (ec || N == 0)
                {
                    co_return Error::IoError;
                }
                Done += N;
            }
            co_return Error::None;
        }

        /**
         * @brief 接收一个 UDP 数据报（ReadFrom 语义）
         * @param src 输出源地址（帧内目标）
         * @param payload 输出载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncReceiveFrom(Address &src, std::vector<std::uint8_t> &payload)
            -> net::awaitable<Error>
        {
            if (NextLayer_ && NextLayer_->TransportType() == Preview::Transmission::Type::Udp)
            {
                std::array<std::uint8_t, 65536> Datagram{};
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
                Message Parsed{};
                std::size_t Consumed = 0;
                const auto Err = Parse(
                    std::span<const std::uint8_t>(Datagram.data(), N), Parsed, Consumed);
                if (Err != Error::None || Parsed.Cmd != CmdPacket || Consumed != N)
                {
                    co_return Err == Error::None ? Error::BadMessage : Err;
                }
                src = Parsed.dst;
                payload.assign(reinterpret_cast<const std::uint8_t *>(Parsed.payload.data()),
                               reinterpret_cast<const std::uint8_t *>(Parsed.payload.data()) +
                                   Parsed.payload.size());
                co_return Error::None;
            }

            // 1. Ver + Cmd + AssocID(2) + PktID(2) + FragTotal + FragId + Size(2)
            std::array<std::uint8_t, 10> head{};
            if (co_await ReadExact(std::span<std::uint8_t>(head)))
            {
                co_return Error::UnexpectedEof;
            }
            if (head[0] != ProtocolVersion || head[1] != CmdPacket)
            {
                co_return Error::BadMessage;
            }

            const auto FragTotal = head[6];
            const auto FragId = head[7];
            const auto Size = static_cast<std::size_t>(head[8]) << 8 | head[9];
            if (FragTotal == 0 || FragId >= FragTotal)
            {
                co_return Error::BadMessage;
            }

            // 2. ATYP + ADDR + PORT（ATYP 位于 10 字节头之后）
            std::array<std::uint8_t, 1> atyp{};
            if (co_await ReadExact(std::span<std::uint8_t>(atyp)))
            {
                co_return Error::UnexpectedEof;
            }
            src.Type = static_cast<AddressType>(atyp[0]);
            if (src.Type == AddressType::None)
            {
                if (FragId == 0)
                {
                    co_return Error::BadMessage;
                }
            }
            else
            {
                if (FragId != 0)
                {
                    co_return Error::BadMessage;
                }
                auto Err = co_await ReadAddressBody(src);
                if (Err != Error::None)
                {
                    co_return Err;
                }
                std::array<std::uint8_t, 2> port{};
                if (co_await ReadExact(std::span<std::uint8_t>(port)))
                {
                    co_return Error::UnexpectedEof;
                }
                src.Port = static_cast<std::uint16_t>(port[0]) << 8 | port[1];
            }

            // 3. 按 Size 精确读取，避免 TCP/QUIC stream 的 partial/coalesced write 破坏帧边界
            std::vector<std::uint8_t> chunk(Size);
            if (co_await ReadExact(std::span<std::uint8_t>(chunk)))
            {
                co_return Error::UnexpectedEof;
            }
            payload.assign(chunk.begin(), chunk.end());
            co_return Error::None;
        }

        /**
         * @brief 透传读取（底层数据报原样）
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await NextLayer_->async_read_some(Buffer, ec);
        }

        /**
         * @brief 透传写入（底层数据报原样）
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
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
         * @brief 获取底层传输
         */
        [[nodiscard]] auto Stream() const noexcept -> SharedTransmission
        {
            return NextLayer_;
        }

    private:
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

        SharedTransmission NextLayer_; ///< 底层数据报传输（独占所有权）
        std::uint16_t AssocId_{0};      ///< UDP 关联 ID
        std::uint16_t PacketId_{0};     ///< 下一个 UDP 包 ID（从 0 开始）
        Memory Mem_;                     ///< 会话内存策略（Arena，热路径零释放分配）
        typename Memory::template Buffer<std::uint8_t> TxWire_{Mem_.Arena()}; ///< 发送缓冲（Arena 复用，热路径零分配）
    };

    /// 包连接共享指针
    using SharedDgram = std::shared_ptr<Dgram<>>;

    static_assert(Preview::TransmissionLike<Dgram<>>);

} // namespace Preview::Tuic
