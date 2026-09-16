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
#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Protocols/Common/Address.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Tuic/Codec.hpp>
#include <Preview/Protocols/Tuic/Types.hpp>

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
         * @param Upstream 底层数据报或已认证 QUIC 数据流（所有权移交）
         */
        explicit Dgram(SharedTransmission Upstream)
            : NextLayer_(std::move(Upstream))
        {
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
         * @brief 发送一个 UDP 数据报（WriteTo 语义）
         * @param Destination 目标地址（帧内携带）
         * @param Payload 载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncSendTo(
            const Address &Destination,
            std::span<const std::uint8_t> Payload) -> Net::awaitable<Error>
        {
            co_await DispatchToExecutor();
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
            MessageValue.dst = Destination;
            MessageValue.payload.assign(
                reinterpret_cast<const char *>(Payload.data()),
                Payload.size());
            Build(MessageValue, TxWire_);
            if (TxWire_.empty())
            {
                co_return Error::BadAddress;
            }
            ++PacketId_;
            std::size_t Done = 0;
            while (Done < TxWire_.size())
            {
                std::error_code ErrorCode;
                const auto N = co_await NextLayer_->async_write_some(
                    AsBytes(std::span<const std::uint8_t>(TxWire_)).subspan(Done),
                    ErrorCode);
                if (ErrorCode || N == 0)
                {
                    co_return Error::IoError;
                }
                if (N > TxWire_.size() - Done)
                {
                    co_return Error::BadLength;
                }
                Done += N;
            }
            co_return Error::None;
        }

        /**
         * @brief 接收一个 UDP 数据报（ReadFrom 语义）
         * @param Source 输出源地址（帧内目标）
         * @param Payload 输出载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncReceiveFrom(
            Address &Source,
            std::vector<std::uint8_t> &Payload) -> Net::awaitable<Error>
        {
            co_await DispatchToExecutor();
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }
            if (NextLayer_ && NextLayer_->TransportType() == Preview::Transmission::Type::Udp)
            {
                std::array<std::uint8_t, 65536> Datagram{};
                std::error_code ErrorCode;
                const auto N = co_await NextLayer_->async_read_some(
                    AsBytes(std::span<std::uint8_t>(Datagram)),
                    ErrorCode);
                if (ErrorCode)
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
                Message Parsed{};
                std::size_t Consumed = 0;
                const auto Err = Parse(
                    std::span<const std::uint8_t>(Datagram.data(), N),
                    Parsed,
                    Consumed);
                if (Err != Error::None || Parsed.Cmd != CmdPacket || Consumed != N)
                {
                    if (Err != Error::None)
                    {
                        co_return Err;
                    }
                    co_return Error::BadMessage;
                }
                Source = Parsed.dst;
                Payload.assign(
                    reinterpret_cast<const std::uint8_t *>(Parsed.payload.data()),
                    reinterpret_cast<const std::uint8_t *>(Parsed.payload.data()) +
                        Parsed.payload.size());
                co_return Error::None;
            }

            // 1. Ver + Cmd + AssocID(2) + PktID(2) + FragTotal + FragId + Size(2)
            std::array<std::uint8_t, 10> Head{};
            if (co_await ReadExact(std::span<std::uint8_t>(Head)))
            {
                co_return Error::UnexpectedEof;
            }
            if (Head[0] != ProtocolVersion || Head[1] != CmdPacket)
            {
                co_return Error::BadMessage;
            }

            const auto FragTotal = Head[6];
            const auto FragId = Head[7];
            const auto Size = static_cast<std::size_t>(Head[8]) << 8 | Head[9];
            if (FragTotal == 0 || FragId >= FragTotal)
            {
                co_return Error::BadMessage;
            }

            // 2. ATYP + ADDR + PORT（ATYP 位于 10 字节头之后）
            std::array<std::uint8_t, 1> Atyp{};
            if (co_await ReadExact(std::span<std::uint8_t>(Atyp)))
            {
                co_return Error::UnexpectedEof;
            }
            Source.Type = static_cast<AddressType>(Atyp[0]);
            if (Source.Type == AddressType::None)
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
                const auto AddressError = co_await ReadAddressBody(Source);
                if (AddressError != Error::None)
                {
                    co_return AddressError;
                }
                std::array<std::uint8_t, 2> Port{};
                if (co_await ReadExact(std::span<std::uint8_t>(Port)))
                {
                    co_return Error::UnexpectedEof;
                }
                Source.Port = static_cast<std::uint16_t>(Port[0]) << 8 | Port[1];
            }

            // 3. 按 Size 精确读取，避免 TCP/QUIC stream 的 partial/coalesced write 破坏帧边界
            std::vector<std::uint8_t> Chunk(Size);
            if (co_await ReadExact(std::span<std::uint8_t>(Chunk)))
            {
                co_return Error::UnexpectedEof;
            }
            Payload.assign(Chunk.begin(), Chunk.end());
            co_return Error::None;
        }

        /**
         * @brief 透传读取（底层数据报原样）
         */
        [[nodiscard]] auto async_read_some(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            co_await DispatchToExecutor();
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
            co_await DispatchToExecutor();
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
         * @brief 获取底层传输共享引用
         * @return 底层传输共享指针
         */
        [[nodiscard]] auto Stream() const noexcept -> SharedTransmission
        {
            return NextLayer_;
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
