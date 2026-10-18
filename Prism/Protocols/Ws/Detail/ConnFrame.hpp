/**
 * @file ConnFrame.hpp
 * @brief WebSocket RFC 6455 帧、分片和控制帧 owner。
 * @details ConnFrame 负责帧头读取/编码、掩码、消息分片重组、
 *          UTF-8/Close payload 校验以及 ping/pong/close 控制语义。
 * @note 实例非线程安全，应在同一协程或线程内使用。
 */
#pragma once

#include <openssl/rand.h>

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Foundation/Memory/OwnedBytes.hpp>
#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Protocols/Ws/Detail/Codec.hpp>
#include <Prism/Protocols/Ws/Detail/ConnClose.hpp>
#include <Prism/Protocols/Ws/Detail/ConnSession.hpp>
#include <Prism/Protocols/Ws/Detail/ConnTransport.hpp>

namespace Prism::Ws::Detail
{

    namespace Net = boost::asio;

    /**
     * @class ConnFrame
     * @brief WebSocket 帧处理与分片消息重组 owner。
     * @tparam Memory 会话内存策略。
     */
    template <Prism::Memory::Restrict Memory>
    class ConnFrame final
    {
    private:
        struct MaskedFrame final
        {
            std::array<std::byte, 14> Header;
            std::size_t HeaderLength;
            std::span<const std::byte> Payload;
            std::array<std::uint8_t, MaskLen> Mask;
            Prism::Memory::OwnedBytes Scratch;
        };

    public:
        static constexpr std::size_t MaxFramePayload = 16 * 1024 * 1024;

        ConnFrame(
            ConnSession<Memory> &Session,
            ConnTransport<Memory> &Transport,
            ConnClose<Memory> &Close)
            : Session_(Session), Transport_(Transport), Close_(Close)
        {
        }

        ConnFrame(const ConnFrame &) = delete;
        auto operator=(const ConnFrame &) -> ConnFrame & = delete;

        auto Reset() -> void
        {
            FragmentOpcode_.reset();
            FragmentPayload_.clear();
        }

        /**
         * @brief 读取下一条可交付消息。
         * @param Payload 输出一条完整消息的载荷。
         * @param ErrorCode 输出错误码。
         * @return true 表示 Payload 已准备好。
         */
        [[nodiscard]] auto ReadNextDataFrame(
            std::vector<std::byte> &Payload,
            std::error_code &ErrorCode) -> Net::awaitable<bool>
        {
            while (true)
            {
                FrameHeader Header;
                if (!co_await ReadFrame(Payload, Header, ErrorCode))
                {
                    co_return false;
                }

                const auto Op = static_cast<Opcode>(Header.Opcode);
                if (Op == Opcode::Close && !IsValidClosePayload(Payload))
                {
                    ErrorCode = make_error_code(Error::BadMessage);
                    Terminate(ErrorCode);
                    co_return false;
                }

                switch (Op)
                {
                case Opcode::Ping:
                    if (co_await SendFrame(Opcode::Pong, Payload, ErrorCode))
                    {
                        Terminate(ErrorCode);
                        co_return false;
                    }
                    continue;
                case Opcode::Pong:
                    continue;
                case Opcode::Close:
                    if (!Close_.CloseSent())
                    {
                        Close_.MarkCloseSent();
                        if (co_await SendFrame(Opcode::Close, Payload, ErrorCode))
                        {
                            Terminate(ErrorCode);
                            co_return false;
                        }
                    }
                    Terminate(ErrorCode);
                    co_return false;
                case Opcode::Text:
                case Opcode::Binary:
                    if (FragmentOpcode_)
                    {
                        co_return ProtocolError(ErrorCode, Error::BadMessage);
                    }
                    if (!Header.Fin)
                    {
                        FragmentOpcode_ = Op;
                        FragmentPayload_ = std::move(Payload);
                        continue;
                    }
                    if (Op == Opcode::Text && !IsValidUtf8(Payload))
                    {
                        co_return ProtocolError(ErrorCode, Error::BadMessage);
                    }
                    if (Payload.empty())
                    {
                        continue;
                    }
                    co_return true;
                case Opcode::Continuation:
                    if (!FragmentOpcode_)
                    {
                        co_return ProtocolError(ErrorCode, Error::BadMessage);
                    }
                    if (Payload.size() > MaxFramePayload - FragmentPayload_.size())
                    {
                        co_return ProtocolError(ErrorCode, Error::BadLength);
                    }
                    FragmentPayload_.insert(
                        FragmentPayload_.end(), Payload.begin(), Payload.end());
                    if (!Header.Fin)
                    {
                        continue;
                    }
                    {
                        const auto FragmentType = *FragmentOpcode_;
                        FragmentOpcode_.reset();
                        if (FragmentPayload_.empty())
                        {
                            continue;
                        }
                        if (FragmentType == Opcode::Text &&
                            !IsValidUtf8(FragmentPayload_))
                        {
                            co_return ProtocolError(ErrorCode, Error::BadMessage);
                        }
                        Payload = std::move(FragmentPayload_);
                        FragmentPayload_.clear();
                        co_return true;
                    }
                default:
                    co_return ProtocolError(ErrorCode, Error::BadMessage);
                }
            }
        }

        /**
         * @brief 编码并完整发送一帧。
         * @return true 表示发送失败；池容量不足时保留原始资源错误。
         */
        [[nodiscard]] auto SendFrame(
            Opcode Op,
            std::span<const std::byte> Payload,
            std::error_code &ErrorCode) -> Net::awaitable<bool>
        {
            ErrorCode.clear();
            const auto Length = Payload.size();
            const auto OpValue = static_cast<std::uint8_t>(Op);
            if (Length > MaxFramePayload ||
                (OpValue >= 0x8U &&
                 (Length > 125 || Op == Opcode::Continuation)))
            {
                ErrorCode = make_error_code(Error::BadLength);
                co_return true;
            }
            if ((Op == Opcode::Text && !IsValidUtf8(Payload)) ||
                (Op == Opcode::Close && !IsValidClosePayload(Payload)))
            {
                ErrorCode = make_error_code(Error::BadMessage);
                co_return true;
            }

            auto Writer = co_await Session_.AcquireFrameWriter();
            if (!Writer)
            {
                ErrorCode = Prism::Fault::ToNative(Writer.error());
                co_return true;
            }
            auto Permit = std::move(*Writer);

            const bool Masked = Session_.IsClient();
            std::array<std::byte, 14> Header{};
            std::size_t HeaderLength = 2;
            Header[0] = static_cast<std::byte>(0x80U | OpValue);
            std::uint8_t MaskBit = 0;
            if (Masked)
            {
                MaskBit = 0x80U;
            }
            std::size_t Offset = 2;
            if (Length < 126)
            {
                Header[1] = static_cast<std::byte>(MaskBit | Length);
            }
            else if (Length <= 0xFFFF)
            {
                HeaderLength += 2;
                Header[1] = static_cast<std::byte>(MaskBit | 126U);
                Header[Offset++] = static_cast<std::byte>((Length >> 8) & 0xFFU);
                Header[Offset++] = static_cast<std::byte>(Length & 0xFFU);
            }
            else
            {
                HeaderLength += 8;
                Header[1] = static_cast<std::byte>(MaskBit | 127U);
                for (int Index = 7; Index >= 0; --Index)
                {
                    Header[Offset++] = static_cast<std::byte>(
                        (Length >> (8 * Index)) & 0xFFU);
                }
            }

            std::array<std::uint8_t, MaskLen> Mask{};
            if (Masked)
            {
                if (RAND_bytes(Mask.data(), static_cast<int>(Mask.size())) != 1)
                {
                    ErrorCode = make_error_code(Error::IoError);
                    co_return true;
                }
                std::memcpy(Header.data() + HeaderLength, Mask.data(), Mask.size());
                HeaderLength += MaskLen;
            }
            if (Length == 0)
            {
                const auto HeaderBytes = std::span<const std::byte>(
                    Header.data(), HeaderLength);
                const auto Sent = co_await Transport_.SendBytes(
                    AsU8Span(HeaderBytes));
                co_return SendFailed(Sent, ErrorCode);
            }
            if (!Masked)
            {
                const auto HeaderBytes = std::span<const std::byte>(
                    Header.data(), HeaderLength);
                const auto HeaderResult = co_await Transport_.SendBytes(
                    AsU8Span(HeaderBytes));
                if (SendFailed(HeaderResult, ErrorCode))
                {
                    co_return true;
                }
                const auto PayloadResult = co_await Transport_.SendBytes(
                    AsU8Span(Payload));
                co_return SendFailed(PayloadResult, ErrorCode);
            }
            co_return co_await SendMaskedFrame(
                MaskedFrame{Header, HeaderLength, Payload, Mask, {}}, ErrorCode);
        }
    private:
        /**
         * @brief 把帧写入的 typed 完成映射回 Transmission callback ABI。
         * @details Bytes 是 wire 进度；帧失败后 Conn 关闭连接，不将它伪报为应用 payload 进度。
         */
        [[nodiscard]] static auto SendFailed(
            const Prism::IoResult &Result,
            std::error_code &ErrorCode) noexcept -> bool
        {
            if (!Result.Failure.Failed())
            {
                ErrorCode.clear();
                return false;
            }
            ErrorCode = Prism::Fault::ToNative(Result.Failure);
            return true;
        }

        /**
         * @brief 先取得唯一掩码缓冲，再分块发送，避免资源拒绝后遗留半帧。
         * @param Frame 按值持有帧头、借用载荷、掩码和独占 scratch 租约。
         * @param ErrorCode 失败时接收原始池或传输错误。
         * @return true 表示发送失败。
         */
        [[nodiscard]] auto SendMaskedFrame(
            MaskedFrame Frame,
            std::error_code &ErrorCode) -> Net::awaitable<bool>
        {
            const auto &Bytes = Session_.Bytes();
            if (!Bytes)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return true;
            }
            const auto InitialSize = (std::min)(
                Frame.Payload.size(), Bytes->BlockSize());
            auto Lease = Bytes->TryAcquire(InitialSize);
            if (!Lease)
            {
                ErrorCode = Prism::Fault::ToNative(Lease.error());
                co_return true;
            }
            Frame.Scratch = std::move(*Lease);

            const auto HeaderBytes = std::span<const std::byte>(
                Frame.Header.data(), Frame.HeaderLength);
            const auto HeaderResult = co_await Transport_.SendBytes(
                AsU8Span(HeaderBytes));
            if (SendFailed(HeaderResult, ErrorCode))
            {
                co_return true;
            }
            std::size_t Offset = 0;
            while (Offset < Frame.Payload.size())
            {
                const auto Size = (std::min)(
                    Frame.Payload.size() - Offset, Frame.Scratch.Capacity());
                const auto Resized = Frame.Scratch.Resize(Size);
                if (!Resized)
                {
                    ErrorCode = Prism::Fault::ToNative(Resized.error());
                    co_return true;
                }
                auto Chunk = Frame.Scratch.WritableBytes();
                std::memcpy(
                    Chunk.data(), Frame.Payload.data() + Offset, Size);
                for (std::size_t Index = 0; Index < Size; ++Index)
                {
                    const auto MaskIndex = (Offset + Index) % MaskLen;
                    Chunk[Index] = static_cast<std::byte>(
                        static_cast<std::uint8_t>(Chunk[Index]) ^
                        Frame.Mask[MaskIndex]);
                }
                const auto Sent = co_await Transport_.SendBytes(
                    AsU8Span(Chunk));
                if (SendFailed(Sent, ErrorCode))
                {
                    co_return true;
                }
                Offset += Size;
            }
            co_return false;
        }
        [[nodiscard]] auto ReadFrame(
            std::vector<std::byte> &Payload,
            FrameHeader &Header,
            std::error_code &ErrorCode) -> Net::awaitable<bool>
        {
            Payload.clear();
            std::array<std::byte, 14> HeaderBytes{};
            if (!co_await Transport_.ReadExact(
                    std::span<std::byte>(HeaderBytes).first(2),
                    ErrorCode))
            {
                Close_.MarkClosed();
                co_return false;
            }

            const auto Head0 = std::to_integer<std::uint8_t>(HeaderBytes[0]);
            const auto Head1 = std::to_integer<std::uint8_t>(HeaderBytes[1]);
            const auto LengthCode = static_cast<std::uint8_t>(Head1 & 0x7FU);
            std::size_t HeaderLength = 2;
            if (LengthCode == 126)
            {
                HeaderLength += 2;
            }
            else if (LengthCode == 127)
            {
                HeaderLength += 8;
            }
            if ((Head1 & 0x80U) != 0)
            {
                HeaderLength += MaskLen;
            }
            if (!co_await Transport_.ReadExact(
                    std::span<std::byte>(HeaderBytes).subspan(2, HeaderLength - 2),
                    ErrorCode))
            {
                Close_.MarkClosed();
                co_return false;
            }
            if (!ParseFrameHeader(
                    std::span<const std::byte>(HeaderBytes).first(HeaderLength),
                    Header) ||
                !ValidFrame(Header, Head0))
            {
                ErrorCode = make_error_code(Error::BadMessage);
                Terminate(ErrorCode);
                co_return false;
            }

            Payload.resize(static_cast<std::size_t>(Header.PayloadLen));
            if (!Payload.empty() &&
                !co_await Transport_.ReadExact(
                    std::span<std::byte>(Payload), ErrorCode))
            {
                Close_.MarkClosed();
                co_return false;
            }
            if (Header.Masked)
            {
                ApplyMask(Payload, Header.MaskKey);
            }
            co_return true;
        }

        [[nodiscard]] auto ValidFrame(
            const FrameHeader &Header,
            std::uint8_t Head0) const noexcept -> bool
        {
            if ((Head0 & 0x70U) != 0 || Header.PayloadLen > MaxFramePayload)
            {
                return false;
            }
            if (Header.Masked != !Session_.IsClient())
            {
                return false;
            }
            const bool IsControl = Header.Opcode >= 0x8U;
            if (IsControl && (!Header.Fin || Header.PayloadLen > 125))
            {
                return false;
            }
            if (Header.Opcode != 0x0U && Header.Opcode != 0x1U &&
                Header.Opcode != 0x2U && Header.Opcode != 0x8U &&
                Header.Opcode != 0x9U && Header.Opcode != 0xAU)
            {
                return false;
            }
            return Header.Opcode != 0x8U || Header.PayloadLen != 1;
        }

        [[nodiscard]] static auto IsValidUtf8(
            std::span<const std::byte> Data) noexcept -> bool
        {
            std::size_t Index = 0;
            while (Index < Data.size())
            {
                const auto First = std::to_integer<std::uint8_t>(Data[Index]);
                if (First <= 0x7FU)
                {
                    ++Index;
                    continue;
                }
                std::size_t Width = 0;
                std::uint8_t SecondMin = 0x80U;
                std::uint8_t SecondMax = 0xBFU;
                if (First >= 0xC2U && First <= 0xDFU)
                {
                    Width = 2;
                }
                else if (First >= 0xE0U && First <= 0xEFU)
                {
                    Width = 3;
                    if (First == 0xE0U)
                    {
                        SecondMin = 0xA0U;
                    }
                    else if (First == 0xEDU)
                    {
                        SecondMax = 0x9FU;
                    }
                }
                else if (First >= 0xF0U && First <= 0xF4U)
                {
                    Width = 4;
                    if (First == 0xF0U)
                    {
                        SecondMin = 0x90U;
                    }
                    else if (First == 0xF4U)
                    {
                        SecondMax = 0x8FU;
                    }
                }
                else
                {
                    return false;
                }
                if (Data.size() - Index < Width)
                {
                    return false;
                }
                const auto Second = std::to_integer<std::uint8_t>(Data[Index + 1]);
                if (Second < SecondMin || Second > SecondMax)
                {
                    return false;
                }
                for (std::size_t Offset = 2; Offset < Width; ++Offset)
                {
                    const auto Byte = std::to_integer<std::uint8_t>(
                        Data[Index + Offset]);
                    if (Byte < 0x80U || Byte > 0xBFU)
                    {
                        return false;
                    }
                }
                Index += Width;
            }
            return true;
        }

        [[nodiscard]] static auto IsValidClosePayload(
            std::span<const std::byte> Data) noexcept -> bool
        {
            if (Data.empty())
            {
                return true;
            }
            if (Data.size() == 1)
            {
                return false;
            }
            const auto Code =
                static_cast<std::uint16_t>(
                    std::to_integer<std::uint8_t>(Data[0]))
                    << 8 |
                std::to_integer<std::uint8_t>(Data[1]);
            const bool StandardCode = Code >= 1000U && Code <= 1003U;
            const bool ProtocolCode = Code >= 1007U && Code <= 1011U;
            const bool ApplicationCode = Code >= 3000U && Code <= 4999U;
            if (!StandardCode && !ProtocolCode && !ApplicationCode)
            {
                return false;
            }
            return IsValidUtf8(Data.subspan(2));
        }

        [[nodiscard]] auto ProtocolError(
            std::error_code &ErrorCode,
            Error ErrorValue) -> bool
        {
            ErrorCode = make_error_code(ErrorValue);
            Terminate(ErrorCode);
            return false;
        }

        /** @brief 记录关闭命令失败；已有帧/传输错误作为首因保留。 */
        auto Terminate(std::error_code &ErrorCode) -> void
        {
            const auto Result = Close_.Terminate(false);
            if (!Result && !ErrorCode)
            {
                ErrorCode = Prism::Fault::ToNative(Result.error());
            }
        }

        ConnSession<Memory> &Session_;
        ConnTransport<Memory> &Transport_;
        ConnClose<Memory> &Close_;
        std::optional<Opcode> FragmentOpcode_;
        std::vector<std::byte> FragmentPayload_;
    };

} // namespace Prism::Ws::Detail
