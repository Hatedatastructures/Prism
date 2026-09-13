/**
 * @file Conn.hpp
 * @brief WebSocket 会话连接对象（Transmission 装饰器）
 * @details 将底层传输包装为 WebSocket 连接（对齐 mihomo transport/ws）：
 * 1. WriteHandshake / ReadHandshake：HTTP 升级握手
 *    （Sec-WebSocket-Key/Accept 交换）
 * 2. 数据面：帧编解码（Codec.hpp 纯函数），本类负责帧边界恢复
 * @note 与 ws.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <openssl/rand.h>

#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Foundation/Memory/Pointer.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Ws/Codec.hpp>
#include <preview/Protocols/Ws/Types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace Preview::Ws
{

    /**
     * @class Conn
     * @brief WebSocket 会话连接（Transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后数据面
     * 为帧边界恢复后的裸流。
     * @tparam Memory 会话内存策略（默认 8KB Arena；可注入自定义策略）
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Conn : public Preview::Transmission,
                 public std::enable_shared_from_this<Conn<Memory>>
    {
    public:
        /// 单个 WebSocket 数据帧的最大载荷，避免恶意长度触发无界分配。
        static constexpr std::size_t MaxFramePayload = 16 * 1024 * 1024;

        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using MemoryType = Memory;
        /**
         * @brief 构造函数
         * @param Upstream 底层传输（所有权移交）
         * @param Client 是否为客户端视角（客户端帧必须掩码）
         */
        explicit Conn(SharedTransmission Upstream, bool Client = false)
            : NextLayer_(std::move(Upstream)), Client_(Client)
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
         * @brief 客户端握手：发送 Upgrade 请求并等待 101 响应
         * @param Key Sec-WebSocket-Key（base64 24 字符）
         * @param Host 目标主机
         * @return 错误码；bad_auth = Accept 不匹配
         */
        [[nodiscard]] auto WriteHandshake(
            std::string_view Key,
            std::string_view Host) -> Net::awaitable<Error>
        {
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }
            const auto KeyValue = std::string(Key);
            const auto HostValue = std::string(Host);
            Handshaken_ = false;
            Closed_ = false;
            CloseSent_ = false;
            Accept_.clear();
            RxPayload_.clear();
            RxOffset_ = 0;
            FragmentOpcode_.reset();
            FragmentPayload_.clear();
            PendingWire_.clear();
            PendingOffset_ = 0;
            std::string Header;
            Header.reserve(128 + HostValue.size() + KeyValue.size());
            Header += "GET / HTTP/1.1\r\n";
            Header += "Host: " + HostValue + "\r\n";
            Header += "Upgrade: websocket\r\n";
            Header += "Connection: Upgrade\r\n";
            Header += "Sec-WebSocket-Key: " + KeyValue + "\r\n";
            Header += "Sec-WebSocket-Version: 13\r\n";
            Header += "\r\n";
            std::error_code SendError;
            if (co_await SendBytes(AsU8Span(Header), SendError))
                co_return Error::IoError;

            // 等待 101 响应并校验 Accept
            std::array<std::uint8_t, 256> ResponseChunk{};
            std::string Response;
            for (int I = 0; I < 16; ++I)
            {
                std::error_code ErrorCode;
                const auto N = co_await NextLayer_->async_read_some(
                    AsBytes(std::span<std::uint8_t>(ResponseChunk)),
                    ErrorCode);
                if (ErrorCode || N == 0)
                    break;
                if (N > ResponseChunk.size())
                    co_return Error::BadLength;
                Response.append(reinterpret_cast<const char *>(ResponseChunk.data()), N);
                if (Response.find("\r\n\r\n") != std::string::npos)
                    break;
            }
            const auto HeaderEnd = Response.find("\r\n\r\n");
            const auto StatusEnd = Response.find("\r\n");
            if (HeaderEnd == std::string::npos || StatusEnd == std::string::npos ||
                !IsStatus101(std::string_view(Response).substr(0, StatusEnd)))
                co_return Error::BadMagic;
            const auto Expected = ComputeAccept(KeyValue);
            const auto Accept = HeaderValue(Response, "Sec-WebSocket-Accept");
            if (!Accept || *Accept != Expected)
                co_return Error::BadAuth;
            PreserveHandshakeTail(Response, HeaderEnd + 4);
            Accept_ = Expected;
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 服务端握手：解析 Upgrade 请求并回复 Accept
         * @param Key 输出客户端 Sec-WebSocket-Key
         * @return 错误码；bad_magic = 非 Upgrade 请求
         */
        [[nodiscard]] auto ReadHandshake(std::string &Key) -> Net::awaitable<Error>
        {
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }
            Handshaken_ = false;
            Closed_ = false;
            CloseSent_ = false;
            Accept_.clear();
            RxPayload_.clear();
            RxOffset_ = 0;
            FragmentOpcode_.reset();
            FragmentPayload_.clear();
            PendingWire_.clear();
            PendingOffset_ = 0;
            std::array<std::uint8_t, 256> Chunk{};
            std::string Header;
            for (int I = 0; I < 16; ++I)
            {
                std::error_code ErrorCode;
                const auto N = co_await NextLayer_->async_read_some(
                    AsBytes(std::span<std::uint8_t>(Chunk)),
                    ErrorCode);
                if (ErrorCode || N == 0)
                    break;
                if (N > Chunk.size())
                    co_return Error::BadLength;
                Header.append(reinterpret_cast<const char *>(Chunk.data()), N);
                if (Header.find("\r\n\r\n") != std::string::npos)
                    break;
            }
            const auto HeaderEnd = Header.find("\r\n\r\n");
            const auto RequestEnd = Header.find("\r\n");
            if (HeaderEnd == std::string::npos || RequestEnd == std::string::npos ||
                !IsGetRequest(std::string_view(Header).substr(0, RequestEnd)))
                co_return Error::BadMagic;

            const auto Upgrade = HeaderValue(Header, "Upgrade");
            const auto Connection = HeaderValue(Header, "Connection");
            const auto KeyHeader = HeaderValue(Header, "Sec-WebSocket-Key");
            const auto Version = HeaderValue(Header, "Sec-WebSocket-Version");
            if (!Upgrade || !ContainsToken(*Upgrade, "websocket") || !Connection ||
                !ContainsToken(*Connection, "upgrade") || !KeyHeader || KeyHeader->empty() ||
                !Version || *Version != "13")
                co_return Error::BadMagic;
            Key = std::string(*KeyHeader);

            const auto Accept = ComputeAccept(Key);
            std::string Response = "HTTP/1.1 101 Switching Protocols\r\n";
            Response += "Upgrade: websocket\r\n";
            Response += "Connection: Upgrade\r\n";
            Response += "Sec-WebSocket-Accept: " + Accept + "\r\n";
            Response += "\r\n";
            std::error_code SendError;
            if (co_await SendBytes(AsU8Span(Response), SendError))
                co_return Error::IoError;
            PreserveHandshakeTail(Header, HeaderEnd + 4);
            Accept_ = Accept;
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 读取 WebSocket 数据帧载荷
         * @details 对调用方暴露裸字节；帧头、掩码和控制帧在本层处理。
         */
        [[nodiscard]] auto async_read_some(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            if (!Handshaken_ || Closed_ || !NextLayer_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            ErrorCode.clear();
            if (Buffer.empty())
            {
                co_return 0;
            }

            while (true)
            {
                if (RxOffset_ < RxPayload_.size())
                {
                    const auto Count = (std::min)(Buffer.size(), RxPayload_.size() - RxOffset_);
                    std::memcpy(Buffer.data(), RxPayload_.data() + RxOffset_, Count);
                    RxOffset_ += Count;
                    if (RxOffset_ == RxPayload_.size())
                    {
                        RxPayload_.clear();
                        RxOffset_ = 0;
                    }
                    co_return Count;
                }

                RxPayload_.clear();
                RxOffset_ = 0;
                if (!co_await ReadNextDataFrame(ErrorCode))
                {
                    co_return 0;
                }
            }
        }

        /**
         * @brief 写入一个客户端或服务端二进制数据帧
         */
        [[nodiscard]] auto async_write_some(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            if (!Handshaken_ || Closed_ || !NextLayer_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            ErrorCode.clear();
            if (Buffer.empty())
            {
                co_return 0;
            }
            if (Buffer.size() > MaxFramePayload)
            {
                ErrorCode = make_error_code(Error::BadLength);
                co_return 0;
            }
            if (co_await SendFrame(Opcode::Binary, Buffer, ErrorCode))
            {
                Closed_ = true;
                NextLayer_->Close();
                co_return 0;
            }
            co_return Buffer.size();
        }

        /**
         * @brief 关闭底层传输
         */
        auto Close() -> void override
        {
            Closed_ = true;
            Handshaken_ = false;
            FragmentOpcode_.reset();
            FragmentPayload_.clear();
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
            Closed_ = true;
            Handshaken_ = false;
            return std::move(NextLayer_);
        }

        /**
         * @brief 获取 Sec-WebSocket-Accept（握手后有效）
         */
        [[nodiscard]] auto Accept() const -> const std::string &
        {
            return Accept_;
        }

    private:
        /**
         * @brief 发送全部字节
         * @param Data 数据
         * @return true = 失败
         */
        [[nodiscard]] auto SendBytes(
            std::span<const std::uint8_t> Data,
            std::error_code &ErrorCode) -> Net::awaitable<bool>
        {
            ErrorCode.clear();
            if (!NextLayer_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return true;
            }
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                std::error_code WriteError;
                const auto N = co_await NextLayer_->async_write_some(
                    AsBytes(Data.subspan(Done)), WriteError);
                if (WriteError)
                {
                    ErrorCode = WriteError;
                    co_return true;
                }
                if (N == 0 || N > Data.size() - Done)
                {
                    ErrorCode = make_error_code(Error::BrokenPipe);
                    co_return true;
                }
                Done += N;
            }
            co_return false;
        }

        /**
         * @brief 从底层传输读取固定长度字节，优先消费握手后的回注数据。
         */
        [[nodiscard]] auto ReadExact(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<bool>
        {
            if (!NextLayer_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return false;
            }
            std::size_t Done = 0;
            while (Done < Buffer.size())
            {
                if (PendingOffset_ < PendingWire_.size())
                {
                    const auto Count = (std::min)(Buffer.size() - Done,
                                                   PendingWire_.size() - PendingOffset_);
                    std::memcpy(Buffer.data() + Done, PendingWire_.data() + PendingOffset_, Count);
                    PendingOffset_ += Count;
                    Done += Count;
                    if (PendingOffset_ == PendingWire_.size())
                    {
                        PendingWire_.clear();
                        PendingOffset_ = 0;
                    }
                    continue;
                }

                std::error_code ReadError;
                const auto Count = co_await NextLayer_->async_read_some(Buffer.subspan(Done), ReadError);
                if (ReadError)
                {
                    ErrorCode = ReadError;
                    co_return false;
                }
                if (Count == 0)
                {
                    if (Done != 0)
                    {
                        ErrorCode = make_error_code(Error::UnexpectedEof);
                    }
                    co_return false;
                }
                if (Count > Buffer.size() - Done)
                {
                    ErrorCode = make_error_code(Error::BrokenPipe);
                    co_return false;
                }
                Done += Count;
            }
            co_return true;
        }

        /**
         * @brief 读取并校验下一帧；控制帧在本函数内处理。
         */
        [[nodiscard]] auto ReadNextDataFrame(std::error_code &ErrorCode) -> Net::awaitable<bool>
        {
            while (true)
            {
                std::array<std::byte, 14> HeaderBytes{};
                if (!co_await ReadExact(std::span<std::byte>(HeaderBytes).first(2), ErrorCode))
                {
                    Closed_ = true;
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
                if (!co_await ReadExact(
                        std::span<std::byte>(HeaderBytes).subspan(2, HeaderLength - 2),
                        ErrorCode))
                {
                    Closed_ = true;
                    co_return false;
                }

                FrameHeader Header;
                if (!ParseFrameHeader(std::span<const std::byte>(HeaderBytes).first(HeaderLength), Header) ||
                    !ValidFrame(Header, Head0))
                {
                    ErrorCode = make_error_code(Error::BadMessage);
                    Closed_ = true;
                    NextLayer_->Close();
                    co_return false;
                }

                std::vector<std::byte> Payload(static_cast<std::size_t>(Header.PayloadLen));
                if (!Payload.empty() && !co_await ReadExact(Payload, ErrorCode))
                {
                    Closed_ = true;
                    co_return false;
                }
                if (Header.Masked)
                {
                    ApplyMask(Payload, Header.MaskKey);
                }
                const auto Op = static_cast<Opcode>(Header.Opcode);
                if (Op == Opcode::Close && !IsValidClosePayload(Payload))
                {
                    ErrorCode = make_error_code(Error::BadMessage);
                    Closed_ = true;
                    NextLayer_->Close();
                    co_return false;
                }

                switch (Op)
                {
                case Opcode::Ping:
                    if (co_await SendFrame(Opcode::Pong, Payload, ErrorCode))
                    {
                        Closed_ = true;
                        NextLayer_->Close();
                        co_return false;
                    }
                    continue;
                case Opcode::Pong:
                    continue;
                case Opcode::Close:
                    if (!CloseSent_)
                    {
                        CloseSent_ = true;
                        std::error_code CloseError;
                        (void)co_await SendFrame(Opcode::Close, Payload, CloseError);
                    }
                    Closed_ = true;
                    NextLayer_->Close();
                    co_return false;
                case Opcode::Text:
                case Opcode::Binary:
                    if (FragmentOpcode_)
                    {
                        ErrorCode = make_error_code(Error::BadMessage);
                        Closed_ = true;
                        NextLayer_->Close();
                        co_return false;
                    }
                    if (!Header.Fin)
                    {
                        FragmentOpcode_ = static_cast<Opcode>(Header.Opcode);
                        FragmentPayload_ = std::move(Payload);
                        continue;
                    }
                    if (Op == Opcode::Text && !IsValidUtf8(Payload))
                    {
                        ErrorCode = make_error_code(Error::BadMessage);
                        Closed_ = true;
                        NextLayer_->Close();
                        co_return false;
                    }
                    if (Payload.empty())
                    {
                        continue;
                    }
                    RxPayload_ = std::move(Payload);
                    RxOffset_ = 0;
                    co_return true;
                case Opcode::Continuation: {
                    if (!FragmentOpcode_)
                    {
                        ErrorCode = make_error_code(Error::BadMessage);
                        Closed_ = true;
                        NextLayer_->Close();
                        co_return false;
                    }
                    if (Payload.size() > MaxFramePayload - FragmentPayload_.size())
                    {
                        ErrorCode = make_error_code(Error::BadLength);
                        Closed_ = true;
                        NextLayer_->Close();
                        co_return false;
                    }
                    FragmentPayload_.insert(
                        FragmentPayload_.end(),
                        Payload.begin(),
                        Payload.end());
                    if (!Header.Fin)
                    {
                        continue;
                    }
                    const auto FragmentType = *FragmentOpcode_;
                    FragmentOpcode_.reset();
                    if (FragmentPayload_.empty())
                    {
                        continue;
                    }
                    if (FragmentType == Opcode::Text && !IsValidUtf8(FragmentPayload_))
                    {
                        ErrorCode = make_error_code(Error::BadMessage);
                        Closed_ = true;
                        NextLayer_->Close();
                        co_return false;
                    }
                    RxPayload_ = std::move(FragmentPayload_);
                    RxOffset_ = 0;
                    co_return true;
                }
                default:
                    ErrorCode = make_error_code(Error::BadMessage);
                    Closed_ = true;
                    NextLayer_->Close();
                    co_return false;
                }
            }
        }

        [[nodiscard]] auto ValidFrame(const FrameHeader &Header, std::uint8_t Head0) const noexcept -> bool
        {
            if ((Head0 & 0x70U) != 0 || Header.PayloadLen > MaxFramePayload)
            {
                return false;
            }
            const bool ExpectedMasked = !Client_;
            if (Header.Masked != ExpectedMasked)
            {
                return false;
            }
            const bool IsControl = Header.Opcode >= 0x8U;
            if (IsControl && (!Header.Fin || Header.PayloadLen > 125))
            {
                return false;
            }
            if (Header.Opcode != 0x0U && Header.Opcode != 0x1U && Header.Opcode != 0x2U && Header.Opcode != 0x8U &&
                Header.Opcode != 0x9U && Header.Opcode != 0xAU)
            {
                return false;
            }
            if (Header.Opcode == 0x8U && Header.PayloadLen == 1)
            {
                return false;
            }
            return true;
        }

        [[nodiscard]] static auto IsValidUtf8(std::span<const std::byte> Data) noexcept -> bool
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
                    const auto Byte = std::to_integer<std::uint8_t>(Data[Index + Offset]);
                    if (Byte < 0x80U || Byte > 0xBFU)
                    {
                        return false;
                    }
                }
                Index += Width;
            }
            return true;
        }

        [[nodiscard]] static auto IsValidClosePayload(std::span<const std::byte> Data) noexcept -> bool
        {
            if (Data.empty())
            {
                return true;
            }
            if (Data.size() == 1)
            {
                return false;
            }
            const auto Code = static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Data[0])) << 8 |
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

        /**
         * @brief 编码并完整发送一帧。
         */
        [[nodiscard]] auto SendFrame(
            Opcode Op,
            std::span<const std::byte> Payload,
            std::error_code &ErrorCode) -> Net::awaitable<bool>
        {
            ErrorCode.clear();
            const auto Length = Payload.size();
            if (Length > MaxFramePayload ||
                (static_cast<std::uint8_t>(Op) >= 0x8U && (Length > 125 || Op == Opcode::Continuation)))
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

            const bool Masked = Client_;
            std::size_t HeaderLength = 2;
            if (Length >= 126 && Length <= 0xFFFF)
            {
                HeaderLength += 2;
            }
            else if (Length > 0xFFFF)
            {
                HeaderLength += 8;
            }
            const auto MaskOffset = HeaderLength;
            if (Masked)
            {
                HeaderLength += MaskLen;
            }
            std::vector<std::byte> Frame(HeaderLength + Length);
            Frame[0] = static_cast<std::byte>(0x80U | static_cast<std::uint8_t>(Op));
            std::uint8_t MaskBit = 0;
            if (Masked)
            {
                MaskBit = 0x80U;
            }
            std::size_t Offset = 2;
            if (Length < 126)
            {
                Frame[1] = static_cast<std::byte>(MaskBit | Length);
            }
            else if (Length <= 0xFFFF)
            {
                Frame[1] = static_cast<std::byte>(MaskBit | 126U);
                Frame[Offset++] = static_cast<std::byte>((Length >> 8) & 0xFFU);
                Frame[Offset++] = static_cast<std::byte>(Length & 0xFFU);
            }
            else
            {
                Frame[1] = static_cast<std::byte>(MaskBit | 127U);
                for (int Index = 7; Index >= 0; --Index)
                {
                    Frame[Offset++] = static_cast<std::byte>((Length >> (8 * Index)) & 0xFFU);
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
                std::memcpy(Frame.data() + MaskOffset, Mask.data(), Mask.size());
                Offset = MaskOffset + MaskLen;
            }
            if (Length != 0)
            {
                std::memcpy(Frame.data() + Offset, Payload.data(), Length);
                if (Masked)
                {
                    ApplyMask(std::span<std::byte>(Frame).subspan(Offset, Length), Mask);
                }
            }
            co_return co_await SendBytes(AsU8Span(Frame), ErrorCode);
        }

        auto PreserveHandshakeTail(const std::string &Data, std::size_t Offset) -> void
        {
            PendingWire_.clear();
            PendingOffset_ = 0;
            if (Offset < Data.size())
            {
                const auto *Begin = reinterpret_cast<const std::byte *>(Data.data() + Offset);
                PendingWire_.assign(Begin, Begin + (Data.size() - Offset));
            }
        }

        [[nodiscard]] static auto Trim(std::string_view Value) noexcept -> std::string_view
        {
            while (!Value.empty() && (Value.front() == ' ' || Value.front() == '\t'))
            {
                Value.remove_prefix(1);
            }
            while (!Value.empty() && (Value.back() == ' ' || Value.back() == '\t'))
            {
                Value.remove_suffix(1);
            }
            return Value;
        }

        [[nodiscard]] static auto EqualInsensitive(std::string_view Left,
                                                   std::string_view Right) noexcept -> bool
        {
            if (Left.size() != Right.size())
            {
                return false;
            }
            for (std::size_t Index = 0; Index < Left.size(); ++Index)
            {
                const auto Lower = [](const char Character) noexcept -> char
                {
                    if (Character >= 'A' && Character <= 'Z')
                    {
                        return static_cast<char>(Character + ('a' - 'A'));
                    }
                    return Character;
                };
                if (Lower(Left[Index]) != Lower(Right[Index]))
                {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] static auto HeaderValue(std::string_view Header,
                                              std::string_view Name) noexcept
            -> std::optional<std::string_view>
        {
            std::size_t Begin = 0;
            while (Begin < Header.size())
            {
                const auto End = Header.find("\r\n", Begin);
                if (End == std::string_view::npos)
                {
                    return std::nullopt;
                }
                const auto Line = Header.substr(Begin, End - Begin);
                if (Line.empty())
                {
                    return std::nullopt;
                }
                const auto Colon = Line.find(':');
                if (Colon != std::string_view::npos &&
                    EqualInsensitive(Trim(Line.substr(0, Colon)), Name))
                {
                    return Trim(Line.substr(Colon + 1));
                }
                Begin = End + 2;
            }
            return std::nullopt;
        }

        [[nodiscard]] static auto ContainsToken(std::string_view Value,
                                                 std::string_view Token) noexcept -> bool
        {
            std::size_t Begin = 0;
            while (Begin <= Value.size())
            {
                const auto End = Value.find(',', Begin);
                std::string_view Part;
                if (End == std::string_view::npos)
                {
                    Part = Trim(Value.substr(Begin));
                }
                else
                {
                    Part = Trim(Value.substr(Begin, End - Begin));
                }
                if (EqualInsensitive(Part, Token))
                {
                    return true;
                }
                if (End == std::string_view::npos)
                {
                    break;
                }
                Begin = End + 1;
            }
            return false;
        }

        [[nodiscard]] static auto IsGetRequest(std::string_view RequestLine) noexcept -> bool
        {
            return RequestLine.starts_with("GET ") && RequestLine.ends_with(" HTTP/1.1");
        }

        [[nodiscard]] static auto IsStatus101(std::string_view StatusLine) noexcept -> bool
        {
            return StatusLine.starts_with("HTTP/1.1 ") && StatusLine.size() >= 12 &&
                   StatusLine.substr(9, 3) == "101" &&
                   (StatusLine.size() == 12 || StatusLine[12] == ' ');
        }

        SharedTransmission NextLayer_;  ///< 底层传输（独占所有权）
        std::string Accept_;              ///< Sec-WebSocket-Accept（握手后）
        bool Handshaken_{false};          ///< 握手完成标志
        bool Client_{false};               ///< 客户端帧掩码角色
        bool Closed_{false};               ///< 协议连接已收口
        bool CloseSent_{false};            ///< 已发送 close 响应
        std::vector<std::byte> RxPayload_; ///< 当前数据帧未消费载荷
        std::size_t RxOffset_{0};          ///< 当前载荷消费位置
        std::optional<Opcode> FragmentOpcode_; ///< 当前分片消息的起始类型
        std::vector<std::byte> FragmentPayload_; ///< 当前分片消息已累积载荷
        std::vector<std::byte> PendingWire_; ///< 握手读取时回注的后续帧
        std::size_t PendingOffset_{0};       ///< 回注数据消费位置
    };

    /// 流连接共享指针（默认内存策略）
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Ws
