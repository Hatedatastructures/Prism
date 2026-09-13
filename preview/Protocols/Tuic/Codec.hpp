/**
 * @file Codec.hpp
 * @brief TUIC 帧编解码（纯函数，零状态 + Serializer/Parser 类）
 * @details 帧格式（TUIC v5）：
 *          Authenticate：[Ver 1B][Cmd 1B][UUID 16B][TOKEN 32B]
 *          Connect：[Ver 1B][Cmd 1B][ATYP][ADDR][PORT 2B BE]
 *          Packet：[Ver 1B][Cmd 1B][AssocID 2B BE][PktID 2B BE]
 *                  [FragTotal 1B][FragID 1B][Size 2B BE][ATYP][ADDR][PORT][Data]
 *          Dissociate：[Ver 1B][Cmd 1B][AssocID 2B BE]
 *          Heartbeat：[Ver 1B][Cmd 1B]
 * @note 提供 Serializer/Parser 类（Beast 风格）与纯函数。
 */

#pragma once

#include <boost/asio/buffer.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <preview/Foundation/Error.hpp>
#include <preview/Protocols/Common/Address.hpp>
#include <preview/Protocols/Tuic/Types.hpp>

namespace Preview::Tuic
{

    /**
     * @brief 编码地址（ATYP + ADDR + PORT 2B BE，追加到缓冲）
     * @param Addr 目标地址
     * @param Output 输出缓冲（追加到末尾；调用方持有复用，热路径零分配）
     * @note 转发层：统一实现见 Protocol/common::EncodeAddress
     *       （原内联实现 ipv4 无校验存在越界写，统一实现修复为非法输入输出 0.0.0.0）
     */
    template <typename Alloc>
    inline auto EncodeAddress(
        const Address &Addr,
        std::vector<std::uint8_t, Alloc> &Output) -> bool
    {
        return Preview::Protocol::Common::EncodeAddress(Addr, Output);
    }

    /**
     * @brief 编码地址（ATYP + ADDR + PORT 2B BE）
     */
    [[nodiscard]] inline auto EncodeAddress(const Address &Addr) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        if (EncodeAddress(Addr, Output))
        {
            return Output;
        }
        return {};
    }

    /**
     * @brief 解析地址（增量）
     * @param Data 输入
     * @param Output 输出地址
     * @param Consumed 输出消耗字节数
     * @return 错误码
     */
    [[nodiscard]] inline auto ParseAddress(
        std::span<const std::uint8_t> Data,
        Address &Output,
        std::size_t &Consumed) -> Error
    {
        Consumed = 0;
        if (Data.empty())
        {
            return Error::NeedMore;
        }
        Output.Type = static_cast<AddressType>(Data[0]);
        std::size_t Off = 1;
        switch (Output.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() - Off < 4 + 2)
            {
                return Error::NeedMore;
            }
            std::array<char, 16> Buffer{};
            std::snprintf(
                Buffer.data(),
                Buffer.size(),
                "%u.%u.%u.%u",
                static_cast<unsigned int>(Data[Off]),
                static_cast<unsigned int>(Data[Off + 1]),
                static_cast<unsigned int>(Data[Off + 2]),
                static_cast<unsigned int>(Data[Off + 3]));
            Output.Host = Buffer.data();
            Off += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() - Off < 16 + 2)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), 16);
            Off += 16;
            break;
        }
        case AddressType::Domain: {
            if (Off >= Data.size())
            {
                return Error::NeedMore;
            }
            const auto Len = Data[Off++];
            if (Len == 0)
            {
                return Error::BadMessage;
            }
            if (Data.size() - Off < static_cast<std::size_t>(Len) + 2)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), Len);
            Off += Len;
            break;
        }
        default:
            return Error::BadMessage;
        }
        Output.Port = static_cast<std::uint16_t>(Data[Off]) << 8 | Data[Off + 1];
        Consumed = Off + 2;
        return Error::None;
    }

    /**
     * @brief 构造消息帧（写入复用缓冲）
     * @param MessageValue 消息
     * @param Output 输出缓冲（调用方持有复用，热路径零分配）
     */
    template <typename Alloc>
    inline auto Build(
        const Message &MessageValue,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        Output.clear();
        Output.reserve(
            2 + 8 + 1 + MessageValue.dst.Host.size() + 2 + MessageValue.payload.size());
        Output.push_back(ProtocolVersion);
        Output.push_back(MessageValue.Cmd);
        if (MessageValue.Cmd == CmdAuthenticate)
        {
            Output.clear();
            return;
        }
        if (MessageValue.Cmd == CmdConnect)
        {
            if (!EncodeAddress(MessageValue.dst, Output))
            {
                Output.clear();
                return;
            }
        }
        else if (MessageValue.Cmd == CmdPacket)
        {
            if (MessageValue.FragTotal == 0 ||
                MessageValue.FragId >= MessageValue.FragTotal ||
                MessageValue.payload.size() > 0xFFFF)
            {
                Output.clear();
                return;
            }
            Output.push_back(static_cast<std::uint8_t>((MessageValue.AssocId >> 8) & 0xFF));
            Output.push_back(static_cast<std::uint8_t>(MessageValue.AssocId & 0xFF));
            Output.push_back(static_cast<std::uint8_t>((MessageValue.PktId >> 8) & 0xFF));
            Output.push_back(static_cast<std::uint8_t>(MessageValue.PktId & 0xFF));
            Output.push_back(MessageValue.FragTotal);
            Output.push_back(MessageValue.FragId);
            Output.push_back(static_cast<std::uint8_t>((MessageValue.payload.size() >> 8) & 0xFF));
            Output.push_back(static_cast<std::uint8_t>(MessageValue.payload.size() & 0xFF));
            if (MessageValue.FragId == 0)
            {
                if (!EncodeAddress(MessageValue.dst, Output))
                {
                    Output.clear();
                    return;
                }
            }
            else
            {
                Output.push_back(static_cast<std::uint8_t>(AddressType::None));
            }
            Output.insert(Output.end(), MessageValue.payload.begin(), MessageValue.payload.end());
        }
        else if (MessageValue.Cmd == CmdDissociate)
        {
            Output.push_back(static_cast<std::uint8_t>((MessageValue.AssocId >> 8) & 0xFF));
            Output.push_back(static_cast<std::uint8_t>(MessageValue.AssocId & 0xFF));
        }
        else if (MessageValue.Cmd != CmdHeartbeat)
        {
            Output.clear();
        }
    }

    /**
     * @brief 构造消息帧
     * @param MessageValue 消息
     * @return wire 字节
     */
    [[nodiscard]] inline auto Build(const Message &MessageValue) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        Build(MessageValue, Output);
        return Output;
    }

    /**
     * @brief 解析消息帧（增量）
     * @param Data 输入
     * @param Output 输出消息
     * @param Consumed 输出消耗字节数
     * @return 错误码
     */
    [[nodiscard]] inline auto Parse(
        std::span<const std::uint8_t> Data,
        Message &Output,
        std::size_t &Consumed) -> Error
    {
        Consumed = 0;
        if (Data.size() < 2)
        {
            return Error::NeedMore;
        }
        if (Data[0] != ProtocolVersion)
        {
            return Error::BadMagic;
        }
        Output.Cmd = Data[1];
        std::size_t Off = 2;
        if (Output.Cmd == CmdAuthenticate)
        {
            return Error::BadMessage;
        }
        if (Output.Cmd == CmdPacket)
        {
            if (Data.size() - Off < 8)
            {
                return Error::NeedMore;
            }
            Output.AssocId = static_cast<std::uint16_t>(Data[Off]) << 8 | Data[Off + 1];
            Output.PktId = static_cast<std::uint16_t>(Data[Off + 2]) << 8 | Data[Off + 3];
            Output.FragTotal = Data[Off + 4];
            Output.FragId = Data[Off + 5];
            Output.Size = static_cast<std::uint16_t>(Data[Off + 6]) << 8 | Data[Off + 7];
            if (Output.FragTotal == 0 || Output.FragId >= Output.FragTotal)
            {
                return Error::BadMessage;
            }
            Off += 8;
        }
        else if (Output.Cmd == CmdDissociate)
        {
            if (Data.size() - Off < 2)
            {
                return Error::NeedMore;
            }
            Output.AssocId = static_cast<std::uint16_t>(Data[Off]) << 8 | Data[Off + 1];
            Consumed = Off + 2;
            return Error::None;
        }
        else if (Output.Cmd == CmdHeartbeat)
        {
            Consumed = Off;
            return Error::None;
        }
        else if (Output.Cmd != CmdConnect)
        {
            return Error::BadMessage;
        }
        if (Output.Cmd == CmdConnect)
        {
            std::size_t AddrConsumed = 0;
            const auto ErrorCode = ParseAddress(Data.subspan(Off), Output.dst, AddrConsumed);
            if (ErrorCode != Error::None)
            {
                return ErrorCode;
            }
            Off += AddrConsumed;
        }
        else
        {
            if (Data.size() - Off < 1)
            {
                return Error::NeedMore;
            }
            if (Data[Off] == static_cast<std::uint8_t>(AddressType::None))
            {
                if (Output.FragId == 0)
                {
                    return Error::BadMessage;
                }
                ++Off;
            }
            else
            {
                if (Output.FragId != 0)
                {
                    return Error::BadMessage;
                }
                std::size_t AddrConsumed = 0;
                const auto ErrorCode = ParseAddress(Data.subspan(Off), Output.dst, AddrConsumed);
                if (ErrorCode != Error::None)
                {
                    return ErrorCode;
                }
                Off += AddrConsumed;
            }
            if (Data.size() - Off < Output.Size)
            {
                return Error::NeedMore;
            }
            Output.payload.assign(reinterpret_cast<const char *>(Data.data() + Off), Output.Size);
            Consumed = Off + Output.Size;
            return Error::None;
        }
        Consumed = Data.size();
        return Error::None;
    }

    /**
     * @brief Tuic 帧序列化器（对象 → wire，Beast 风格）
     */
    class Serializer
    {
    public:
        /**
         * @brief 重置并绑定消息
         */
        auto Reset(const Message &MessageValue) -> void
        {
            Wire_ = Build(MessageValue);
            Offset_ = 0;
        }

        /**
         * @brief 增量输出
         */
        auto Get(boost::asio::mutable_buffer Buffer, std::error_code &Ec) -> std::size_t
        {
            Ec.clear();
            if (Offset_ >= Wire_.size() || Buffer.size() == 0)
            {
                return 0;
            }
            const auto N = std::min(Buffer.size(), Wire_.size() - Offset_);
            std::memcpy(Buffer.data(), Wire_.data() + Offset_, N);
            Offset_ += N;
            return N;
        }

        /**
         * @brief 是否已全部输出
         * @return true = 全部输出完毕
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return Offset_ >= Wire_.size();
        }

    private:
        std::vector<std::uint8_t> Wire_;
        std::size_t Offset_{0};
    };

    /**
     * @brief 构造 TUIC v5 独立 uni stream 认证帧
     */
    [[nodiscard]] inline auto BuildAuthenticate(
        const std::array<std::uint8_t, UuidLen> &Uuid,
        const std::array<std::uint8_t, TokenLen> &Token)
        -> std::array<std::uint8_t, AuthenticateFrameLen>
    {
        std::array<std::uint8_t, AuthenticateFrameLen> Out{};
        Out[0] = ProtocolVersion;
        Out[1] = CmdAuthenticate;
        std::memcpy(Out.data() + 2, Uuid.data(), UuidLen);
        std::memcpy(Out.data() + 2 + UuidLen, Token.data(), TokenLen);
        return Out;
    }

    /**
     * @brief 解析 TUIC v5 独立 uni stream 认证帧
     */
    [[nodiscard]] inline auto ParseAuthenticate(std::span<const std::uint8_t> Data,
                                                 AuthenticateFrame &Out, std::size_t &Consumed) -> Error
    {
        Consumed = 0;
        if (Data.size() < AuthenticateFrameLen)
        {
            return Error::NeedMore;
        }
        if (Data[0] != ProtocolVersion || Data[1] != CmdAuthenticate)
        {
            return Error::BadMagic;
        }
        std::memcpy(Out.Uuid.data(), Data.data() + 2, UuidLen);
        std::memcpy(Out.Token.data(), Data.data() + 2 + UuidLen, TokenLen);
        Consumed = AuthenticateFrameLen;
        return Error::None;
    }

    /**
     * @brief Tuic 帧解析器（wire → 对象，Beast 风格）
     */
    class Parser
    {
    public:
        /**
         * @brief 增量喂入
         */
        auto Put(boost::asio::const_buffer Buffer, std::error_code &Ec) -> std::size_t
        {
            Ec.clear();
            const auto Data = std::span<const std::uint8_t>(
                static_cast<const std::uint8_t *>(Buffer.data()),
                Buffer.size());
            const auto PreviousSize = Buf_.size();
            Buf_.insert(Buf_.end(), Data.begin(), Data.end());
            std::size_t Consumed = 0;
            const auto Err = Parse(Buf_, Msg_, Consumed);
            if (Err == Error::NeedMore)
            {
                Ec = make_error_code(Error::NeedMore);
                return 0;
            }
            if (Err != Error::None)
            {
                Ec = make_error_code(Err);
                return 0;
            }
            if (Consumed < PreviousSize)
            {
                Ec = make_error_code(Error::BadLength);
                return 0;
            }
            const auto ConsumedFromInput = Consumed - PreviousSize;
            if (ConsumedFromInput > Data.size())
            {
                Ec = make_error_code(Error::BadLength);
                return 0;
            }
            Done_ = true;
            return ConsumedFromInput;
        }

        /**
         * @brief 是否解析完成
         * @return true = 解析完成
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return Done_;
        }

        /**
         * @brief 解析结果
         * @return 消息引用（解析完成后调用）
         */
        [[nodiscard]] auto Get() const -> const Message &
        {
            return Msg_;
        }

        /**
         * @brief 重置
         */
        auto Reset() -> void
        {
            Buf_.clear();
            Msg_ = Message{};
            Done_ = false;
        }

    private:
        std::vector<std::uint8_t> Buf_;
        Message Msg_{};
        bool Done_{false};
    };

} // namespace Preview::Tuic
