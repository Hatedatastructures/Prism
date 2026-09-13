/**
 * @file Codec.hpp
 * @brief Hysteria2 帧编解码（纯函数 + Serializer/Parser 类）
 * @details 帧格式（简化对齐 hysteria2 测试协议）：
 *          TCP：[Kind 1B][ATYP 1B][ADDR][PORT 2B BE][Payload]
 *          UDP：[Kind 1B][SessionID 4B LE][PacketID 4B LE][ATYP 1B][ADDR][PORT 2B BE][Payload]
 *          另含认证请求构造（MakeAuthRequest，HTTP/3 HEADERS 风格）
 *          与 Beast 风格 Serializer/Parser 类。
 * @note 参考 hysteria2 协议规范。
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
#include <string_view>
#include <system_error>
#include <vector>

#include <preview/Foundation/Error.hpp>
#include <preview/Protocols/Common/Address.hpp>
#include <preview/Protocols/Hysteria2/Types.hpp>
#include <preview/Protocols/Http3/Auth.hpp>

namespace Preview::Hysteria2
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
     * @brief 构造 TCP 帧
     */
    [[nodiscard]] inline auto BuildTcp(
        const Address &Destination,
        std::span<const std::uint8_t> Payload) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        Output.push_back(static_cast<std::uint8_t>(Message::Kind::Tcp));
        const auto AddressWire = EncodeAddress(Destination);
        if (AddressWire.empty())
        {
            return {};
        }
        Output.insert(Output.end(), AddressWire.begin(), AddressWire.end());
        Output.insert(Output.end(), Payload.begin(), Payload.end());
        return Output;
    }

    /**
     * @brief UDP 帧构造输入（SessionId + PacketId + dst + payload）
     */
    struct UdpFrameInput
    {
        std::uint32_t SessionId{0};           ///< 会话 ID
        std::uint32_t PacketId{0};            ///< 包 ID
        const Address *dst{nullptr};           ///< 目标地址
        std::span<const std::uint8_t> payload; ///< 载荷
    };

    /**
     * @brief 构造 UDP 帧（写入复用缓冲）
     * @param Input 输入
     * @param Output 输出缓冲（调用方持有复用，热路径零分配）
     */
    template <typename Alloc>
    inline auto BuildUdp(
        const UdpFrameInput &Input,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        Output.clear();
        if (!Input.dst)
        {
            return;
        }
        Output.push_back(static_cast<std::uint8_t>(Message::Kind::Udp));
        Output.push_back(static_cast<std::uint8_t>(Input.SessionId & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Input.SessionId >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Input.SessionId >> 16) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Input.SessionId >> 24) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(Input.PacketId & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Input.PacketId >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Input.PacketId >> 16) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Input.PacketId >> 24) & 0xFF));
        if (!EncodeAddress(*Input.dst, Output))
        {
            Output.clear();
            return;
        }
        Output.insert(Output.end(), Input.payload.begin(), Input.payload.end());
    }

    /**
     * @brief 构造 UDP 帧
     */
    [[nodiscard]] inline auto BuildUdp(const UdpFrameInput &Input) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        BuildUdp(Input, Output);
        return Output;
    }

    /**
     * @brief 解析帧（增量）
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
        if (Data.empty())
        {
            return Error::NeedMore;
        }
        Output.Type = static_cast<Message::Kind>(Data[0]);
        if (Output.Type != Message::Kind::Tcp && Output.Type != Message::Kind::Udp)
        {
            return Error::BadMessage;
        }
        std::size_t Off = 1;
        if (Output.Type == Message::Kind::Udp)
        {
            if (Data.size() - Off < 8)
            {
                return Error::NeedMore;
            }
            Output.SessionId = static_cast<std::uint32_t>(Data[Off]) |
                                static_cast<std::uint32_t>(Data[Off + 1]) << 8 |
                                static_cast<std::uint32_t>(Data[Off + 2]) << 16 |
                                static_cast<std::uint32_t>(Data[Off + 3]) << 24;
            Output.PacketId = static_cast<std::uint32_t>(Data[Off + 4]) |
                              static_cast<std::uint32_t>(Data[Off + 5]) << 8 |
                              static_cast<std::uint32_t>(Data[Off + 6]) << 16 |
                              static_cast<std::uint32_t>(Data[Off + 7]) << 24;
            Off += 8;
        }
        std::size_t AddrConsumed = 0;
        const auto Ec = ParseAddress(Data.subspan(Off), Output.dst, AddrConsumed);
        if (Ec != Error::None)
        {
            return Ec;
        }
        Off += AddrConsumed;
        Output.payload.assign(reinterpret_cast<const char *>(Data.data() + Off), Data.size() - Off);
        Consumed = Data.size();
        return Error::None;
    }

    // ==================== Auth（认证请求）合并 ====================

    /**
     * @brief 认证请求（HTTP/3 HEADERS 帧，首字节 0x01）
     * @param Password 认证密码
     * @return 认证请求字节；QPACK 或帧长度不足时返回空字符串
     */
    [[nodiscard]] inline auto MakeAuthRequest(std::string_view Password) -> std::string
    {
        // HTTP/3 HEADERS 帧：[Type varint=1][Length varint][QPACK 头块]
        std::array<std::uint8_t, 1024> Block{};
        const auto PrefixLength = Http3::Qpack::EncodePrefix(Block);
        if (PrefixLength == 0)
        {
            return {};
        }
        std::size_t BlockLength = PrefixLength;

        const auto MethodLength = Http3::Qpack::EncodeLiteral(
            ":method",
            "POST",
            std::span(Block).subspan(BlockLength));
        if (MethodLength == 0)
        {
            return {};
        }
        BlockLength += MethodLength;

        const auto SchemeLength = Http3::Qpack::EncodeLiteral(
            ":scheme",
            "https",
            std::span(Block).subspan(BlockLength));
        if (SchemeLength == 0)
        {
            return {};
        }
        BlockLength += SchemeLength;

        const auto AuthorityLength = Http3::Qpack::EncodeLiteral(
            ":authority",
            "hysteria2",
            std::span(Block).subspan(BlockLength));
        if (AuthorityLength == 0)
        {
            return {};
        }
        BlockLength += AuthorityLength;

        const auto PathLength = Http3::Qpack::EncodeLiteral(
            ":path",
            "/auth",
            std::span(Block).subspan(BlockLength));
        if (PathLength == 0)
        {
            return {};
        }
        BlockLength += PathLength;

        const auto AuthLength = Http3::Qpack::EncodeLiteral(
            "hysteria-auth",
            Password,
            std::span(Block).subspan(BlockLength));
        if (AuthLength == 0)
        {
            return {};
        }
        BlockLength += AuthLength;

        const auto ReceiveRateLength = Http3::Qpack::EncodeLiteral(
            "hysteria-cc-rx",
            "0",
            std::span(Block).subspan(BlockLength));
        if (ReceiveRateLength == 0)
        {
            return {};
        }
        BlockLength += ReceiveRateLength;

        std::array<std::byte, 1100> Frame{};
        std::size_t FrameLength = 0;
        if (!Http3::WriteFrameVarint(Frame, FrameLength, Http3::FrameHeaders) ||
            !Http3::WriteFrameVarint(Frame, FrameLength, BlockLength) ||
            Frame.size() < FrameLength + BlockLength)
        {
            return {};
        }
        for (std::size_t I = 0; I < BlockLength; ++I)
        {
            Frame[FrameLength + I] = static_cast<std::byte>(Block[I]);
        }
        return std::string(reinterpret_cast<const char *>(Frame.data()), FrameLength + BlockLength);
    }
    // ==================== Session.hpp（Serializer/Parser）合并 ====================

    /**
     * @brief Hysteria2 帧序列化器（对象 → wire）
     */
    class Serializer
    {
    public:
        /**
         * @brief 重置并绑定消息
         * @param MessageValue 待序列化消息
         */
        auto Reset(const Message &MessageValue) -> void
        {
            if (MessageValue.Type == Message::Kind::Udp)
            {
                Wire_ = BuildUdp(UdpFrameInput{
                    MessageValue.SessionId,
                    MessageValue.PacketId,
                    &MessageValue.dst,
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(MessageValue.payload.data()),
                        MessageValue.payload.size())});
            }
            else if (MessageValue.Type == Message::Kind::Tcp)
            {
                Wire_ = BuildTcp(
                    MessageValue.dst,
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(MessageValue.payload.data()),
                        MessageValue.payload.size()));
            }
            else
            {
                Wire_.clear();
            }
            Offset_ = 0;
        }

        /**
         * @brief 增量输出 wire 字节
         * @param Buffer 输出缓冲
         * @param Ec 输出错误码
         * @return 本次写入字节数
         */
        auto Get(
            boost::asio::mutable_buffer Buffer,
            std::error_code &Ec) -> std::size_t
        {
            Ec.clear();
            if (Buffer.size() == 0 || Offset_ >= Wire_.size())
            {
                return 0;
            }
            const auto RemainingBytes = Wire_.size() - Offset_;
            const auto Count = std::min(Buffer.size(), RemainingBytes);
            std::memcpy(Buffer.data(), Wire_.data() + Offset_, Count);
            Offset_ += Count;
            return Count;
        }

        /**
         * @brief 是否已全部输出
         * @return true = 全部输出完毕
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return Offset_ >= Wire_.size();
        }

        /**
         * @brief 剩余未输出字节数
         * @return 剩余未输出字节数
         */
        [[nodiscard]] auto Remaining() const -> std::size_t
        {
            if (Offset_ >= Wire_.size())
            {
                return 0;
            }
            return Wire_.size() - Offset_;
        }

    private:
        std::vector<std::uint8_t> Wire_;
        std::size_t Offset_{0};
    };

    /**
     * @brief Hysteria2 帧解析器（wire → 对象）
     */
    class Parser
    {
    public:
        /**
         * @brief 增量喂入 wire 字节
         * @param Buffer 输入缓冲
         * @param Ec 输出错误码
         * @return 本次消耗字节数
         */
        auto Put(
            boost::asio::const_buffer Buffer,
            std::error_code &Ec) -> std::size_t
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
         * @brief 解析结果（Done 后有效）
         * @return 消息引用（Done 后有效）
         */
        [[nodiscard]] auto Get() const -> const Message &
        {
            return Msg_;
        }

        /**
         * @brief 重置解析器
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

} // namespace Preview::Hysteria2
