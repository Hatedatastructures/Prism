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

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <common/Core/Error.hpp>
#include <common/Core/Protocol/Address.hpp>
#include <common/Protocols/Hysteria2/Types.hpp>

namespace Preview::Hysteria2
{

    /**
     * @brief 编码地址（ATYP + ADDR + PORT 2B BE，追加到缓冲）
     * @param addr 目标地址
     * @param out 输出缓冲（追加到末尾；调用方持有复用，热路径零分配）
     * @note 转发层：统一实现见 Protocol/common::EncodeAddress
     *       （原内联实现 ipv4 无校验存在越界写，统一实现修复为非法输入输出 0.0.0.0）
     */
    template <typename Alloc>
    inline auto EncodeAddress(const Address &addr, std::vector<std::uint8_t, Alloc> &out) -> void
    {
        Preview::Protocol::Common::EncodeAddress(addr, out);
    }

    /**
     * @brief 编码地址（ATYP + ADDR + PORT 2B BE）
     */
    [[nodiscard]] inline auto EncodeAddress(const Address &addr) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        EncodeAddress(addr, out);
        return out;
    }

    /**
     * @brief 解析地址（增量）
     * @param Data 输入
     * @param out 输出地址
     * @param consumed 输出消耗字节数
     * @return 错误码
     */
    [[nodiscard]] inline auto ParseAddress(std::span<const std::uint8_t> Data, Address &out,
                                            std::size_t &consumed) -> Error
    {
        if (Data.empty())
        {
            return Error::need_more;
        }
        out.Type = static_cast<AddressType>(Data[0]);
        std::size_t off = 1;
        switch (out.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() < off + 4 + 2)
            {
                return Error::need_more;
            }
            std::array<char, 16> buf{};
            std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u", Data[off], Data[off + 1], Data[off + 2],
                          Data[off + 3]);
            out.Host = buf.data();
            off += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() < off + 16 + 2)
            {
                return Error::need_more;
            }
            out.Host.assign(reinterpret_cast<const char *>(Data.data() + off), 16);
            off += 16;
            break;
        }
        case AddressType::Domain:
        default: {
            if (off >= Data.size())
            {
                return Error::need_more;
            }
            const auto len = Data[off++];
            if (Data.size() < off + len + 2)
            {
                return Error::need_more;
            }
            out.Host.assign(reinterpret_cast<const char *>(Data.data() + off), len);
            off += len;
            break;
        }
        }
        out.Port = static_cast<std::uint16_t>(Data[off]) << 8 | Data[off + 1];
        consumed = off + 2;
        return Error::none;
    }

    /**
     * @brief 构造 TCP 帧
     */
    [[nodiscard]] inline auto BuildTcp(const Address &dst, std::span<const std::uint8_t> payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.push_back(static_cast<std::uint8_t>(Message::Kind::Tcp));
        const auto addr = EncodeAddress(dst);
        out.insert(out.end(), addr.begin(), addr.end());
        out.insert(out.end(), payload.begin(), payload.end());
        return out;
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
     * @param in 输入
     * @param out 输出缓冲（调用方持有复用，热路径零分配）
     */
    template <typename Alloc>
    inline auto BuildUdp(const UdpFrameInput &in, std::vector<std::uint8_t, Alloc> &out) -> void
    {
        out.clear();
        if (!in.dst)
        {
            return;
        }
        out.push_back(static_cast<std::uint8_t>(Message::Kind::udp));
        out.push_back(static_cast<std::uint8_t>(in.SessionId & 0xFF));
        out.push_back(static_cast<std::uint8_t>((in.SessionId >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((in.SessionId >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((in.SessionId >> 24) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(in.PacketId & 0xFF));
        out.push_back(static_cast<std::uint8_t>((in.PacketId >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((in.PacketId >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((in.PacketId >> 24) & 0xFF));
        EncodeAddress(*in.dst, out);
        out.insert(out.end(), in.payload.begin(), in.payload.end());
    }

    /**
     * @brief 构造 UDP 帧
     */
    [[nodiscard]] inline auto BuildUdp(const UdpFrameInput &in) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        BuildUdp(in, out);
        return out;
    }

    /**
     * @brief 解析帧（增量）
     * @param Data 输入
     * @param out 输出消息
     * @param consumed 输出消耗字节数
     * @return 错误码
     */
    [[nodiscard]] inline auto Parse(std::span<const std::uint8_t> Data, Message &out, std::size_t &consumed)
        -> Error
    {
        if (Data.size() < 1)
        {
            return Error::need_more;
        }
        out.Type = static_cast<Message::Kind>(Data[0]);
        std::size_t off = 1;
        if (out.Type == Message::Kind::udp)
        {
            if (Data.size() < off + 8)
            {
                return Error::need_more;
            }
            out.SessionId = static_cast<std::uint32_t>(Data[off]) |
                             static_cast<std::uint32_t>(Data[off + 1]) << 8 |
                             static_cast<std::uint32_t>(Data[off + 2]) << 16 |
                             static_cast<std::uint32_t>(Data[off + 3]) << 24;
            out.PacketId = static_cast<std::uint32_t>(Data[off + 4]) |
                            static_cast<std::uint32_t>(Data[off + 5]) << 8 |
                            static_cast<std::uint32_t>(Data[off + 6]) << 16 |
                            static_cast<std::uint32_t>(Data[off + 7]) << 24;
            off += 8;
        }
        std::size_t AddrConsumed = 0;
        const auto ec = ParseAddress(Data.subspan(off), out.dst, AddrConsumed);
        if (ec != Error::none)
        {
            return ec;
        }
        off += AddrConsumed;
        out.payload.assign(reinterpret_cast<const char *>(Data.data() + off), Data.size() - off);
        consumed = Data.size();
        return Error::none;
    }

    // ==================== Auth（认证请求）合并 ====================

    /**
     * @brief 认证请求（HTTP/3 HEADERS 帧，首字节 0x01）
     * @param password 认证密码
     * @return 认证请求字节
     */
    [[nodiscard]] inline auto MakeAuthRequest(std::string_view password) -> std::string
    {
        // QUIC HEADERS 帧：[Type 0x01][Length varint][HTTP/3 头块]
        // 简化头块：:Method POST、:Path /Auth、authorization: <password>
        std::string payload = "POST /Auth HTTP/1.1\r\n";
        payload += "Host: hysteria2\r\n";
        payload += "Authorization: " + std::string(password) + "\r\n";
        payload += "\r\n";
        std::string out;
        out.push_back(static_cast<char>(0x01));           // HEADERS 帧类型
        out.push_back(static_cast<char>(payload.size())); // 长度（简化 1 字节）
        out += payload;
        return out;
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
         * @param msg 待序列化消息
         */
        auto Reset(const Message &msg) -> void
        {
            if (msg.Type == Message::Kind::udp)
            {
                wire_ = BuildUdp(UdpFrameInput{
                    msg.SessionId, msg.PacketId, &msg.dst,
                    std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(msg.payload.data()),
                                                  msg.payload.size())});
            }
            else
            {
                wire_ = BuildTcp(msg.dst, std::span<const std::uint8_t>(
                                               reinterpret_cast<const std::uint8_t *>(msg.payload.data()),
                                               msg.payload.size()));
            }
            offset_ = 0;
        }

        /**
         * @brief 增量输出 wire 字节
         * @param Buffer 输出缓冲
         * @param ec 输出错误码
         * @return 本次写入字节数
         */
        auto Get(boost::asio::mutable_buffer Buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto space = Buffer.size();
            const auto remain = wire_.size() - offset_;
            const auto n = std::min(space, remain);
            std::memcpy(Buffer.data(), wire_.data() + offset_, n);
            offset_ += n;
            return n;
        }

        /**
         * @brief 是否已全部输出
         * @return true = 全部输出完毕
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return offset_ >= wire_.size();
        }

        /**
         * @brief 剩余未输出字节数
         * @return 剩余未输出字节数
         */
        [[nodiscard]] auto Remaining() const -> std::size_t
        {
            return wire_.size() - offset_;
        }

    private:
        std::vector<std::uint8_t> wire_;
        std::size_t offset_{0};
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
         * @param ec 输出错误码
         * @return 本次消耗字节数
         */
        auto Put(boost::asio::const_buffer Buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto Data = std::span<const std::uint8_t>(static_cast<const std::uint8_t *>(Buffer.data()),
                                                            Buffer.size());
            buf_.insert(buf_.end(), Data.begin(), Data.end());
            std::size_t consumed = 0;
            const auto err = Parse(buf_, msg_, consumed);
            if (err == Error::need_more)
            {
                ec = make_error_code(Error::need_more);
                return 0;
            }
            if (err != Error::none)
            {
                ec = make_error_code(err);
                return 0;
            }
            done_ = true;
            return consumed;
        }

        /**
         * @brief 是否解析完成
         * @return true = 解析完成
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return done_;
        }

        /**
         * @brief 解析结果（Done 后有效）
         * @return 消息引用（Done 后有效）
         */
        [[nodiscard]] auto Get() const -> const Message &
        {
            return msg_;
        }

        /**
         * @brief 重置解析器
         */
        auto Reset() -> void
        {
            buf_.clear();
            msg_ = Message{};
            done_ = false;
        }

    private:
        std::vector<std::uint8_t> buf_;
        Message msg_{};
        bool done_{false};
    };

} // namespace Preview::Hysteria2
