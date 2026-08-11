/**
 * @file codec.hpp
 * @brief Hysteria2 帧编解码（纯函数，零状态）
 * @details 帧格式（简化对齐 hysteria2 测试协议）：
 *          TCP：[Kind 1B][ATYP 1B][ADDR][PORT 2B BE][Payload]
 *          UDP：[Kind 1B][SessionID 4B LE][PacketID 4B LE][ATYP 1B][ADDR][PORT 2B BE][Payload]
 * @note 提供 build/parse 纯函数，serializer/parser 类在 session 层。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/hysteria2/types.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

namespace psmtest::hysteria2
{

    /// @brief 编码地址（ATYP + ADDR + PORT 2B BE）
    [[nodiscard]] inline auto encode_address(const address &addr) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.push_back(static_cast<std::uint8_t>(addr.type));
        switch (addr.type)
        {
            case address_type::ipv4:
            {
                std::array<std::uint8_t, 4> ip{};
                std::size_t a = 0, p = 0;
                for (const char ch : addr.host)
                {
                    if (ch == '.')
                    {
                        ip[a++] = static_cast<std::uint8_t>(p);
                        p = 0;
                    }
                    else
                    {
                        p = p * 10 + static_cast<std::size_t>(ch - '0');
                    }
                }
                ip[a] = static_cast<std::uint8_t>(p);
                out.insert(out.end(), ip.begin(), ip.end());
                break;
            }
            case address_type::ipv6:
            {
                out.insert(out.end(), addr.host.begin(), addr.host.end());
                break;
            }
            case address_type::domain:
            default:
            {
                out.push_back(static_cast<std::uint8_t>(addr.host.size()));
                out.insert(out.end(), addr.host.begin(), addr.host.end());
                break;
            }
        }
        out.push_back(static_cast<std::uint8_t>((addr.port >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(addr.port & 0xFF));
        return out;
    }

    /// @brief 解析地址（增量）
    /// @param data 输入
    /// @param out 输出地址
    /// @param consumed 输出消耗字节数
    /// @return 错误码
    [[nodiscard]] inline auto parse_address(std::span<const std::uint8_t> data,
                                            address &out, std::size_t &consumed) -> error
    {
        if (data.empty())
            return error::need_more;
        out.type = static_cast<address_type>(data[0]);
        std::size_t off = 1;
        switch (out.type)
        {
            case address_type::ipv4:
            {
                if (data.size() < off + 4 + 2)
                    return error::need_more;
                std::array<char, 16> buf{};
                std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u",
                              data[off], data[off + 1], data[off + 2], data[off + 3]);
                out.host = buf.data();
                off += 4;
                break;
            }
            case address_type::ipv6:
            {
                if (data.size() < off + 16 + 2)
                    return error::need_more;
                out.host.assign(reinterpret_cast<const char *>(data.data() + off), 16);
                off += 16;
                break;
            }
            case address_type::domain:
            default:
            {
                if (off >= data.size())
                    return error::need_more;
                const auto len = data[off++];
                if (data.size() < off + len + 2)
                    return error::need_more;
                out.host.assign(reinterpret_cast<const char *>(data.data() + off), len);
                off += len;
                break;
            }
        }
        out.port = static_cast<std::uint16_t>(data[off]) << 8 | data[off + 1];
        consumed = off + 2;
        return error::none;
    }

    /// @brief 构造 TCP 帧
    [[nodiscard]] inline auto build_tcp(const address &dst, std::span<const std::uint8_t> payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.push_back(static_cast<std::uint8_t>(message::kind::tcp));
        const auto addr = encode_address(dst);
        out.insert(out.end(), addr.begin(), addr.end());
        out.insert(out.end(), payload.begin(), payload.end());
        return out;
    }

    /// @brief 构造 UDP 帧
    [[nodiscard]] inline auto build_udp(std::uint32_t session_id, std::uint32_t packet_id,
                                        const address &dst, std::span<const std::uint8_t> payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.push_back(static_cast<std::uint8_t>(message::kind::udp));
        out.push_back(static_cast<std::uint8_t>(session_id & 0xFF));
        out.push_back(static_cast<std::uint8_t>((session_id >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((session_id >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((session_id >> 24) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(packet_id & 0xFF));
        out.push_back(static_cast<std::uint8_t>((packet_id >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((packet_id >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((packet_id >> 24) & 0xFF));
        const auto addr = encode_address(dst);
        out.insert(out.end(), addr.begin(), addr.end());
        out.insert(out.end(), payload.begin(), payload.end());
        return out;
    }

    /// @brief 解析帧（增量）
    /// @param data 输入
    /// @param out 输出消息
    /// @param consumed 输出消耗字节数
    /// @return 错误码
    [[nodiscard]] inline auto parse(std::span<const std::uint8_t> data, message &out,
                                    std::size_t &consumed) -> error
    {
        if (data.size() < 1)
            return error::need_more;
        out.type = static_cast<message::kind>(data[0]);
        std::size_t off = 1;
        if (out.type == message::kind::udp)
        {
            if (data.size() < off + 8)
                return error::need_more;
            out.session_id = static_cast<std::uint32_t>(data[off]) |
                             static_cast<std::uint32_t>(data[off + 1]) << 8 |
                             static_cast<std::uint32_t>(data[off + 2]) << 16 |
                             static_cast<std::uint32_t>(data[off + 3]) << 24;
            out.packet_id = static_cast<std::uint32_t>(data[off + 4]) |
                            static_cast<std::uint32_t>(data[off + 5]) << 8 |
                            static_cast<std::uint32_t>(data[off + 6]) << 16 |
                            static_cast<std::uint32_t>(data[off + 7]) << 24;
            off += 8;
        }
        std::size_t addr_consumed = 0;
        const auto ec = parse_address(data.subspan(off), out.dst, addr_consumed);
        if (ec != error::none)
            return ec;
        off += addr_consumed;
        out.payload.assign(reinterpret_cast<const char *>(data.data() + off), data.size() - off);
        consumed = data.size();
        return error::none;
    }

} // namespace psmtest::hysteria2
