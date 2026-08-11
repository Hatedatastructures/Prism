/**
 * @file codec.hpp
 * @brief SS2022 头部编解码（纯函数，零状态）
 * @details 固定头明文：[Type 1B][Timestamp 8B BE][VarLen 2B BE] = 11B。
 *          变长头明文：[ATYP 1B][ADDR][PORT 2B BE][PadLen 2B BE][Padding][Payload]。
 * @note 参考 SIP022 规范。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/shadowsocks2022/types.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <vector>

namespace psmtest::ss2022
{

    /// @brief 构造固定头明文
    /// @param type 头类型（0x00 请求 / 0x01 响应）
    /// @param time_sec UTC 秒
    /// @param var_len 变长头长度
    /// @return 11 字节明文
    [[nodiscard]] inline auto build_fixed_header(std::uint8_t type, std::uint64_t time_sec,
                                                 std::uint16_t var_len)
        -> std::array<std::uint8_t, fixed_hdr_plain>
    {
        std::array<std::uint8_t, fixed_hdr_plain> out{};
        out[0] = type;
        for (std::size_t i = 0; i < 8; ++i)
            out[1 + i] = static_cast<std::uint8_t>((time_sec >> (56 - i * 8)) & 0xFF);
        out[9] = static_cast<std::uint8_t>((var_len >> 8) & 0xFF);
        out[10] = static_cast<std::uint8_t>(var_len & 0xFF);
        return out;
    }

    /// @brief 解析固定头明文
    /// @param data 11 字节明文
    /// @param type 输出头类型
    /// @param time_sec 输出时间戳
    /// @param var_len 输出变长头长度
    /// @return 错误码
    [[nodiscard]] inline auto parse_fixed_header(std::span<const std::uint8_t> data,
                                                 std::uint8_t &type, std::uint64_t &time_sec,
                                                 std::uint16_t &var_len) -> error
    {
        if (data.size() < fixed_hdr_plain)
            return error::need_more;
        type = data[0];
        time_sec = 0;
        for (std::size_t i = 0; i < 8; ++i)
            time_sec = (time_sec << 8) | data[1 + i];
        var_len = static_cast<std::uint16_t>(data[9]) << 8 | data[10];
        return error::none;
    }

    /// @brief 编码地址为字节（ATYP + ADDR + PORT 2B BE）
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

    /// @brief 解析地址字节（ATYP + ADDR + PORT 2B BE）
    /// @param data 完整缓冲区
    /// @param addr 输出目标地址
    /// @param off 输入起始偏移，输出结束偏移
    /// @return 错误码
    [[nodiscard]] inline auto parse_address(std::span<const std::uint8_t> data, address &addr,
                                            std::size_t &off) -> error
    {
        if (off >= data.size())
            return error::need_more;
        addr.type = static_cast<address_type>(data[off++]);
        switch (addr.type)
        {
            case address_type::ipv4:
            {
                if (data.size() < off + 4)
                    return error::need_more;
                std::array<char, 16> buf{};
                std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u",
                              data[off], data[off + 1], data[off + 2], data[off + 3]);
                addr.host = buf.data();
                off += 4;
                break;
            }
            case address_type::ipv6:
            {
                if (data.size() < off + 16)
                    return error::need_more;
                addr.host.assign(reinterpret_cast<const char *>(data.data() + off), 16);
                off += 16;
                break;
            }
            case address_type::domain:
            default:
            {
                if (off >= data.size())
                    return error::need_more;
                const auto len = data[off++];
                if (data.size() < off + len)
                    return error::need_more;
                addr.host.assign(reinterpret_cast<const char *>(data.data() + off), len);
                off += len;
                break;
            }
        }
        if (data.size() < off + 2)
            return error::need_more;
        addr.port = static_cast<std::uint16_t>(data[off]) << 8 | data[off + 1];
        off += 2;
        return error::none;
    }

    /// @brief 构造变长头明文（地址 + padding + 初始载荷）
    /// @param addr 目标地址
    /// @param pad_len padding 长度
    /// @param payload 初始载荷（可空）
    /// @return 变长头明文
    [[nodiscard]] inline auto build_var_header(const address &addr, std::uint16_t pad_len,
                                               std::span<const std::uint8_t> payload = {})
        -> std::vector<std::uint8_t>
    {
        auto out = encode_address(addr);
        out.push_back(static_cast<std::uint8_t>((pad_len >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(pad_len & 0xFF));
        for (std::uint16_t i = 0; i < pad_len; ++i)
            out.push_back(0);
        out.insert(out.end(), payload.begin(), payload.end());
        return out;
    }

    /// @brief 解析变长头明文
    /// @param data 变长头明文
    /// @param addr 输出目标地址
    /// @param payload 输出剩余载荷
    /// @return 错误码
    [[nodiscard]] inline auto parse_var_header(std::span<const std::uint8_t> data,
                                               address &addr,
                                               std::span<const std::uint8_t> &payload) -> error
    {
        if (data.size() < 2)
            return error::need_more;
        addr.type = static_cast<address_type>(data[0]);
        std::size_t off = 1;
        switch (addr.type)
        {
            case address_type::ipv4:
            {
                if (data.size() < off + 4)
                    return error::need_more;
                std::array<char, 16> buf{};
                std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u",
                              data[off], data[off + 1], data[off + 2], data[off + 3]);
                addr.host = buf.data();
                off += 4;
                break;
            }
            case address_type::ipv6:
            {
                if (data.size() < off + 16)
                    return error::need_more;
                addr.host.assign(reinterpret_cast<const char *>(data.data() + off), 16);
                off += 16;
                break;
            }
            case address_type::domain:
            default:
            {
                if (off >= data.size())
                    return error::need_more;
                const auto len = data[off++];
                if (data.size() < off + len)
                    return error::need_more;
                addr.host.assign(reinterpret_cast<const char *>(data.data() + off), len);
                off += len;
                break;
            }
        }
        if (data.size() < off + 2)
            return error::need_more;
        addr.port = static_cast<std::uint16_t>(data[off]) << 8 | data[off + 1];
        off += 2;
        if (data.size() < off + 2)
            return error::need_more;
        const auto pad_len = static_cast<std::size_t>(data[off]) << 8 | data[off + 1];
        off += 2;
        if (data.size() < off + pad_len)
            return error::need_more;
        off += pad_len;
        payload = data.subspan(off);
        return error::none;
    }

} // namespace psmtest::ss2022
