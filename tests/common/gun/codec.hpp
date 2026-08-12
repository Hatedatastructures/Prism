/**
 * @file codec.hpp
 * @brief gRPC (gun) 帧编解码（纯函数）
 * @details 对齐 C++ include/prism/handshake/gun/codec.hpp（gun-lite）：
 *          - encode_varint / decode_varint：protobuf LEB128
 *          - encode_frame：[0x00][u32 BE len][0x0A][uvarint][payload]
 *          - parse_frame_header：帧头解析
 * @note 参考 gun-lite 协议规范。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/gun/types.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace psmtest::gun
{

    /**
     * @brief 编码 protobuf varint（LEB128）
     * @param value 数值
     * @param out 输出缓冲区
     * @return 写入字节数
     */
    [[nodiscard]] inline auto encode_varint(std::uint32_t value, std::span<std::uint8_t> out)
        -> std::size_t
    {
        std::uint32_t v = value;
        std::size_t n = 0;
        while (v >= 0x80)
        {
            if (n >= out.size())
                return 0;
            out[n++] = static_cast<std::uint8_t>((v & 0x7F) | 0x80);
            v >>= 7;
        }
        if (n >= out.size())
            return 0;
        out[n++] = static_cast<std::uint8_t>(v);
        return n;
    }

    /**
     * @brief 解码 protobuf varint
     * @param in 输入数据
     * @param value 输出数值
     * @return 消耗字节数，0 = 数据不足或非法
     */
    [[nodiscard]] inline auto decode_varint(std::span<const std::uint8_t> in,
                                            std::uint32_t &value) -> std::size_t
    {
        std::uint32_t v = 0;
        for (std::size_t i = 0; i < in.size() && i < max_varint_len; ++i)
        {
            v |= static_cast<std::uint32_t>(in[i] & 0x7F) << (7 * i);
            if ((in[i] & 0x80) == 0)
            {
                value = v;
                return i + 1;
            }
        }
        return 0;
    }

    /// 解析出的帧头信息
    struct frame_header
    {
        /// 载荷长度
        std::size_t payload_len{0};
        /// 帧头总长度（含 varint）
        std::size_t header_len{0};
    };

    /**
     * @brief 编码一个 gun 帧
     * @param payload 帧载荷
     * @return 帧字节 [0x00][u32 BE len][0x0A][uvarint][payload]
     */
    [[nodiscard]] inline auto encode_frame(std::span<const std::uint8_t> payload)
        -> std::vector<std::uint8_t>
    {
        std::array<std::uint8_t, max_varint_len> varint_buf{};
        const auto varint_len = encode_varint(static_cast<std::uint32_t>(payload.size()),
                                              varint_buf);
        std::vector<std::uint8_t> out;
        out.reserve(header_fixed_len + varint_len + payload.size());
        out.push_back(0x00);
        const auto total = static_cast<std::uint32_t>(1 + varint_len + payload.size());
        out.push_back(static_cast<std::uint8_t>((total >> 24) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((total >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((total >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(total & 0xFF));
        out.push_back(0x0A);
        out.insert(out.end(), varint_buf.begin(), varint_buf.begin() + varint_len);
        out.insert(out.end(), payload.begin(), payload.end());
        return out;
    }

    /**
     * @brief 解析帧头
     * @param in 输入数据（至少含 6 字节定长头）
     * @param header 输出帧头信息
     * @return true = 解析成功（数据不足或长度非法返回 false）
     */
    [[nodiscard]] inline auto parse_frame_header(std::span<const std::uint8_t> in,
                                                 frame_header &header) -> bool
    {
        if (in.size() < header_fixed_len + 1)
            return false;
        if (in[0] != 0x00 || in[5] != 0x0A)
            return false;
        const auto total = static_cast<std::uint32_t>(in[1]) << 24 |
                           static_cast<std::uint32_t>(in[2]) << 16 |
                           static_cast<std::uint32_t>(in[3]) << 8 |
                           static_cast<std::uint32_t>(in[4]);
        std::uint32_t plen = 0;
        const auto vlen = decode_varint(in.subspan(header_fixed_len), plen);
        if (vlen == 0 || total != 1 + vlen + plen)
            return false;
        header.payload_len = plen;
        header.header_len = header_fixed_len + vlen;
        return true;
    }

} // namespace psmtest::gun
