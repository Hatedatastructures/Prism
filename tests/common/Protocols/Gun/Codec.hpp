/**
 * @file Codec.hpp
 * @brief gRPC (gun) 帧编解码（纯函数）
 * @details 对齐 C++ include/prism/handshake/gun/Codec.hpp（gun-lite）：
 *          - EncodeVarint / DecodeVarint：protobuf LEB128
 *          - EncodeFrame：[0x00][u32 BE len][0x0A][uvarint][payload]
 *          - ParseFrameHeader：帧头解析
 * @note 参考 gun-lite 协议规范。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <common/Core/Error.hpp>
#include <common/Protocols/Gun/Types.hpp>

namespace Preview::Gun
{

    /**
     * @brief 编码 protobuf varint（LEB128）
     * @param value 数值
     * @param out 输出缓冲区
     * @return 写入字节数
     */
    [[nodiscard]] inline auto EncodeVarint(std::uint32_t value, std::span<std::uint8_t> out) -> std::size_t
    {
        std::uint32_t v = value;
        std::size_t n = 0;
        while (v >= 0x80)
        {
            if (n >= out.size())
            {
                return 0;
            }
            out[n++] = static_cast<std::uint8_t>((v & 0x7F) | 0x80);
            v >>= 7;
        }
        if (n >= out.size())
        {
            return 0;
        }
        out[n++] = static_cast<std::uint8_t>(v);
        return n;
    }

    /**
     * @brief 解码 protobuf varint
     * @param in 输入数据
     * @param value 输出数值
     * @return 消耗字节数，0 = 数据不足或非法
     */
    [[nodiscard]] inline auto DecodeVarint(std::span<const std::uint8_t> in, std::uint32_t &value)
        -> std::size_t
    {
        std::uint32_t v = 0;
        for (std::size_t i = 0; i < in.size() && i < MaxVarintLen; ++i)
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
    struct FrameHeader
    {
        /// 载荷长度
        std::size_t PayloadLen{0};
        /// 帧头总长度（含 varint）
        std::size_t HeaderLen{0};
    };

    /**
     * @brief 编码一个 gun 帧
     * @param payload 帧载荷
     * @return 帧字节 [0x00][u32 BE len][0x0A][uvarint][payload]
     */
    [[nodiscard]] inline auto EncodeFrame(std::span<const std::uint8_t> payload) -> std::vector<std::uint8_t>
    {
        std::array<std::uint8_t, MaxVarintLen> varint_buf{};
        const auto VarintLen = EncodeVarint(static_cast<std::uint32_t>(payload.size()), varint_buf);
        std::vector<std::uint8_t> out;
        out.reserve(HeaderFixedLen + VarintLen + payload.size());
        out.push_back(0x00);
        const auto Total = static_cast<std::uint32_t>(1 + VarintLen + payload.size());
        out.push_back(static_cast<std::uint8_t>((Total >> 24) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((Total >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((Total >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(Total & 0xFF));
        out.push_back(0x0A);
        out.insert(out.end(), varint_buf.begin(), varint_buf.begin() + VarintLen);
        out.insert(out.end(), payload.begin(), payload.end());
        return out;
    }

    /**
     * @brief 解析帧头
     * @param in 输入数据（至少含 6 字节定长头）
     * @param Header 输出帧头信息
     * @return true = 解析成功（数据不足或长度非法返回 false）
     */
    [[nodiscard]] inline auto ParseFrameHeader(std::span<const std::uint8_t> in, FrameHeader &Header)
        -> bool
    {
        if (in.size() < HeaderFixedLen + 1)
        {
            return false;
        }
        if (in[0] != 0x00 || in[5] != 0x0A)
        {
            return false;
        }
        const auto Total = static_cast<std::uint32_t>(in[1]) << 24 | static_cast<std::uint32_t>(in[2]) << 16 |
                           static_cast<std::uint32_t>(in[3]) << 8 | static_cast<std::uint32_t>(in[4]);
        std::uint32_t plen = 0;
        const auto vlen = DecodeVarint(in.subspan(HeaderFixedLen), plen);
        if (vlen == 0 || Total != 1 + vlen + plen)
        {
            return false;
        }
        Header.PayloadLen = plen;
        Header.HeaderLen = HeaderFixedLen + vlen;
        return true;
    }

} // namespace Preview::Gun
