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

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

#include <preview/Foundation/Error.hpp>
#include <preview/Protocols/Gun/Types.hpp>

namespace Preview::Gun
{

    /**
     * @brief 编码 protobuf varint（LEB128）
     * @param Value 数值
     * @param Output 输出缓冲区
     * @return 写入字节数
     */
    [[nodiscard]] inline auto EncodeVarint(
        std::uint32_t Value,
        std::span<std::uint8_t> Output) -> std::size_t
    {
        std::uint32_t Probe = Value;
        std::size_t Required = 1;
        while (Probe >= 0x80)
        {
            ++Required;
            Probe >>= 7;
        }
        if (Required > Output.size())
        {
            return 0;
        }

        std::uint32_t Remaining = Value;
        std::size_t Written = 0;
        while (Remaining >= 0x80)
        {
            Output[Written++] = static_cast<std::uint8_t>((Remaining & 0x7F) | 0x80);
            Remaining >>= 7;
        }
        Output[Written++] = static_cast<std::uint8_t>(Remaining);
        return Written;
    }

    /**
     * @brief 解码 protobuf varint
     * @param Input 输入数据
     * @param Value 输出数值
     * @return 消耗字节数，0 = 数据不足或非法
     */
    [[nodiscard]] inline auto DecodeVarint(
        std::span<const std::uint8_t> Input,
        std::uint32_t &Value)
        -> std::size_t
    {
        Value = 0;
        std::uint32_t V = 0;
        for (std::size_t I = 0; I < Input.size() && I < MaxVarintLen; ++I)
        {
            const auto Byte = Input[I];
            const auto Chunk = static_cast<std::uint32_t>(Byte & 0x7F);
            if (I == MaxVarintLen - 1 &&
                (Chunk > 0x0F || (Byte & 0x80) != 0))
            {
                return 0;
            }
            V |= Chunk << (7 * I);
            if ((Byte & 0x80) == 0)
            {
                Value = V;
                return I + 1;
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
     * @param Payload 帧载荷
     * @return 帧字节 [0x00][u32 BE len][0x0A][uvarint][payload]
     */
    [[nodiscard]] inline auto EncodeFrame(
        std::span<const std::uint8_t> Payload) -> std::vector<std::uint8_t>
    {
        if (Payload.size() > MaxPayloadLen ||
            Payload.size() > (std::numeric_limits<std::uint32_t>::max)())
        {
            return {};
        }
        std::array<std::uint8_t, MaxVarintLen> VarintBuf{};
        const auto VarintLen = EncodeVarint(static_cast<std::uint32_t>(Payload.size()), VarintBuf);
        if (VarintLen == 0)
        {
            return {};
        }
        const auto TotalSize = std::size_t{1} + VarintLen + Payload.size();
        if (TotalSize > (std::numeric_limits<std::uint32_t>::max)())
        {
            return {};
        }
        const auto Total = static_cast<std::uint32_t>(TotalSize);
        std::vector<std::uint8_t> Output;
        Output.reserve(HeaderFixedLen + VarintLen + Payload.size());
        Output.push_back(0x00);
        Output.push_back(static_cast<std::uint8_t>((Total >> 24) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Total >> 16) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Total >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(Total & 0xFF));
        Output.push_back(0x0A);
        Output.insert(Output.end(), VarintBuf.begin(), VarintBuf.begin() + VarintLen);
        Output.insert(Output.end(), Payload.begin(), Payload.end());
        return Output;
    }

    /**
     * @brief 解析帧头
     * @param Input 输入数据（至少含 6 字节定长头）
     * @param Header 输出帧头信息
     * @return true = 解析成功（数据不足或长度非法返回 false）
     */
    [[nodiscard]] inline auto ParseFrameHeader(
        std::span<const std::uint8_t> Input,
        FrameHeader &Header)
        -> bool
    {
        Header = {};
        if (Input.size() < HeaderFixedLen + 1)
        {
            return false;
        }
        if (Input[0] != 0x00 || Input[5] != 0x0A)
        {
            return false;
        }
        const auto Total = static_cast<std::uint32_t>(Input[1]) << 24 |
                           static_cast<std::uint32_t>(Input[2]) << 16 |
                           static_cast<std::uint32_t>(Input[3]) << 8 |
                           static_cast<std::uint32_t>(Input[4]);
        std::uint32_t PayloadLength = 0;
        const auto VarintLength = DecodeVarint(
            Input.subspan(HeaderFixedLen), PayloadLength);
        if (VarintLength == 0 || PayloadLength > MaxPayloadLen)
        {
            return false;
        }
        const auto ExpectedTotal = std::size_t{1} + VarintLength + PayloadLength;
        if (ExpectedTotal > (std::numeric_limits<std::uint32_t>::max)() ||
            Total != ExpectedTotal)
        {
            return false;
        }
        Header.PayloadLen = PayloadLength;
        Header.HeaderLen = HeaderFixedLen + VarintLength;
        return true;
    }

} // namespace Preview::Gun
