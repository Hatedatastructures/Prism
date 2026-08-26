/**
 * @file Codec.hpp
 * @brief WebSocket 帧编解码（纯函数，RFC 6455）
 * @details 对齐 C++ include/prism/handshake/ws/Codec.hpp：
 *          - ComputeAccept：base64(SHA1(key + GUID)) → Sec-WebSocket-Accept
 *          - ParseFrameHeader：2/4/10 字节帧头解析（含 masked key）
 *          - EncodeFrame：服务端帧（不掩码）编码
 *          - ApplyMask：客户端帧 32bit 循环 XOR
 * @note 参考 RFC 6455 协议规范。
 */

#pragma once

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>

#include <common/Core/Error.hpp>
#include <common/Protocols/Ws/Types.hpp>

namespace Preview::Ws
{

    /**
     * @brief 计算 Sec-WebSocket-Accept
     * @param key Sec-WebSocket-Key（客户端提供）
     * @return 28 字节 base64 结果；失败返回空
     * @details base64(SHA1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))。
     */
    [[nodiscard]] inline auto ComputeAccept(std::string_view key) -> std::string
    {
        std::string combined(key);
        combined.append(WsGuid);
        std::array<std::uint8_t, Sha1Len> digest{};
        SHA1(reinterpret_cast<const std::uint8_t *>(combined.data()), combined.size(), digest.data());
        std::array<std::uint8_t, AcceptLen + 1> enc{};
        if (EVP_EncodeBlock(enc.data(), digest.data(), static_cast<int>(digest.size())) !=
            static_cast<int>(AcceptLen))
        {
            return {};
        }
        return std::string(reinterpret_cast<const char *>(enc.data()), AcceptLen);
    }

    /// 解析出的帧头
    struct FrameHeader
    {
        /// FIN 标志
        bool Fin{false};
        /// 帧类型
        std::uint8_t Opcode{0};
        /// 是否掩码
        bool Masked{false};
        /// 载荷长度
        std::uint64_t PayloadLen{0};
        /// 帧头总长度（含 masked key）
        std::size_t HeaderLen{0};
        /// 掩码键（masked 时有效）
        std::array<std::uint8_t, MaskLen> MaskKey{};
    };

    /**
     * @brief 解析帧头
     * @param in 输入数据
     * @param Header 输出帧头
     * @return true = 解析成功（数据不足返回 false）
     */
    [[nodiscard]] inline auto ParseFrameHeader(std::span<const std::byte> in, FrameHeader &Header) -> bool
    {
        if (in.size() < 2)
        {
            return false;
        }
        const auto B0 = static_cast<std::uint8_t>(in[0]);
        const auto B1 = static_cast<std::uint8_t>(in[1]);
        Header.Fin = (B0 & 0x80) != 0;
        Header.Opcode = static_cast<std::uint8_t>(B0 & 0x0F);
        Header.Masked = (B1 & 0x80) != 0;

        std::size_t Offset = 2;
        std::uint64_t Len = static_cast<std::uint64_t>(B1 & 0x7F);
        if (Len == 126)
        {
            if (in.size() < Offset + 2)
            {
                return false;
            }
            Len = (static_cast<std::uint64_t>(static_cast<std::uint8_t>(in[Offset])) << 8) |
                  static_cast<std::uint64_t>(static_cast<std::uint8_t>(in[Offset + 1]));
            Offset += 2;
        }
        else if (Len == 127)
        {
            if (in.size() < Offset + 8)
            {
                return false;
            }
            Len = 0;
            for (std::size_t I = 0; I < 8; ++I)
            {
                Len = (Len << 8) | static_cast<std::uint64_t>(static_cast<std::uint8_t>(in[Offset + I]));
            }
            Offset += 8;
        }
        Header.PayloadLen = Len;

        if (Header.Masked)
        {
            if (in.size() < Offset + 4)
            {
                return false;
            }
            std::memcpy(Header.MaskKey.data(), in.data() + Offset, 4);
            Offset += 4;
        }
        Header.HeaderLen = Offset;
        return true;
    }

    /**
     * @brief 应用掩码（32bit 循环 XOR）
     * @param Data 载荷（原地）
     * @param masked 4 字节掩码键
     */
    inline auto ApplyMask(std::span<std::byte> Data, std::span<const std::uint8_t, MaskLen> Key) -> void
    {
        for (std::size_t I = 0; I < Data.size(); ++I)
        {
            Data[I] = static_cast<std::byte>(static_cast<std::uint8_t>(Data[I]) ^ Key[I % 4]);
        }
    }

    /// 帧编码输入（op + fin + payload）
    struct FrameInput
    {
        Opcode op{Opcode::Binary};          ///< 帧类型
        bool Fin{true};                     ///< 是否 FIN
        std::span<const std::byte> payload; ///< 载荷
    };

    /**
     * @brief 编码服务端帧（不掩码）
     * @param in 帧输入
     * @param out 输出缓冲区
     * @return 写入字节数，0 = 缓冲区不足
     */
    [[nodiscard]] inline auto EncodeFrame(const FrameInput &in, std::span<std::byte> out) -> std::size_t
    {
        const auto Len = in.payload.size();
        std::size_t HeaderLen = 2;
        if (Len >= 126 && Len <= 0xFFFF)
        {
            HeaderLen += 2;
        }
        else if (Len > 0xFFFF)
        {
            HeaderLen += 8;
        }
        if (out.size() < HeaderLen + Len)
        {
            return 0;
        }

        std::uint8_t FinBit;
        if (in.Fin)
        {
            FinBit = 0x80;
        }
        else
        {
            FinBit = 0x00;
        }
        const auto B0 = static_cast<std::uint8_t>(static_cast<std::uint8_t>(in.op)) | FinBit;
        out[0] = static_cast<std::byte>(B0);
        std::size_t Offset = 2;
        if (Len < 126)
        {
            out[1] = static_cast<std::byte>(Len);
        }
        else if (Len <= 0xFFFF)
        {
            out[1] = std::byte{126};
            out[Offset++] = static_cast<std::byte>((Len >> 8) & 0xFF);
            out[Offset++] = static_cast<std::byte>(Len & 0xFF);
        }
        else
        {
            out[1] = std::byte{127};
            for (int I = 7; I >= 0; --I)
            {
                out[Offset++] = static_cast<std::byte>((Len >> (8 * I)) & 0xFF);
            }
        }
        std::memcpy(out.data() + Offset, in.payload.data(), Len);
        return HeaderLen + Len;
    }

} // namespace Preview::Ws
