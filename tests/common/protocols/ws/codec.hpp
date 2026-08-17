/**
 * @file codec.hpp
 * @brief WebSocket 帧编解码（纯函数，RFC 6455）
 * @details 对齐 C++ include/prism/handshake/ws/codec.hpp：
 *          - compute_accept：base64(SHA1(key + GUID)) → Sec-WebSocket-Accept
 *          - parse_frame_header：2/4/10 字节帧头解析（含 mask key）
 *          - encode_frame：服务端帧（不掩码）编码
 *          - apply_mask：客户端帧 32bit 循环 XOR
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

#include <common/core/error.hpp>
#include <common/protocols/ws/types.hpp>

namespace preview::ws
{

    /**
     * @brief 计算 Sec-WebSocket-Accept
     * @param key Sec-WebSocket-Key（客户端提供）
     * @return 28 字节 base64 结果；失败返回空
     * @details base64(SHA1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))。
     */
    [[nodiscard]] inline auto compute_accept(std::string_view key) -> std::string
    {
        std::string combined(key);
        combined.append(ws_guid);
        std::array<std::uint8_t, sha1_len> digest{};
        SHA1(reinterpret_cast<const std::uint8_t *>(combined.data()), combined.size(), digest.data());
        std::array<std::uint8_t, accept_len + 1> enc{};
        if (EVP_EncodeBlock(enc.data(), digest.data(), static_cast<int>(digest.size())) !=
            static_cast<int>(accept_len))
        {
            return {};
        }
        return std::string(reinterpret_cast<const char *>(enc.data()), accept_len);
    }

    /// 解析出的帧头
    struct frame_header
    {
        /// FIN 标志
        bool fin{false};
        /// 帧类型
        std::uint8_t opcode{0};
        /// 是否掩码
        bool masked{false};
        /// 载荷长度
        std::uint64_t payload_len{0};
        /// 帧头总长度（含 mask key）
        std::size_t header_len{0};
        /// 掩码键（masked 时有效）
        std::array<std::uint8_t, mask_len> mask{};
    };

    /**
     * @brief 解析帧头
     * @param in 输入数据
     * @param header 输出帧头
     * @return true = 解析成功（数据不足返回 false）
     */
    [[nodiscard]] inline auto parse_frame_header(std::span<const std::byte> in, frame_header &header) -> bool
    {
        if (in.size() < 2)
        {
            return false;
        }
        const auto b0 = static_cast<std::uint8_t>(in[0]);
        const auto b1 = static_cast<std::uint8_t>(in[1]);
        header.fin = (b0 & 0x80) != 0;
        header.opcode = static_cast<std::uint8_t>(b0 & 0x0F);
        header.masked = (b1 & 0x80) != 0;

        std::size_t offset = 2;
        std::uint64_t len = static_cast<std::uint64_t>(b1 & 0x7F);
        if (len == 126)
        {
            if (in.size() < offset + 2)
            {
                return false;
            }
            len = (static_cast<std::uint64_t>(static_cast<std::uint8_t>(in[offset])) << 8) |
                  static_cast<std::uint64_t>(static_cast<std::uint8_t>(in[offset + 1]));
            offset += 2;
        }
        else if (len == 127)
        {
            if (in.size() < offset + 8)
            {
                return false;
            }
            len = 0;
            for (std::size_t i = 0; i < 8; ++i)
            {
                len = (len << 8) | static_cast<std::uint64_t>(static_cast<std::uint8_t>(in[offset + i]));
            }
            offset += 8;
        }
        header.payload_len = len;

        if (header.masked)
        {
            if (in.size() < offset + 4)
            {
                return false;
            }
            std::memcpy(header.mask.data(), in.data() + offset, 4);
            offset += 4;
        }
        header.header_len = offset;
        return true;
    }

    /**
     * @brief 应用掩码（32bit 循环 XOR）
     * @param data 载荷（原地）
     * @param mask 4 字节掩码键
     */
    inline auto apply_mask(std::span<std::byte> data, std::span<const std::uint8_t, mask_len> mask) -> void
    {
        for (std::size_t i = 0; i < data.size(); ++i)
        {
            data[i] = static_cast<std::byte>(static_cast<std::uint8_t>(data[i]) ^ mask[i % 4]);
        }
    }

    /// 帧编码输入（op + fin + payload）
    struct frame_input
    {
        opcode op{opcode::binary};          ///< 帧类型
        bool fin{true};                     ///< 是否 FIN
        std::span<const std::byte> payload; ///< 载荷
    };

    /**
     * @brief 编码服务端帧（不掩码）
     * @param in 帧输入
     * @param out 输出缓冲区
     * @return 写入字节数，0 = 缓冲区不足
     */
    [[nodiscard]] inline auto encode_frame(const frame_input &in, std::span<std::byte> out) -> std::size_t
    {
        const auto len = in.payload.size();
        std::size_t header_len = 2;
        if (len >= 126 && len <= 0xFFFF)
        {
            header_len += 2;
        }
        else if (len > 0xFFFF)
        {
            header_len += 8;
        }
        if (out.size() < header_len + len)
        {
            return 0;
        }

        std::uint8_t fin_bit;
        if (in.fin)
        {
            fin_bit = 0x80;
        }
        else
        {
            fin_bit = 0x00;
        }
        const auto b0 = static_cast<std::uint8_t>(static_cast<std::uint8_t>(in.op)) | fin_bit;
        out[0] = static_cast<std::byte>(b0);
        std::size_t offset = 2;
        if (len < 126)
        {
            out[1] = static_cast<std::byte>(len);
        }
        else if (len <= 0xFFFF)
        {
            out[1] = std::byte{126};
            out[offset++] = static_cast<std::byte>((len >> 8) & 0xFF);
            out[offset++] = static_cast<std::byte>(len & 0xFF);
        }
        else
        {
            out[1] = std::byte{127};
            for (int i = 7; i >= 0; --i)
            {
                out[offset++] = static_cast<std::byte>((len >> (8 * i)) & 0xFF);
            }
        }
        std::memcpy(out.data() + offset, in.payload.data(), len);
        return header_len + len;
    }

} // namespace preview::ws
