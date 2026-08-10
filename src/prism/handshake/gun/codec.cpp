/**
 * @file codec.cpp
 * @brief gRPC (gun) 传输帧编解码实现
 */

#include <prism/handshake/gun/codec.hpp>

#include <cstring>

namespace psm::handshake::gun::codec
{

    auto encode_varint(const std::uint32_t value, const std::span<std::uint8_t> out) -> std::size_t
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

    auto decode_varint(const std::span<const std::uint8_t> in, std::uint32_t &value) -> std::size_t
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

    auto encode_frame(const std::span<const std::uint8_t> payload, const std::span<std::uint8_t> out)
        -> std::size_t
    {
        std::array<std::uint8_t, max_varint_len> varint{};
        const auto varint_len = encode_varint(static_cast<std::uint32_t>(payload.size()), varint);
        if (varint_len == 0)
            return 0;

        const std::size_t total = header_fixed_len + varint_len + payload.size();
        if (out.size() < total)
            return 0;

        out[0] = 0x00; // 压缩标志：identity
        const auto frame_len = static_cast<std::uint32_t>(1 + varint_len + payload.size());
        out[1] = static_cast<std::uint8_t>(frame_len >> 24);
        out[2] = static_cast<std::uint8_t>(frame_len >> 16);
        out[3] = static_cast<std::uint8_t>(frame_len >> 8);
        out[4] = static_cast<std::uint8_t>(frame_len & 0xFF);
        out[5] = 0x0A; // protobuf field 1 (Tun.addr)，wire type 2
        std::memcpy(out.data() + header_fixed_len, varint.data(), varint_len);
        std::memcpy(out.data() + header_fixed_len + varint_len, payload.data(), payload.size());
        return total;
    }

    auto parse_frame_header(const std::span<const std::uint8_t> in, frame_header &header) -> bool
    {
        if (in.size() < header_fixed_len)
            return false;

        // 压缩标志必须为 0（identity）
        if (in[0] != 0x00)
            return false;

        const std::uint32_t frame_len = (static_cast<std::uint32_t>(in[1]) << 24)
            | (static_cast<std::uint32_t>(in[2]) << 16)
            | (static_cast<std::uint32_t>(in[3]) << 8)
            | static_cast<std::uint32_t>(in[4]);

        // protobuf 字段标记必须为 0x0A
        if (in[5] != 0x0A)
            return false;

        // 解码载荷长度 varint
        std::uint32_t payload_len = 0;
        const auto varint_len = decode_varint(in.subspan(header_fixed_len), payload_len);
        if (varint_len == 0)
            return false;
        if (payload_len > max_payload_len)
            return false;

        // 帧长度字段须与头部 + 载荷一致（防恶意声明不一致）
        const std::uint64_t expected = 1U + static_cast<std::uint64_t>(varint_len)
            + static_cast<std::uint64_t>(payload_len);
        if (frame_len != expected)
            return false;

        header.payload_len = payload_len;
        header.header_len = header_fixed_len + varint_len;
        return true;
    }

} // namespace psm::handshake::gun::codec
