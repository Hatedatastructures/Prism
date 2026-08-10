/**
 * @file codec.cpp
 * @brief Hysteria2 协议帧编解码实现
 */

#include <prism/protocol/hysteria2/codec.hpp>

#include <cstring>

namespace psm::protocol::hysteria2
{

    auto encode_varint(const std::uint64_t value, const std::span<std::uint8_t> out) -> std::size_t
    {
        // RFC 9000 varint：1/2/4/8 字节
        if (value < (1ULL << 6))
        {
            if (out.size() < 1)
                return 0;
            out[0] = static_cast<std::uint8_t>(value);
            return 1;
        }
        if (value < (1ULL << 14))
        {
            if (out.size() < 2)
                return 0;
            out[0] = static_cast<std::uint8_t>(0x40 | (value >> 8));
            out[1] = static_cast<std::uint8_t>(value & 0xFF);
            return 2;
        }
        if (value < (1ULL << 30))
        {
            if (out.size() < 4)
                return 0;
            out[0] = static_cast<std::uint8_t>(0x80 | (value >> 24));
            out[1] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
            out[2] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
            out[3] = static_cast<std::uint8_t>(value & 0xFF);
            return 4;
        }
        if (out.size() < 8)
            return 0;
        out[0] = static_cast<std::uint8_t>(0xC0 | (value >> 56));
        out[1] = static_cast<std::uint8_t>((value >> 48) & 0xFF);
        out[2] = static_cast<std::uint8_t>((value >> 40) & 0xFF);
        out[3] = static_cast<std::uint8_t>((value >> 32) & 0xFF);
        out[4] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
        out[5] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
        out[6] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
        out[7] = static_cast<std::uint8_t>(value & 0xFF);
        return 8;
    }

    auto decode_varint(const std::span<const std::uint8_t> in, std::uint64_t &value) -> std::size_t
    {
        if (in.empty())
            return 0;
        const auto first = in[0];
        const auto prefix = first >> 6;
        const std::size_t len = static_cast<std::size_t>(1) << prefix;
        if (in.size() < len)
            return 0;

        std::uint64_t v = 0;
        const std::uint64_t mask = (1ULL << (62 - (prefix * 8))) - 1;
        v = static_cast<std::uint64_t>(first & 0x3F);
        if (prefix == 0)
        {
            value = v;
            return 1;
        }
        // 提取剩余字节（大端）
        v = 0;
        const std::size_t payload_bytes = len - 1;
        for (std::size_t i = 0; i < payload_bytes; ++i)
        {
            v = (v << 8) | static_cast<std::uint64_t>(in[1 + i]);
        }
        // 前缀位是 value 的高位
        v |= static_cast<std::uint64_t>(first & 0x3F) << (8 * payload_bytes);
        (void)mask;
        value = v;
        return len;
    }

    auto parse_tcp_request(const std::span<const std::uint8_t> in, tcp_request &out,
                           std::size_t &payload_offset) -> bool
    {
        std::uint64_t frame_type = 0;
        auto offset = decode_varint(in, frame_type);
        if (offset == 0 || frame_type != frame_type_tcp)
            return false;

        std::uint64_t addr_len = 0;
        const auto len_n = decode_varint(in.subspan(offset), addr_len);
        if (len_n == 0 || addr_len == 0 || addr_len > max_address_length)
            return false;
        offset += len_n;
        if (in.size() < offset + addr_len)
            return false;
        out.address.assign(reinterpret_cast<const char *>(in.data() + offset),
                           static_cast<std::size_t>(addr_len));
        offset += static_cast<std::size_t>(addr_len);

        // PaddingLen + Padding（忽略）
        std::uint64_t pad_len = 0;
        const auto pad_n = decode_varint(in.subspan(offset), pad_len);
        if (pad_n == 0 || pad_len > 4096)
            return false;
        offset += pad_n;
        if (in.size() < offset + pad_len)
            return false;
        offset += static_cast<std::size_t>(pad_len);

        // 载荷起点：帧头（类型 + 地址 + padding）之后
        payload_offset = offset;
        return true;
    }

    auto parse_udp_message(const std::span<const std::uint8_t> in, udp_message &out) -> bool
    {
        // SessionID(4) PacketID(2) FragID(1) FragCount(1) AddrLen(varint) Addr Data
        if (in.size() < 8)
            return false;
        std::size_t offset = 0;
        out.session_id = (static_cast<std::uint32_t>(in[0]) << 24)
            | (static_cast<std::uint32_t>(in[1]) << 16)
            | (static_cast<std::uint32_t>(in[2]) << 8)
            | static_cast<std::uint32_t>(in[3]);
        offset += 4;
        out.packet_id = static_cast<std::uint16_t>((in[4] << 8) | in[5]);
        offset += 2;
        out.frag_id = in[6];
        out.frag_count = in[7];
        offset += 2;
        if (out.frag_count == 0 || out.frag_id >= out.frag_count)
            return false;

        std::uint64_t addr_len = 0;
        const auto len_n = decode_varint(in.subspan(offset), addr_len);
        if (len_n == 0 || addr_len > max_address_length)
            return false;
        offset += len_n;
        if (in.size() < offset + addr_len)
            return false;
        out.address.assign(reinterpret_cast<const char *>(in.data() + offset),
                           static_cast<std::size_t>(addr_len));
        offset += static_cast<std::size_t>(addr_len);

        out.data_offset = offset;
        out.data_len = in.size() - offset;
        return true;
    }

} // namespace psm::protocol::hysteria2
