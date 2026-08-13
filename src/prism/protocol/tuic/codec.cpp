/**
 * @file codec.cpp
 * @brief TUIC v5 协议帧编解码实现
 */

#include <prism/protocol/tuic/codec.hpp>

#include <cstring>

namespace psm::protocol::tuic
{

    namespace
    {
        /**
         * @brief 地址编码（TUIC v5：ATYP 0=domain 1=IPv4 2=IPv6）
         * @param in 输入字节序列
         * @param addr 解析出的地址
         * @param port 解析出的端口
         * @param consumed 消耗的字节数
         * @return 是否解析成功
         */
        [[nodiscard]] auto parse_address(std::span<const std::uint8_t> in,
                                         psm::protocol::common::address &addr, std::uint16_t &port,
                                         std::size_t &consumed) -> bool
        {
            if (in.empty())
            {
                return false;
            }
            const auto atyp = in[0];
            std::size_t offset = 1;

            switch (atyp)
            {
            case static_cast<std::uint8_t>(address_type::domain): {
                if (in.size() < offset + 1)
                {
                    return false;
                }
                const auto len = in[offset];
                if (len == 0 || in.size() < offset + 1 + len + 2)
                {
                    return false;
                }
                psm::protocol::common::domain_address dom{};
                dom.length = len;
                std::memcpy(dom.value.data(), in.data() + offset + 1, len);
                addr = dom;
                offset += 1 + len;
                break;
            }
            case static_cast<std::uint8_t>(address_type::ipv4): {
                if (in.size() < offset + 4 + 2)
                {
                    return false;
                }
                psm::protocol::common::ipv4_address ip{};
                std::memcpy(ip.bytes.data(), in.data() + offset, 4);
                addr = ip;
                offset += 4;
                break;
            }
            case static_cast<std::uint8_t>(address_type::ipv6): {
                if (in.size() < offset + 16 + 2)
                {
                    return false;
                }
                psm::protocol::common::ipv6_address ip{};
                std::memcpy(ip.bytes.data(), in.data() + offset, 16);
                addr = ip;
                offset += 16;
                break;
            }
            default: return false;
            }

            port = static_cast<std::uint16_t>((in[offset] << 8) | in[offset + 1]);
            offset += 2;
            consumed = offset;
            return true;
        }
    } // namespace

    auto encode_varint(const std::uint32_t value, const std::span<std::uint8_t> out) -> std::size_t
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

    auto decode_varint(const std::span<const std::uint8_t> in, std::uint32_t &value) -> std::size_t
    {
        std::uint32_t v = 0;
        for (std::size_t i = 0; i < in.size() && i < 5; ++i)
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

    auto parse_authenticate(const std::span<const std::uint8_t> in, authenticate_frame &out) -> bool
    {
        if (in.size() < 2 + 16 + token_len)
        {
            return false;
        }
        if (in[0] != version || in[1] != static_cast<std::uint8_t>(command::authenticate))
        {
            return false;
        }
        std::memcpy(out.uuid.data(), in.data() + 2, 16);
        std::memcpy(out.token.data(), in.data() + 2 + 16, token_len);
        return true;
    }

    auto parse_connect(const std::span<const std::uint8_t> in, connect_frame &out, std::size_t &frame_len)
        -> bool
    {
        if (in.size() < 3)
        {
            return false;
        }
        if (in[0] != version || in[1] != static_cast<std::uint8_t>(command::connect))
        {
            return false;
        }

        std::size_t consumed = 0;
        if (!parse_address(in.subspan(2), out.destination, out.port, consumed))
        {
            return false;
        }
        frame_len = 2 + consumed;
        return true;
    }

    auto parse_packet(const std::span<const std::uint8_t> in, packet_frame &out) -> bool
    {
        // VER TYPE ASSOC_ID(2) PKT_ID(2) FRAG_TOTAL(1) FRAG_ID(1) SIZE(2) ATYP...
        if (in.size() < 2 + 2 + 2 + 1 + 1 + 2 + 1)
        {
            return false;
        }
        if (in[0] != version || in[1] != static_cast<std::uint8_t>(command::packet))
        {
            return false;
        }

        std::size_t offset = 2;
        out.assoc_id = static_cast<std::uint16_t>((in[offset] << 8) | in[offset + 1]);
        offset += 2;
        out.pkt_id = static_cast<std::uint16_t>((in[offset] << 8) | in[offset + 1]);
        offset += 2;
        out.frag_total = in[offset++];
        out.frag_id = in[offset++];
        const std::size_t size = static_cast<std::size_t>((in[offset] << 8) | in[offset + 1]);
        offset += 2;

        // ATYP
        const auto atyp = in[offset];
        if (atyp == static_cast<std::uint8_t>(address_type::none))
        {
            // 非首片：无地址，SIZE 后直接是数据
            offset += 1;
            if (in.size() < offset + size)
            {
                return false;
            }
            out.data_offset = offset;
            out.data_len = size;
            return true;
        }

        std::size_t consumed = 0;
        if (!parse_address(in.subspan(offset), out.destination, out.port, consumed))
        {
            return false;
        }
        offset += consumed;
        if (in.size() < offset + size)
        {
            return false;
        }
        out.data_offset = offset;
        out.data_len = size;
        return true;
    }

    auto parse_dissociate(const std::span<const std::uint8_t> in, std::uint16_t &assoc_id) -> bool
    {
        if (in.size() < 4)
        {
            return false;
        }
        if (in[0] != version || in[1] != static_cast<std::uint8_t>(command::dissociate))
        {
            return false;
        }
        assoc_id = static_cast<std::uint16_t>((in[2] << 8) | in[3]);
        return true;
    }

    auto parse_heartbeat(const std::span<const std::uint8_t> in) -> bool
    {
        if (in.size() < 2)
        {
            return false;
        }
        return in[0] == version && in[1] == static_cast<std::uint8_t>(command::heartbeat);
    }

} // namespace psm::protocol::tuic
