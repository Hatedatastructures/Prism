/**
 * @file wire.hpp
 * @brief Trojan 协议线级解析
 * @details 提供 Trojan 协议报文的底层解析函数，包括密码哈希、头部、地址、端口和 UDP 帧的编解码。
 */
#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <forward-engine/gist.hpp>
#include <cctype>
#include <forward-engine/protocol/trojan/message.hpp>
#include <forward-engine/memory/container.hpp>

namespace ngx::protocol::trojan::wire
{
    struct header_parse
    {
        command cmd;
        address_type atyp;
    };

    inline auto decode_credential(const std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, std::array<char, 56>>
    {
        if (buffer.size() < 56)
        {
            return {gist::code::bad_message, {}};
        }

        std::array<char, 56> credential{};
        for (size_t i = 0; i < 56; ++i)
        {
            if (!std::isxdigit(buffer[i]))
            {
                return {gist::code::protocol_error, {}};
            }
            credential[i] = static_cast<char>(buffer[i]);
        }
        return {gist::code::success, credential};
    }

    inline auto decode_crlf(const std::span<const std::uint8_t> buffer)
        -> gist::code
    {
        if (buffer.size() < 2)
        {
            return gist::code::bad_message;
        }
        if (buffer[0] != '\r' || buffer[1] != '\n')
        {
            return gist::code::protocol_error;
        }
        return gist::code::success;
    }

    inline auto decode_cmd_atyp(std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, header_parse>
    {
        if (buffer.size() < 2)
        {
            return {gist::code::bad_message, {}};
        }
        return {gist::code::success, {static_cast<command>(buffer[0]), static_cast<address_type>(buffer[1])}};
    }

    inline auto parse_ipv4(const std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, ipv4_address>
    {
        if (buffer.size() < 4)
        {
            return {gist::code::bad_message, {}};
        }
        ipv4_address addr{};
        std::memcpy(addr.bytes.data(), buffer.data(), 4);
        return {gist::code::success, addr};
    }

    inline auto parse_ipv6(const std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, ipv6_address>
    {
        if (buffer.size() < 16)
        {
            return {gist::code::bad_message, {}};
        }
        ipv6_address addr{};
        std::memcpy(addr.bytes.data(), buffer.data(), 16);
        return {gist::code::success, addr};
    }

    inline auto parse_domain(const std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, domain_address>
    {
        if (buffer.empty())
        {
            return {gist::code::bad_message, {}};
        }
        std::uint8_t len = buffer[0];
        if (buffer.size() < static_cast<size_t>(1 + len))
        {
            return {gist::code::bad_message, {}};
        }
        domain_address addr{};
        if (len > addr.value.size())
        {
            return {gist::code::bad_message, {}};
        }
        addr.length = len;
        std::memcpy(addr.value.data(), buffer.data() + 1, len);
        return {gist::code::success, addr};
    }

    inline auto decode_port(const std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, uint16_t>
    {
        if (buffer.size() < 2)
        {
            return {gist::code::bad_message, 0};
        }
        uint16_t port = (static_cast<uint16_t>(buffer[0]) << 8) | static_cast<uint16_t>(buffer[1]);
        return {gist::code::success, port};
    }

    /**
     * @brief Trojan UDP 帧格式
     * @details Trojan UDP 帧格式:
     * +------+-------+----------+----------+--------+
     * | ATYP |  LEN  | DST.ADDR | DST.PORT |  DATA  |
     * +------+-------+----------+----------+--------+
     * |  1   | 2 BE  | Variable |    2     |Variable|
     * +------+-------+----------+----------+--------+
     *
     * 字段说明：
     * - ATYP: 地址类型 (0x01=IPv4, 0x03=域名, 0x04=IPv6)
     * - LEN: 数据长度（2 字节大端序），包含地址+端口+数据
     * - DST.ADDR: 目标地址
     * - DST.PORT: 目标端口（大端序）
     * - DATA: 用户数据
     *
     * 注：LEN = len(DST.ADDR) + len(DST.PORT) + len(DATA)
     */
    struct udp_frame
    {
        address destination_address;
        std::uint16_t destination_port;
    };

    /**
     * @brief UDP 帧解析结果
     */
    struct udp_frame_parse
    {
        address destination_address;
        std::uint16_t destination_port;
        std::size_t payload_offset;
        std::size_t payload_size;
    };

    /**
     * @brief 编码 Trojan UDP 帧
     * @param frame UDP 帧信息
     * @param payload 用户数据
     * @param out 输出缓冲区
     * @return gist::code 编码结果
     */
    inline auto encode_udp_frame(const udp_frame &frame,
                                 std::span<const std::byte> payload,
                                 memory::vector<std::byte> &out)
        -> gist::code
    {
        // 计算地址长度
        std::size_t addr_len = 0;
        std::visit([&addr_len]<typename Address>(const Address &addr)
                   {
            if constexpr (std::is_same_v<Address, ipv4_address>)
            {
                addr_len = 4;
            }
            else if constexpr (std::is_same_v<Address, ipv6_address>)
            {
                addr_len = 16;
            }
            else if constexpr (std::is_same_v<Address, domain_address>)
            {
                addr_len = 1 + addr.length;
            } }, frame.destination_address);

        // LEN = addr_len + port(2) + payload.size()
        std::uint16_t len = static_cast<std::uint16_t>(addr_len + 2 + payload.size());

        // ATYP
        std::visit([&out]<typename Address>(const Address &addr)
                   {
            if constexpr (std::is_same_v<Address, ipv4_address>)
            {
                out.push_back(static_cast<std::byte>(0x01));
            }
            else if constexpr (std::is_same_v<Address, ipv6_address>)
            {
                out.push_back(static_cast<std::byte>(0x04));
            }
            else if constexpr (std::is_same_v<Address, domain_address>)
            {
                out.push_back(static_cast<std::byte>(0x03));
            } }, frame.destination_address);

        // LEN (大端序)
        out.push_back(static_cast<std::byte>((len >> 8) & 0xFF));
        out.push_back(static_cast<std::byte>(len & 0xFF));

        // DST.ADDR
        std::visit([&out]<typename Address>(const Address &addr)
                   {
            if constexpr (std::is_same_v<Address, ipv4_address>)
            {
                out.insert(out.end(),
                    reinterpret_cast<const std::byte*>(addr.bytes.data()),
                    reinterpret_cast<const std::byte*>(addr.bytes.data()) + 4);
            }
            else if constexpr (std::is_same_v<Address, ipv6_address>)
            {
                out.insert(out.end(),
                    reinterpret_cast<const std::byte*>(addr.bytes.data()),
                    reinterpret_cast<const std::byte*>(addr.bytes.data()) + 16);
            }
            else if constexpr (std::is_same_v<Address, domain_address>)
            {
                out.push_back(static_cast<std::byte>(addr.length));
                out.insert(out.end(),
                    reinterpret_cast<const std::byte*>(addr.value.data()),
                    reinterpret_cast<const std::byte*>(addr.value.data()) + addr.length);
            } }, frame.destination_address);

        // DST.PORT (大端序)
        out.push_back(static_cast<std::byte>((frame.destination_port >> 8) & 0xFF));
        out.push_back(static_cast<std::byte>(frame.destination_port & 0xFF));

        // DATA
        out.insert(out.end(), payload.begin(), payload.end());

        return gist::code::success;
    }

    /**
     * @brief 解码 Trojan UDP 帧
     * @param buffer UDP 帧缓冲区
     * @return std::pair<gist::code, udp_frame_parse> 解码结果
     * @details 解析 UDP 帧，返回目标地址、端口和数据偏移
     */
    inline auto decode_udp_frame(std::span<const std::byte> buffer)
        -> std::pair<gist::code, udp_frame_parse>
    {
        // 最小长度：ATYP(1) + LEN(2) + IPv4(4) + PORT(2) = 9
        if (buffer.size() < 9)
        {
            return {gist::code::bad_message, {}};
        }

        address_type atyp = static_cast<address_type>(static_cast<std::uint8_t>(buffer[0]));
        std::uint16_t len = (static_cast<std::uint16_t>(buffer[1]) << 8) |
                            static_cast<std::uint16_t>(buffer[2]);

        if (buffer.size() < static_cast<std::size_t>(3 + len))
        {
            return {gist::code::bad_message, {}};
        }

        std::size_t offset = 3;
        address dest_addr;
        std::size_t addr_size = 0;

        switch (atyp)
        {
        case address_type::ipv4:
        {
            if (len < 4 + 2)
            {
                return {gist::code::bad_message, {}};
            }
            auto addr_span = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(buffer.data() + offset), 4);
            auto [ec, addr] = parse_ipv4(addr_span);
            if (gist::failed(ec))
            {
                return {ec, {}};
            }
            dest_addr = addr;
            addr_size = 4;
            break;
        }
        case address_type::ipv6:
        {
            if (len < 16 + 2)
            {
                return {gist::code::bad_message, {}};
            }
            auto addr_span = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(buffer.data() + offset), 16);
            auto [ec, addr] = parse_ipv6(addr_span);
            if (gist::failed(ec))
            {
                return {ec, {}};
            }
            dest_addr = addr;
            addr_size = 16;
            break;
        }
        case address_type::domain:
        {
            if (len < 1)
            {
                return {gist::code::bad_message, {}};
            }
            std::uint8_t domain_len = static_cast<std::uint8_t>(buffer[offset]);
            if (len < 1 + domain_len + 2)
            {
                return {gist::code::bad_message, {}};
            }
            auto domain_span = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(buffer.data() + offset), 1 + domain_len);
            auto [ec, addr] = parse_domain(domain_span);
            if (gist::failed(ec))
            {
                return {ec, {}};
            }
            dest_addr = addr;
            addr_size = 1 + domain_len;
            break;
        }
        default:
            return {gist::code::unsupported_address, {}};
        }

        offset += addr_size;
        auto port_span = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(buffer.data() + offset), 2);
        auto [port_ec, port] = decode_port(port_span);
        if (gist::failed(port_ec))
        {
            return {port_ec, {}};
        }

        offset += 2;
        std::size_t payload_size = len - addr_size - 2;

        udp_frame_parse result;
        result.destination_address = dest_addr;
        result.destination_port = port;
        result.payload_offset = offset;
        result.payload_size = payload_size;

        return {gist::code::success, result};
    }
}
