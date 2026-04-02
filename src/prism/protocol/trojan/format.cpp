/**
 * @file format.cpp
 * @brief Trojan 协议格式编解码实现
 * @details 提供 Trojan 协议报文的底层解析函数实现，包括凭据解码、CRLF 验证、
 * 命令和地址类型解析、地址解析、端口解码以及 UDP 帧编解码。
 */

#include <prism/protocol/trojan/format.hpp>
#include <cstring>
#include <cctype>

namespace psm::protocol::trojan::format
{

    auto parse_credential(const std::span<const std::uint8_t> buffer)
        -> std::pair<fault::code, std::array<char, 56>>
    {
        if (buffer.size() < 56)
        {
            return {fault::code::bad_message, {}};
        }

        std::array<char, 56> credential{};
        for (size_t i = 0; i < 56; ++i)
        {
            if (!std::isxdigit(buffer[i]))
            {
                return {fault::code::protocol_error, {}};
            }
            credential[i] = static_cast<char>(buffer[i]);
        }
        return {fault::code::success, credential};
    }

    auto parse_crlf(const std::span<const std::uint8_t> buffer)
        -> fault::code
    {
        if (buffer.size() < 2)
        {
            return fault::code::bad_message;
        }
        if (buffer[0] != '\r' || buffer[1] != '\n')
        {
            return fault::code::protocol_error;
        }
        return fault::code::success;
    }

    auto parse_cmd_atyp(std::span<const std::uint8_t> buffer)
        -> std::pair<fault::code, header_parse>
    {
        if (buffer.size() < 2)
        {
            return {fault::code::bad_message, {}};
        }
        return {fault::code::success, {static_cast<command>(buffer[0]), static_cast<address_type>(buffer[1])}};
    }

    auto parse_ipv4(const std::span<const std::uint8_t> buffer)
        -> std::pair<fault::code, ipv4_address>
    {
        if (buffer.size() < 4)
        {
            return {fault::code::bad_message, {}};
        }
        ipv4_address addr{};
        std::memcpy(addr.bytes.data(), buffer.data(), 4);
        return {fault::code::success, addr};
    }

    auto parse_ipv6(const std::span<const std::uint8_t> buffer)
        -> std::pair<fault::code, ipv6_address>
    {
        if (buffer.size() < 16)
        {
            return {fault::code::bad_message, {}};
        }
        ipv6_address addr{};
        std::memcpy(addr.bytes.data(), buffer.data(), 16);
        return {fault::code::success, addr};
    }

    auto parse_domain(const std::span<const std::uint8_t> buffer)
        -> std::pair<fault::code, domain_address>
    {
        if (buffer.empty())
        {
            return {fault::code::bad_message, {}};
        }
        const std::uint8_t len = buffer[0];
        if (buffer.size() < static_cast<size_t>(1 + len))
        {
            return {fault::code::bad_message, {}};
        }
        domain_address addr{};
        if (len > addr.value.size())
        {
            return {fault::code::bad_message, {}};
        }
        addr.length = len;
        std::memcpy(addr.value.data(), buffer.data() + 1, len);
        return {fault::code::success, addr};
    }

    auto parse_port(const std::span<const std::uint8_t> buffer)
        -> std::pair<fault::code, uint16_t>
    {
        if (buffer.size() < 2)
        {
            return {fault::code::bad_message, 0};
        }
        uint16_t port = static_cast<uint16_t>(buffer[0]) << 8 | static_cast<uint16_t>(buffer[1]);
        return {fault::code::success, port};
    }

    auto build_udp_packet(const udp_frame &frame, std::span<const std::byte> payload,
                           memory::vector<std::byte> &out)
        -> fault::code
    {
        // 写入 SOCKS5 地址 (ATYP + ADDR + PORT)
        std::visit([&out]<typename Address>(const Address &addr)
                   {
        if constexpr (std::is_same_v<Address, ipv4_address>)
        {
            out.push_back(static_cast<std::byte>(0x01));
            out.insert(out.end(),
                reinterpret_cast<const std::byte*>(addr.bytes.data()),
                reinterpret_cast<const std::byte*>(addr.bytes.data()) + 4);
        }
        else if constexpr (std::is_same_v<Address, ipv6_address>)
        {
            out.push_back(static_cast<std::byte>(0x04));
            out.insert(out.end(),
                reinterpret_cast<const std::byte*>(addr.bytes.data()),
                reinterpret_cast<const std::byte*>(addr.bytes.data()) + 16);
        }
        else if constexpr (std::is_same_v<Address, domain_address>)
        {
            out.push_back(static_cast<std::byte>(0x03));
            out.push_back(static_cast<std::byte>(addr.length));
            out.insert(out.end(),
                reinterpret_cast<const std::byte*>(addr.value.data()),
                reinterpret_cast<const std::byte*>(addr.value.data()) + addr.length);
        } }, frame.destination_address);

        // 写入端口
        out.push_back(static_cast<std::byte>(frame.destination_port >> 8 & 0xFF));
        out.push_back(static_cast<std::byte>(frame.destination_port & 0xFF));

        // 写入 Length (payload 长度, 2 bytes BE)
        const auto payload_len = static_cast<std::uint16_t>(payload.size());
        out.push_back(static_cast<std::byte>(payload_len >> 8 & 0xFF));
        out.push_back(static_cast<std::byte>(payload_len & 0xFF));

        // 写入 CRLF
        out.push_back(static_cast<std::byte>('\r'));
        out.push_back(static_cast<std::byte>('\n'));

        // 写入 Payload
        out.insert(out.end(), payload.begin(), payload.end());

        return fault::code::success;
    }

    auto parse_udp_packet(std::span<const std::byte> buffer)
        -> std::pair<fault::code, udp_parse_result>
    {
        // 最小长度: ATYP(1) + IPv4(4) + PORT(2) + Length(2) + CRLF(2) = 11
        if (buffer.size() < 11)
        {
            return {fault::code::bad_message, {}};
        }

        const auto atyp = static_cast<address_type>(static_cast<std::uint8_t>(buffer[0]));
        std::size_t offset = 1; // 偏移量，初始为 ATYP 字节之后
        address dest_addr;
        std::size_t addr_size = 0;

        // 解析地址
        switch (atyp)
        {
        case address_type::ipv4:
        {
            if (buffer.size() < offset + 4 + 2)
            {
                return {fault::code::bad_message, {}};
            }
            const auto addr_span = std::span(reinterpret_cast<const std::uint8_t *>(buffer.data() + offset), 4);
            auto [ec, addr] = parse_ipv4(addr_span);
            if (fault::failed(ec))
            {
                return {ec, {}};
            }
            dest_addr = addr;
            addr_size = 4;
            break;
        }
        case address_type::ipv6:
        {
            if (buffer.size() < offset + 16 + 2)
            {
                return {fault::code::bad_message, {}};
            }
            auto addr_span = std::span(reinterpret_cast<const std::uint8_t *>(buffer.data() + offset), 16);
            auto [ec, addr] = parse_ipv6(addr_span);
            if (fault::failed(ec))
            {
                return {ec, {}};
            }
            dest_addr = addr;
            addr_size = 16;
            break;
        }
        case address_type::domain:
        {
            if (buffer.size() < offset + 1)
            {
                return {fault::code::bad_message, {}};
            }
            const auto domain_len = static_cast<std::uint8_t>(buffer[offset]);
            if (buffer.size() < offset + 1 + domain_len + 2)
            {
                return {fault::code::bad_message, {}};
            }
            const auto domain_span = std::span(
                reinterpret_cast<const std::uint8_t *>(buffer.data() + offset), 1 + domain_len);
            auto [ec, addr] = parse_domain(domain_span);
            if (fault::failed(ec))
            {
                return {ec, {}};
            }
            dest_addr = addr;
            addr_size = 1 + domain_len;
            break;
        }
        default:
            return {fault::code::unsupported_address, {}};
        }

        offset += addr_size;

        // 解析端口
        const auto port_span = std::span(reinterpret_cast<const std::uint8_t *>(buffer.data() + offset), 2);
        auto [port_ec, port] = parse_port(port_span);
        if (fault::failed(port_ec))
        {
            return {port_ec, {}};
        }
        offset += 2;

        // 解析 Length (payload 长度)
        if (buffer.size() < offset + 2)
        {
            return {fault::code::bad_message, {}};
        }
        const std::uint16_t payload_len = static_cast<std::uint16_t>(buffer[offset]) << 8 | static_cast<std::uint16_t>(buffer[offset + 1]);
        offset += 2;

        // 验证 CRLF
        if (buffer.size() < offset + 2)
        {
            return {fault::code::bad_message, {}};
        }
        if (buffer[offset] != static_cast<std::byte>('\r') || buffer[offset + 1] != static_cast<std::byte>('\n'))
        {
            return {fault::code::protocol_error, {}};
        }
        offset += 2;

        // 验证 payload 长度
        if (buffer.size() < offset + payload_len)
        {
            return {fault::code::bad_message, {}};
        }

        udp_parse_result result;
        result.destination_address = dest_addr;
        result.destination_port = port;
        result.payload_offset = offset;
        result.payload_size = payload_len;

        return {fault::code::success, result};
    }

} // namespace psm::protocol::trojan::format