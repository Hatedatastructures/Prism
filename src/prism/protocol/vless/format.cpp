#include <prism/protocol/vless/format.hpp>
#include <prism/fault.hpp>
#include <cstring>

namespace psm::protocol::vless::format
{
    auto parse_request(std::span<const std::uint8_t> buffer) -> std::optional<request>
    {
        // 最小长度：Version(1) + UUID(16) + AddnlInfoLen(1) + Cmd(1) + Port(2) + Atyp(1) + IPv4(4) = 26
        if (buffer.size() < 26)
        {
            return std::nullopt;
        }

        // 校验版本号
        if (buffer[0] != version)
        {
            return std::nullopt;
        }

        std::size_t offset = 1;

        // 解析 UUID (16 字节)
        request req;
        std::memcpy(req.uuid.data(), buffer.data() + offset, 16);
        offset += 16;

        // 解析附加信息长度，plain VLESS 必须为 0
        const std::uint8_t addnl_len = buffer[offset];
        if (addnl_len != 0)
        {
            return std::nullopt;
        }
        offset += 1;

        // 解析命令
        const auto cmd = static_cast<command>(buffer[offset]);
        switch (cmd)
        {
        case command::tcp:
            req.form = psm::protocol::form::stream;
            break;
        case command::udp:
            req.form = psm::protocol::form::datagram;
            break;
        case command::mux:
            req.form = psm::protocol::form::stream;
            break;
        default:
            return std::nullopt;
        }
        req.cmd = cmd;
        offset += 1;

        // 解析端口 (2 字节大端)
        if (offset + 2 > buffer.size())
        {
            return std::nullopt;
        }
        req.port = static_cast<uint16_t>(buffer[offset]) << 8 | static_cast<uint16_t>(buffer[offset + 1]);
        offset += 2;

        // 解析地址类型
        if (offset >= buffer.size())
        {
            return std::nullopt;
        }
        const auto atyp = static_cast<address_type>(buffer[offset]);
        offset += 1;

        switch (atyp)
        {
        case address_type::ipv4:
        {
            if (offset + 4 > buffer.size())
            {
                return std::nullopt;
            }
            ipv4_address addr;
            std::memcpy(addr.bytes.data(), buffer.data() + offset, 4);
            req.destination_address = addr;
            break;
        }
        case address_type::domain:
        {
            if (offset >= buffer.size())
            {
                return std::nullopt;
            }
            const std::uint8_t domain_len = buffer[offset];
            offset += 1;
            if (offset + domain_len > buffer.size() || domain_len == 0)
            {
                return std::nullopt;
            }
            domain_address addr;
            addr.length = domain_len;
            std::memcpy(addr.value.data(), buffer.data() + offset, domain_len);
            req.destination_address = addr;
            break;
        }
        case address_type::ipv6:
        {
            if (offset + 16 > buffer.size())
            {
                return std::nullopt;
            }
            ipv6_address addr;
            std::memcpy(addr.bytes.data(), buffer.data() + offset, 16);
            req.destination_address = addr;
            break;
        }
        default:
            return std::nullopt;
        }

        return req;
    }

    auto parse_udp_packet(std::span<const std::byte> buffer)
        -> std::pair<fault::code, udp_parse_result>
    {
        // 最小长度: ATYP(1) + IPv4(4) + PORT(2) = 7
        if (buffer.size() < 7)
        {
            return {fault::code::bad_message, {}};
        }

        const auto atyp = static_cast<address_type>(static_cast<std::uint8_t>(buffer[0]));
        std::size_t offset = 1;
        address dest_addr;
        std::size_t addr_size = 0;

        switch (atyp)
        {
        case address_type::ipv4:
        {
            if (buffer.size() < offset + 4 + 2)
            {
                return {fault::code::bad_message, {}};
            }
            ipv4_address addr;
            std::memcpy(addr.bytes.data(), buffer.data() + offset, 4);
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
            ipv6_address addr;
            std::memcpy(addr.bytes.data(), buffer.data() + offset, 16);
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
            domain_address addr;
            addr.length = domain_len;
            std::memcpy(addr.value.data(), buffer.data() + offset + 1, domain_len);
            dest_addr = addr;
            addr_size = 1 + domain_len;
            break;
        }
        default:
            return {fault::code::unsupported_address, {}};
        }

        offset += addr_size;

        // 解析端口 (2 字节大端)
        const std::uint16_t port =
            static_cast<std::uint16_t>(static_cast<std::uint8_t>(buffer[offset])) << 8 |
            static_cast<std::uint16_t>(static_cast<std::uint8_t>(buffer[offset + 1]));
        offset += 2;

        // Payload 为地址+端口之后的全部数据（与 Trojan 不同，无 Length+CRLF）
        udp_parse_result result;
        result.destination_address = dest_addr;
        result.destination_port = port;
        result.payload_offset = offset;
        result.payload_size = buffer.size() - offset;

        return {fault::code::success, result};
    }

    auto build_udp_packet(const udp_frame &frame, std::span<const std::byte> payload,
                          memory::vector<std::byte> &out) -> fault::code
    {
        // 预分配：最大地址长度(1+16) + port(2) + payload
        out.reserve(out.size() + 19 + payload.size());

        // 写入 SOCKS5 风格地址 (ATYP + ADDR)
        std::visit([&out]<typename Address>(const Address &addr)
                   {
            if constexpr (std::is_same_v<Address, ipv4_address>)
            {
                out.push_back(static_cast<std::byte>(address_type::ipv4));
                out.insert(out.end(),
                           reinterpret_cast<const std::byte*>(addr.bytes.data()),
                           reinterpret_cast<const std::byte*>(addr.bytes.data()) + 4);
            }
            else if constexpr (std::is_same_v<Address, ipv6_address>)
            {
                out.push_back(static_cast<std::byte>(address_type::ipv6));
                out.insert(out.end(),
                           reinterpret_cast<const std::byte*>(addr.bytes.data()),
                           reinterpret_cast<const std::byte*>(addr.bytes.data()) + 16);
            }
            else if constexpr (std::is_same_v<Address, domain_address>)
            {
                out.push_back(static_cast<std::byte>(address_type::domain));
                out.push_back(static_cast<std::byte>(addr.length));
                out.insert(out.end(),
                           reinterpret_cast<const std::byte*>(addr.value.data()),
                           reinterpret_cast<const std::byte*>(addr.value.data()) + addr.length);
            } }, frame.destination_address);

        // 写入端口 (2 字节大端)
        out.push_back(static_cast<std::byte>(frame.destination_port >> 8 & 0xFF));
        out.push_back(static_cast<std::byte>(frame.destination_port & 0xFF));

        // 写入 Payload（无 Length + CRLF，与 Trojan 不同）
        out.insert(out.end(), payload.begin(), payload.end());

        return fault::code::success;
    }

} // namespace psm::protocol::vless::format
