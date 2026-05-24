#include <prism/protocol/vless/framing.hpp>
#include <prism/protocol/common/framing.hpp>
#include <prism/fault.hpp>
#include <cstring>

namespace
{
    auto u8_sub(std::span<const std::byte> buf, std::size_t offset, std::size_t count)
        -> std::span<const std::uint8_t>
    {
        // safe: casting byte span to uint8_t span for protocol sub-range extraction, same memory layout
        return {reinterpret_cast<const std::uint8_t*>(buf.data()) + offset, count};
    }
} // namespace

namespace psm::protocol::vless::format
{
    auto parse_request(std::span<const std::uint8_t> buffer)
        -> std::optional<request>
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
            req.transport = psm::protocol::form::stream;
            break;
        case command::udp:
            req.transport = psm::protocol::form::datagram;
            break;
        case command::mux:
            req.transport = psm::protocol::form::stream;
            break;
        default:
            return std::nullopt;
        }
        req.cmd = cmd;
        offset += 1;

        // 解析端口 (2 字节大端)
        auto [port_ec, port_val] = common::framing::parse_port(buffer.subspan(offset));
        if (fault::failed(port_ec))
        {
            return std::nullopt;
        }
        req.port = port_val;
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
            auto [ec4, addr4] = common::framing::parse_ipv4(buffer.subspan(offset));
            if (ec4 != fault::code::success)
            {
                return std::nullopt;
            }
            req.destination_address = addr4;
            offset += 4;
            break;
        }
        case address_type::domain:
        {
            auto [ecd, addrd] = common::framing::parse_domain(buffer.subspan(offset));
            if (ecd != fault::code::success)
            {
                return std::nullopt;
            }
            req.destination_address = addrd;
            offset += 1 + addrd.length;
            break;
        }
        case address_type::ipv6:
        {
            auto [ec6, addr6] = common::framing::parse_ipv6(buffer.subspan(offset));
            if (ec6 != fault::code::success)
            {
                return std::nullopt;
            }
            req.destination_address = addr6;
            offset += 16;
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
            auto [ec4, addr4] = common::framing::parse_ipv4(u8_sub(buffer, offset, 4));
            if (ec4 != fault::code::success)
            {
                return {ec4, {}};
            }
            dest_addr = addr4;
            addr_size = 4;
            break;
        }
        case address_type::ipv6:
        {
            if (buffer.size() < offset + 16 + 2)
            {
                return {fault::code::bad_message, {}};
            }
            auto [ec6, addr6] = common::framing::parse_ipv6(u8_sub(buffer, offset, 16));
            if (ec6 != fault::code::success)
            {
                return {ec6, {}};
            }
            dest_addr = addr6;
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
            auto [ecd, addrd] = common::framing::parse_domain(u8_sub(buffer, offset, buffer.size() - offset));
            if (ecd != fault::code::success)
            {
                return {ecd, {}};
            }
            dest_addr = addrd;
            addr_size = 1 + domain_len;
            break;
        }
        default:
            return {fault::code::unsupported_address, {}};
        }

        offset += addr_size;

        // 解析端口 (2 字节大端)
        auto [port_ec, port] = common::framing::parse_port(u8_sub(buffer, offset, 2));
        if (fault::failed(port_ec))
        {
            return {port_ec, {}};
        }
        offset += 2;

        // Payload 为地址+端口之后的全部数据（与 Trojan 不同，无 Length+CRLF）
        udp_parse_result result;
        result.destination_address = dest_addr;
        result.destination_port = port;
        result.payload_offset = offset;
        result.payload_size = buffer.size() - offset;

        return {fault::code::success, result};
    }

    auto build_udp_packet(const udp_frame &frame, std::span<const std::byte> payload, memory::vector<std::byte> &out)
        -> fault::code
    {
        // 预分配：最大地址长度(1+16) + port(2) + payload
        out.reserve(out.size() + 19 + payload.size());

        // 写入 SOCKS5 风格地址 (ATYP + ADDR)
        std::visit([&out]<typename Address>(const Address &addr)
                   {
            if constexpr (std::is_same_v<Address, ipv4_address>)
            {
                out.push_back(static_cast<std::byte>(address_type::ipv4));
                // safe: casting IPv4 address bytes (array<uint8_t,4>) to byte span for serialization
                out.insert(out.end(),
                           reinterpret_cast<const std::byte*>(addr.bytes.data()),
                           reinterpret_cast<const std::byte*>(addr.bytes.data()) + 4);
            }
            else if constexpr (std::is_same_v<Address, ipv6_address>)
            {
                out.push_back(static_cast<std::byte>(address_type::ipv6));
                // safe: casting IPv6 address bytes (array<uint8_t,16>) to byte span for serialization
                out.insert(out.end(),
                           reinterpret_cast<const std::byte*>(addr.bytes.data()),
                           reinterpret_cast<const std::byte*>(addr.bytes.data()) + 16);
            }
            else if constexpr (std::is_same_v<Address, domain_address>)
            {
                out.push_back(static_cast<std::byte>(address_type::domain));
                out.push_back(static_cast<std::byte>(addr.length));
                // safe: casting domain string bytes to byte span for wire serialization
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
