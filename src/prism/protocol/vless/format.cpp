/**
 * @file format.cpp
 * @brief VLESS 协议格式编解码实现
 * @details 提供 VLESS 协议报文的底层解析函数实现，包括请求解析。
 */

#include <prism/protocol/vless/format.hpp>
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

} // namespace psm::protocol::vless::format
