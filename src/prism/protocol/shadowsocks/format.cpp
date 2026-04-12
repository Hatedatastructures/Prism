/**
 * @file format.cpp
 * @brief SS2022 协议格式编解码实现
 * @details 实现 SOCKS5 风格地址解析和 PSK base64 解码。
 */

#include <prism/protocol/shadowsocks/format.hpp>
#include <prism/crypto/base64.hpp>
#include <cstring>

namespace psm::protocol::shadowsocks::format
{
    auto parse_address_port(const std::span<const std::uint8_t> buffer)
        -> std::pair<fault::code, address_parse_result>
    {
        address_parse_result result;

        if (buffer.empty())
        {
            return {fault::code::bad_message, result};
        }

        const auto atyp = buffer[0];
        std::size_t offset = 1;

        switch (atyp)
        {
        case atyp_ipv4:
        {
            if (buffer.size() < 1 + 4 + 2)
            {
                return {fault::code::bad_message, result};
            }
            ipv4_address addr;
            std::memcpy(addr.bytes.data(), buffer.data() + offset, 4);
            offset += 4;
            result.addr = addr;
            break;
        }
        case atyp_domain:
        {
            if (buffer.size() < 1 + 1)
            {
                return {fault::code::bad_message, result};
            }
            const auto domain_len = buffer[offset];
            offset += 1;
            if (buffer.size() < offset + domain_len + 2)
            {
                return {fault::code::bad_message, result};
            }
            domain_address addr;
            addr.length = domain_len;
            std::memcpy(addr.value.data(), buffer.data() + offset, domain_len);
            offset += domain_len;
            result.addr = addr;
            break;
        }
        case atyp_ipv6:
        {
            if (buffer.size() < 1 + 16 + 2)
            {
                return {fault::code::bad_message, result};
            }
            ipv6_address addr;
            std::memcpy(addr.bytes.data(), buffer.data() + offset, 16);
            offset += 16;
            result.addr = addr;
            break;
        }
        default:
            return {fault::code::unsupported_address, result};
        }

        // 读取端口（2 字节大端序）
        if (buffer.size() < offset + 2)
        {
            return {fault::code::bad_message, result};
        }
        result.port = static_cast<std::uint16_t>(buffer[offset]) << 8 | static_cast<std::uint16_t>(buffer[offset + 1]);
        offset += 2;

        result.offset = offset;
        return {fault::code::success, result};
    }

    auto decode_psk(const std::string_view base64_psk)
        -> std::pair<fault::code, std::vector<std::uint8_t>>
    {
        if (base64_psk.empty())
        {
            return {fault::code::invalid_psk, {}};
        }

        const auto decoded = psm::crypto::base64_decode(base64_psk);
        if (decoded.size() != 16 && decoded.size() != 32)
        {
            return {fault::code::invalid_psk, {}};
        }

        std::vector<std::uint8_t> psk(decoded.size());
        std::memcpy(psk.data(), decoded.data(), decoded.size());
        return {fault::code::success, std::move(psk)};
    }
} // namespace psm::protocol::shadowsocks::format
