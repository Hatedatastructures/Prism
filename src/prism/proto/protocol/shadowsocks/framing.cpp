#include <prism/proto/protocol/shadowsocks/framing.hpp>
#include <prism/crypto/base64.hpp>
#include <prism/proto/protocol/common/framing.hpp>

#include <cstring>

namespace psm::protocol::shadowsocks::format
{

    auto parse_addr_port(const std::span<const std::uint8_t> buffer)
        -> std::pair<fault::code, addr_parse_result>
    {
        addr_parse_result result;

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
            auto [ec4, addr4] = common::framing::parse_ipv4(buffer.subspan(offset));
            if (ec4 != fault::code::success)
            {
                return {ec4, result};
            }
            offset += 4;
            result.addr = addr4;
            break;
        }
        case atyp_domain:
        {
            if (buffer.size() < 1 + 1)
            {
                return {fault::code::bad_message, result};
            }
            auto [ecd, addrd] = common::framing::parse_domain(buffer.subspan(offset));
            if (ecd != fault::code::success)
            {
                return {ecd, result};
            }
            offset += 1 + addrd.length;
            result.addr = addrd;
            break;
        }
        case atyp_ipv6:
        {
            if (buffer.size() < 1 + 16 + 2)
            {
                return {fault::code::bad_message, result};
            }
            auto [ec6, addr6] = common::framing::parse_ipv6(buffer.subspan(offset));
            if (ec6 != fault::code::success)
            {
                return {ec6, result};
            }
            offset += 16;
            result.addr = addr6;
            break;
        }
        default:
            return {fault::code::unsupported_address, result};
        }

        // 读取端口（2 字节大端序）
        auto [port_ec, port_val] = common::framing::parse_port(buffer.subspan(offset));
        if (fault::failed(port_ec))
        {
            return {port_ec, result};
        }
        result.port = port_val;
        offset += 2;

        result.offset = offset;
        return {fault::code::success, result};
    }


    auto decode_psk(const std::string_view base64_psk)
        -> std::pair<fault::code, memory::vector<std::uint8_t>>
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

        memory::vector<std::uint8_t> psk(decoded.size(), memory::current_resource());
        std::memcpy(psk.data(), decoded.data(), decoded.size());
        return {fault::code::success, std::move(psk)};
    }


    auto resolve_method(const std::string_view method_str, const std::size_t psk_len) noexcept
        -> cipher_method
    {
        if (!method_str.empty())
        {
            if (method_str == method_aes_128)
            {
                return cipher_method::aes_128_gcm;
            }
            if (method_str == method_aes_256)
            {
                return cipher_method::aes_256_gcm;
            }
            if (method_str == method_chacha20)
            {
                return cipher_method::chacha20_poly1305;
            }
        }

        // 自动推断：16B → aes-128, 32B → aes-256
        if (psk_len == 16)
            return cipher_method::aes_128_gcm;
        return cipher_method::aes_256_gcm;
    }

} // namespace psm::protocol::shadowsocks::format
