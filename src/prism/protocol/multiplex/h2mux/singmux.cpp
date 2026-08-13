/**
 * @file singmux.cpp
 * @brief sing-mux StreamRequest 解析实现
 */

#include <prism/protocol/multiplex/h2mux/singmux.hpp>

namespace psm::multiplex::h2mux
{

    namespace
    {
        /// sing 地址类型（与 SOCKS5 不同：0x01 IPv4 / 0x03 域名 / 0x04 IPv6）
        constexpr std::uint8_t addr_ipv4 = 0x01;
        constexpr std::uint8_t addr_domain = 0x03;
        constexpr std::uint8_t addr_ipv6 = 0x04;

        /**
         * @brief 地址类型对应的地址长度（域名返回 0，需读取长度字节）
         * @param atyp 地址类型（0x01 IPv4 / 0x03 域名 / 0x04 IPv6）
         * @return 固定地址长度，域名返回 0
         */
        [[nodiscard]] constexpr auto fixed_addr_len(const std::uint8_t atyp) -> std::size_t
        {
            switch (atyp)
            {
            case addr_ipv4: return 4;
            case addr_ipv6: return 16;
            default: return 0;
            }
        }

        /**
         * @brief IPv4/6 字节数组转可读字符串
         * @param bytes 地址原始字节
         * @param atyp 地址类型（0x01 IPv4 / 0x04 IPv6）
         * @return 可读的地址字符串
         */
        [[nodiscard]] auto ip_to_string(const std::span<const std::byte> bytes, const std::uint8_t atyp)
            -> memory::string
        {
            memory::string out(memory::current_resource());
            if (atyp == addr_ipv4)
            {
                char buf[16];
                std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", static_cast<unsigned>(bytes[0]),
                              static_cast<unsigned>(bytes[1]), static_cast<unsigned>(bytes[2]),
                              static_cast<unsigned>(bytes[3]));
                out.assign(buf);
            }
            else
            {
                char buf[48];
                std::snprintf(buf, sizeof(buf),
                              "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                              static_cast<unsigned>(bytes[0]), static_cast<unsigned>(bytes[1]),
                              static_cast<unsigned>(bytes[2]), static_cast<unsigned>(bytes[3]),
                              static_cast<unsigned>(bytes[4]), static_cast<unsigned>(bytes[5]),
                              static_cast<unsigned>(bytes[6]), static_cast<unsigned>(bytes[7]),
                              static_cast<unsigned>(bytes[8]), static_cast<unsigned>(bytes[9]),
                              static_cast<unsigned>(bytes[10]), static_cast<unsigned>(bytes[11]),
                              static_cast<unsigned>(bytes[12]), static_cast<unsigned>(bytes[13]),
                              static_cast<unsigned>(bytes[14]), static_cast<unsigned>(bytes[15]));
                out.assign(buf);
            }
            return out;
        }
    } // namespace

    auto parse_sing_request(const std::span<const std::byte> data, const memory::resource_pointer mr)
        -> std::optional<sing_request>
    {
        if (data.size() < 4)
        {
            // 数据不足：调用方应累积后重试（flags 2B + atyp 1B + port 2B 最少 5B，
            // 但空目标模式 flags+port 4B 即可，按最小 4B 处理）
            return std::nullopt;
        }

        sing_request req;
        req.host = memory::string(mr);

        const std::uint16_t flags = static_cast<std::uint16_t>((static_cast<std::uint8_t>(data[0]) << 8) |
                                                               static_cast<std::uint8_t>(data[1]));
        req.udp = (flags & static_cast<std::uint16_t>(sing_flag::udp)) != 0;
        req.packet_addr = (flags & static_cast<std::uint16_t>(sing_flag::packet_addr)) != 0;

        std::size_t offset = 2;
        const std::uint8_t atyp = static_cast<std::uint8_t>(data[offset++]);

        if (atyp == addr_domain)
        {
            if (data.size() < offset + 1)
            {
                return std::nullopt;
            }
            const auto len = static_cast<std::size_t>(static_cast<std::uint8_t>(data[offset++]));
            if (len == 0 || data.size() < offset + len + 2)
            {
                return std::nullopt;
            }
            req.host.assign(reinterpret_cast<const char *>(data.data() + offset), len);
            offset += len;
            req.port = static_cast<std::uint16_t>((static_cast<std::uint8_t>(data[offset]) << 8) |
                                                  static_cast<std::uint8_t>(data[offset + 1]));
            offset += 2;
        }
        else
        {
            const auto len = fixed_addr_len(atyp);
            if (len == 0)
            {
                // 非法地址类型：consumed=0 空结果表示解析失败
                return sing_request{};
            }
            if (data.size() < offset + len + 2)
            {
                return std::nullopt;
            }
            req.host = ip_to_string(data.subspan(offset, len), atyp);
            offset += len;
            req.port = static_cast<std::uint16_t>((static_cast<std::uint8_t>(data[offset]) << 8) |
                                                  static_cast<std::uint8_t>(data[offset + 1]));
            offset += 2;
        }

        req.consumed = offset;
        return req;
    }

} // namespace psm::multiplex::h2mux
