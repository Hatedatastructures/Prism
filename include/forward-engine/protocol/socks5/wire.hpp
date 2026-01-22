#pragma once
#include <span>
#include <system_error>
#include <cstring>
#include <forward-engine/protocol/socks5/message.hpp>

namespace ngx::protocol::socks5::wire
{
    /**
     * @brief 解析头部部分
     */
    struct header_parse
    {
        /**
         * @brief SOCKS5 版本号
         */
        std::uint8_t version;
        /**
         * @brief 命令类型
         */
        command cmd;
        /**
         * @brief 保留字段 (必须为 0x00)
         */
        std::uint8_t rsv;
        /**
         * @brief 地址类型
         */
        address_type atyp;
    };

    /**
     * @brief 解析请求头部
     * @param buffer 数据缓冲区 (至少 4 字节)
     * @return `std::pair<std::error_code, header_parse>`
     */
    inline std::pair<std::error_code, header_parse> decode_header(std::span<const std::uint8_t> buffer)
    {
        if (buffer.size() < 4)
        {
            return {std::make_error_code(std::errc::bad_message), {}};
        }

        if (buffer[0] != 0x05)
        {
            return {std::make_error_code(std::errc::protocol_error), {}};
        }

        return {std::error_code{}, {buffer[0], static_cast<command>(buffer[1]), buffer[2], static_cast<address_type>(buffer[3])}};
    }

    /**
     * @brief 解析 IPv4 地址
     * @param buffer 数据缓冲区 (至少 4 字节)
     * @return `std::pair<std::error_code, ipv4_address>`
     */
    inline std::pair<std::error_code, ipv4_address> decode_ipv4(std::span<const std::uint8_t> buffer)
    {
        if (buffer.size() < 4)
        {
            return {std::make_error_code(std::errc::bad_message), {}};
        }
        ipv4_address addr;
        std::memcpy(addr.bytes.data(), buffer.data(), 4);
        return {std::error_code{}, addr};
    }

    /**
     * @brief 解析 IPv6 地址
     * @param buffer 数据缓冲区 (至少 16 字节)
     * @return `std::pair<std::error_code, ipv6_address>`
     */
    inline std::pair<std::error_code, ipv6_address> decode_ipv6(std::span<const std::uint8_t> buffer)
    {
        if (buffer.size() < 16)
        {
            return {std::make_error_code(std::errc::bad_message), {}};
        }
        ipv6_address addr;
        std::memcpy(addr.bytes.data(), buffer.data(), 16);
        return {std::error_code{}, addr};
    }

    /**
     * @brief 解析域名
     * @param buffer 数据缓冲区 (包括长度字节)
     * @return `std::pair<std::error_code, domain_address>`
     */
    inline std::pair<std::error_code, domain_address> decode_domain(std::span<const std::uint8_t> buffer)
    {
        if (buffer.empty())
        {
            return {std::make_error_code(std::errc::bad_message), {}};
        }
        std::uint8_t len = buffer[0];
        if (buffer.size() < static_cast<size_t>(1 + len))
        {
            return {std::make_error_code(std::errc::bad_message), {}};
        }
        domain_address addr;
        addr.length = len;
        std::memcpy(addr.value.data(), buffer.data() + 1, len);
        return {std::error_code{}, addr};
    }

    /**
     * @brief 解析端口
     * @param buffer 数据缓冲区 (2 字节)
     * @return `std::pair<std::error_code, uint16_t>` (主机字节序)
     */
    inline std::pair<std::error_code, uint16_t> decode_port(std::span<const std::uint8_t> buffer)
    {
        if (buffer.size() < 2)
        {
            return {std::make_error_code(std::errc::bad_message), 0};
        }
        uint16_t port = (static_cast<uint16_t>(buffer[0]) << 8) | static_cast<uint16_t>(buffer[1]);
        return {std::error_code{}, port};
    }
}
