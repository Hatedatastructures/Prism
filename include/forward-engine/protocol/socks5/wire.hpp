/**
 * @file wire.hpp
 * @brief SOCKS5 协议线级解析
 * @details 提供 SOCKS5 协议报文的底层解析函数，包括头部、IPv4、IPv6、域名和端口的解码。
 */
#pragma once

#include <cstdint>
#include <utility>
#include <span>
#include <tuple>

#include <forward-engine/gist.hpp>
#include <forward-engine/protocol/socks5/constants.hpp>
#include <forward-engine/protocol/socks5/message.hpp>

namespace ngx::protocol::socks5::wire
{
    /**
     * @brief 头部解析结果
     * @details 包含命令类型和地址类型。
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
     * @return `std::pair<gist::code, header_parse>`
     */
    inline auto decode_header(std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, header_parse>
    {
        if (buffer.size() < 4)
        {
            return {gist::code::bad_message, {}};
        }

        if (buffer[0] != 0x05)
        {
            return {gist::code::protocol_error, {}};
        }

        return {gist::code::success, {buffer[0], static_cast<command>(buffer[1]), buffer[2], static_cast<address_type>(buffer[3])}};
    }

    /**
     * @brief 解析 IPv4 地址
     * @param buffer 数据缓冲区 (至少 4 字节)
     * @return `std::pair<gist::code, ipv4_address>`
     */
    inline auto decode_ipv4(const std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, ipv4_address>
    {
        if (buffer.size() < 4)
        {
            return {gist::code::bad_message, {}};
        }
        ipv4_address addr;
        std::memcpy(addr.bytes.data(), buffer.data(), 4);
        return {gist::code::success, addr};
    }

    /**
     * @brief 解析 IPv6 地址
     * @param buffer 数据缓冲区 (至少 16 字节)
     * @return `std::pair<gist::code, ipv6_address>`
     */
    inline auto decode_ipv6(const std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, ipv6_address>
    {
        if (buffer.size() < 16)
        {
            return {gist::code::bad_message, {}};
        }
        ipv6_address addr;
        std::memcpy(addr.bytes.data(), buffer.data(), 16);
        return {gist::code::success, addr};
    }

    /**
     * @brief 解析域名
     * @param buffer 数据缓冲区 (包括长度字节)
     * @return `std::pair<gist::code, domain_address>`
     */
    inline auto decode_domain(const std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, domain_address>
    {
        if (buffer.empty())
        {
            return {gist::code::bad_message, {}};
        }
        const std::uint8_t len = buffer[0];
        if (buffer.size() < static_cast<size_t>(1 + len))
        {
            return {gist::code::bad_message, {}};
        }
        domain_address addr;
        addr.length = len;
        std::memcpy(addr.value.data(), buffer.data() + 1, len);
        return {gist::code::success, addr};
    }

    /**
     * @brief 解析端口
     * @param buffer 数据缓冲区 (2 字节)
     * @return `std::pair<gist::code, uint16_t>` (主机字节序)
     */
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
}
