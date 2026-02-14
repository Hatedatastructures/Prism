/**
 * @file wire.hpp
 * @brief Trojan 协议线级解析
 * @details 提供 Trojan 协议报文的底层解析函数，包括密码哈希、头部、地址和端口的解码。
 */
#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <forward-engine/gist.hpp>
#include <cctype>
#include <forward-engine/protocol/trojan/message.hpp>

/**
 * @namespace ngx::protocol::trojan::wire
 * @brief Trojan 协议线级解析
 * @details 提供底层的报文解析函数，负责处理 TCP 流中的二进制数据。
 * 包括密码哈希提取、CRLF 验证、命令字和地址类型的解析。
 */
namespace ngx::protocol::trojan::wire
{
    /**
     * @brief 头部解析结果
     * @details 包含命令类型和地址类型。
     */
    struct header_parse
    {
        command cmd;       // 命令类型
        address_type atyp; // 地址类型
    };

    /**
     * @brief 解析并验证用户凭据
     * @param buffer 数据缓冲区 (至少 56 字节)
     * @return `std::pair<gist::code, std::array<char, 56>>` 结果代码和用户凭据
     */
    inline auto decode_credential(const std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, std::array<char, 56>>
    {
        if (buffer.size() < 56)
        {
            return {gist::code::bad_message, {}};
        }

        std::array<char, 56> credential{};
        for (size_t i = 0; i < 56; ++i)
        { // 检查每个字符是否为十六进制
            if (!std::isxdigit(buffer[i]))
            {
                return {gist::code::protocol_error, {}};
            }
            credential[i] = static_cast<char>(buffer[i]);
        }
        return {gist::code::success, credential};
    }

    /**
     * @brief 验证 CRLF
     * @param buffer 数据缓冲区 (至少 2 字节)
     * @return `gist::code` 验证结果
     */
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

    /**
     * @brief 解析 Command 和 Address Type
     * @param buffer 数据缓冲区 (至少 2 字节)
     * @return `std::pair<gist::code, header_parse>` 解析结果
     */
    inline auto decode_cmd_atyp(std::span<const std::uint8_t> buffer)
        -> std::pair<gist::code, header_parse>
    {
        if (buffer.size() < 2)
        {
            return {gist::code::bad_message, {}};
        }
        return {gist::code::success, {static_cast<command>(buffer[0]), static_cast<address_type>(buffer[1])}};
    }

    /**
     * @brief 解析 IPv4 地址
     * @param buffer 数据缓冲区 (至少 4 字节)
     * @return `std::pair<gist::code, ipv4_address>` 解析结果
     */
    inline auto decode_ipv4(const std::span<const std::uint8_t> buffer)
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

    /**
     * @brief 解析 IPv6 地址
     * @param buffer 数据缓冲区 (至少 16 字节)
     * @return `std::pair<gist::code, ipv6_address>` 解析结果
     */
    inline auto decode_ipv6(const std::span<const std::uint8_t> buffer)
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

    /**
     * @brief 解析域名
     * @param buffer 数据缓冲区 (包括长度字节)
     * @return `std::pair<gist::code, domain_address>` 解析结果
     */
    inline auto decode_domain(const std::span<const std::uint8_t> buffer)
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
        addr.length = len;
        std::memcpy(addr.value.data(), buffer.data() + 1, len);
        return {gist::code::success, addr};
    }

    /**
     * @brief 解析端口
     * @param buffer 数据缓冲区 (2 字节，大端序)
     * @return `std::pair<gist::code, uint16_t>` 解析结果 (主机字节序)
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
