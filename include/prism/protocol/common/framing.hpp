/**
 * @file framing.hpp
 * @brief 共享协议帧解析函数
 * @details 提供跨协议通用的地址和端口线级解析函数，包括 IPv4、IPv6、
 * 域名地址和大端序端口。各协议 (SOCKS5/Trojan/VLESS/Shadowsocks)
 * 通过 using 声明或直接调用复用这些函数，消除四处重复的 memcpy 实现。
 * 所有函数为 inline constexpr，零开销，直接操作字节缓冲区。
 */

#pragma once

#include <prism/foundation/fault/code.hpp>
#include <prism/protocol/common/address.hpp>

#include <cstdint>
#include <cstring>
#include <span>
#include <utility>


namespace psm::protocol::common::framing
{

    /**
     * @brief 解析 IPv4 地址
     * @param buffer 包含 IPv4 地址的缓冲区，至少 4 字节
     * @return 错误码和 IPv4 地址结构
     */
    [[nodiscard]] inline auto parse_ipv4(const std::span<const std::uint8_t> buffer)
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

    /**
     * @brief 解析 IPv6 地址
     * @param buffer 包含 IPv6 地址的缓冲区，至少 16 字节
     * @return 错误码和 IPv6 地址结构
     */
    [[nodiscard]] inline auto parse_ipv6(const std::span<const std::uint8_t> buffer)
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

    /**
     * @brief 解析域名地址
     * @param buffer 包含域名地址的缓冲区，格式为 LEN(1) + DOMAIN(n)
     * @return 错误码和域名地址结构
     */
    [[nodiscard]] inline auto parse_domain(const std::span<const std::uint8_t> buffer)
        -> std::pair<fault::code, domain_address>
    {
        if (buffer.empty())
        {
            return {fault::code::bad_message, {}};
        }
        const std::uint8_t len = buffer[0];
        if (buffer.size() < static_cast<std::size_t>(1 + len))
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

    /**
     * @brief 解析端口号（大端序）
     * @param buffer 包含端口号的缓冲区，至少 2 字节
     * @return 错误码和端口号
     */
    [[nodiscard]] inline auto parse_port(const std::span<const std::uint8_t> buffer)
        -> std::pair<fault::code, std::uint16_t>
    {
        if (buffer.size() < 2)
        {
            return {fault::code::bad_message, 0};
        }
        std::uint16_t port = static_cast<std::uint16_t>(buffer[0]) << 8 | static_cast<std::uint16_t>(buffer[1]);
        return {fault::code::success, port};
    }
} // namespace psm::protocol::common::framing
