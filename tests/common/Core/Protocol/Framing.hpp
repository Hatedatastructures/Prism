/**
 * @file Framing.hpp
 * @brief 共享协议帧解析函数
 * @details 提供跨协议通用的地址和端口线级解析函数，包括 IPv4、IPv6、
 * 域名地址和大端序端口。各协议 (SOCKS5/Trojan/VLESS/Shadowsocks)
 * 通过 using 声明或直接调用复用这些函数，消除四处重复的 memcpy 实现。
 * 所有函数为 inline constexpr，零开销，直接操作字节缓冲区。
 */

#pragma once

#include <common/Core/Fault/Code.hpp>
#include <common/Core/Protocol/Address.hpp>

#include <cstdint>
#include <cstring>
#include <span>
#include <utility>

namespace Preview::Protocol::Common::Framing
{

    /**
     * @brief 解析 IPv4 地址
     * @param Buffer 包含 IPv4 地址的缓冲区，至少 4 字节
     * @return 错误码和 IPv4 地址结构
     */
    [[nodiscard]] inline auto ParseIpv4(std::span<const std::uint8_t> Buffer)
        -> std::pair<Fault::Code, Ipv4Address>
    {
        if (Buffer.size() < 4)
        {
            return {Fault::Code::BadMessage, {}};
        }
        Ipv4Address addr{};
        std::memcpy(addr.Bytes.data(), Buffer.data(), 4);
        return {Fault::Code::Success, addr};
    }

    /**
     * @brief 解析 IPv6 地址
     * @param Buffer 包含 IPv6 地址的缓冲区，至少 16 字节
     * @return 错误码和 IPv6 地址结构
     */
    [[nodiscard]] inline auto ParseIpv6(std::span<const std::uint8_t> Buffer)
        -> std::pair<Fault::Code, Ipv6Address>
    {
        if (Buffer.size() < 16)
        {
            return {Fault::Code::BadMessage, {}};
        }
        Ipv6Address addr{};
        std::memcpy(addr.Bytes.data(), Buffer.data(), 16);
        return {Fault::Code::Success, addr};
    }

    /**
     * @brief 解析域名地址
     * @param Buffer 包含域名地址的缓冲区，格式为 LEN(1) + DOMAIN(n)
     * @return 错误码和域名地址结构
     */
    [[nodiscard]] inline auto ParseDomain(std::span<const std::uint8_t> Buffer)
        -> std::pair<Fault::Code, DomainAddress>
    {
        if (Buffer.empty())
        {
            return {Fault::Code::BadMessage, {}};
        }
        const std::uint8_t Len = Buffer[0];
        if (Buffer.size() < static_cast<std::size_t>(1 + Len))
        {
            return {Fault::Code::BadMessage, {}};
        }
        DomainAddress addr{};
        if (Len > addr.value.size())
        {
            return {Fault::Code::BadMessage, {}};
        }
        addr.length = Len;
        std::memcpy(addr.value.data(), Buffer.data() + 1, Len);
        return {Fault::Code::Success, addr};
    }

    /**
     * @brief 解析端口号（大端序）
     * @param Buffer 包含端口号的缓冲区，至少 2 字节
     * @return 错误码和端口号
     */
    [[nodiscard]] inline auto ParsePort(std::span<const std::uint8_t> Buffer)
        -> std::pair<Fault::Code, std::uint16_t>
    {
        if (Buffer.size() < 2)
        {
            return {Fault::Code::BadMessage, 0};
        }
        std::uint16_t Port =
            static_cast<std::uint16_t>(Buffer[0]) << 8 | static_cast<std::uint16_t>(Buffer[1]);
        return {Fault::Code::Success, Port};
    }
} // namespace Preview::Protocol::Common::Framing
