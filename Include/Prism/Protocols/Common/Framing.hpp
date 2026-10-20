/**
 * @file Framing.hpp
 * @brief 共享协议帧解析函数
 * @details 提供跨协议通用的地址和端口线级解析函数，包括 IPv4、IPv6、
 * 域名地址和大端序端口。各协议 (SOCKS5/Trojan/VLESS/Shadowsocks)
 * 通过 using 声明或直接调用复用这些函数，消除四处重复的 memcpy 实现。
 * 解析入口在 Common owner 编译单元内实现，直接读取调用方提供的字节视图。
 */

#pragma once

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Protocols/Common/Address.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace Prism::Protocol::Common::Framing
{

    /**
     * @brief 解析 IPv4 地址
     * @param Buffer 包含 IPv4 地址的缓冲区，至少 4 字节
     * @return 错误码和 IPv4 地址结构
     */
    [[nodiscard]] auto ParseIpv4(std::span<const std::uint8_t> Buffer)
        -> std::pair<Fault::Code, Ipv4Address>;

    /**
     * @brief 解析 IPv6 地址
     * @param Buffer 包含 IPv6 地址的缓冲区，至少 16 字节
     * @return 错误码和 IPv6 地址结构
     */
    [[nodiscard]] auto ParseIpv6(std::span<const std::uint8_t> Buffer)
        -> std::pair<Fault::Code, Ipv6Address>;

    /**
     * @brief 解析域名地址
     * @param Buffer 包含域名地址的缓冲区，格式为 LEN(1) + DOMAIN(n)
     * @return 错误码和域名地址结构
     */
    [[nodiscard]] auto ParseDomain(std::span<const std::uint8_t> Buffer)
        -> std::pair<Fault::Code, DomainAddress>;

    /**
     * @brief 解析端口号（大端序）
     * @param Buffer 包含端口号的缓冲区，至少 2 字节
     * @return 错误码和端口号
     */
    [[nodiscard]] auto ParsePort(std::span<const std::uint8_t> Buffer)
        -> std::pair<Fault::Code, std::uint16_t>;
} // namespace Prism::Protocol::Common::Framing
