/**
 * @file constants.hpp
 * @brief VLESS 协议常量定义
 * @details 定义 VLESS 协议的版本号、命令字和地址类型枚举。
 * VLESS 协议运行在 TLS 内层，本身不提供加密。命令字用于区分
 * TCP 连接、UDP 关联和多路复用请求，地址类型用于标识目标地址
 * 的格式（IPv4、IPv6 或域名）
 */
#pragma once

#include <cstdint>

namespace psm::protocol::vless
{
    // 协议版本号，固定为 0x00
    constexpr std::uint8_t version = 0x00;

    /**
     * @enum command
     * @brief VLESS 协议命令字
     * @details 定义 VLESS 协议支持的命令类型。TCP 为标准 TCP 代理，
     * UDP 为 UDP 代理，mux 为多路复用命令（与 sing-box 兼容）
     */
    enum class command : std::uint8_t
    {
        /** @brief TCP 代理，值 0x01 */
        tcp = 0x01,
        /** @brief UDP 代理，值 0x02 */
        udp = 0x02,
        /** @brief 多路复用命令，值 0x7F（sing-box 兼容） */
        mux = 0x7F
    };

    /**
     * @enum address_type
     * @brief VLESS 协议地址类型
     * @details 定义 VLESS 协议支持的地址类型。
     * 注意：VLESS 的地址类型值与 Trojan/SOCKS5 不同。
     * IPv4 = 0x01, Domain = 0x02, IPv6 = 0x03
     */
    enum class address_type : std::uint8_t
    {
        /** @brief IPv4 地址，值 0x01，占用 4 字节 */
        ipv4 = 0x01,
        /** @brief 域名地址，值 0x02，格式为长度前缀加域名内容 */
        domain = 0x02,
        /** @brief IPv6 地址，值 0x03，占用 16 字节 */
        ipv6 = 0x03
    };
}
