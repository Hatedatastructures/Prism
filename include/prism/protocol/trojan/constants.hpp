/**
 * @file constants.hpp
 * @brief Trojan 协议常量定义
 * @details 定义 Trojan 协议的命令字和地址类型枚举。命令字用于
 * 区分 TCP 隧道连接和 UDP 关联请求，地址类型用于标识目标地址
 * 的格式（IPv4、IPv6 或域名）。这些常量遵循 Trojan 协议规范。
 */
#pragma once

#include <cstdint>

/**
 * @namespace psm::protocol::trojan
 * @brief Trojan 协议实现
 * @details 实现 Trojan 协议的数据结构和处理逻辑，包含地址解析、
 * 密码哈希验证和流量转发封装。遵循 Trojan 协议规范。
 */
namespace psm::protocol::trojan
{
    /**
     * @enum command
     * @brief Trojan 协议命令字
     * @details 定义 Trojan 协议支持的命令类型。CONNECT 命令用于
     * 建立 TCP 隧道，UDP_ASSOCIATE 命令用于建立 UDP over TLS 关联。
     * 命令字出现在协议头部的固定位置，用于指示客户端请求的操作类型。
     */
    enum class command : std::uint8_t
    {
        // 建立 TCP 隧道连接，值 0x01
        connect = 0x01,

        // 建立 UDP over TLS 关联，值 0x03
        udp_associate = 0x03,

        // Mihomo smux 多路复用命令，值 0x7f
        mux = 0x7f
    };

    /**
     * @enum address_type
     * @brief Trojan 协议地址类型
     * @details 定义 Trojan 协议支持的地址类型。地址类型字段用于
     * 指示后续地址数据的格式和长度。IPv4 地址占用 4 字节，IPv6
     * 地址占用 16 字节，域名地址以长度前缀格式编码，最大 255 字节。
     */
    enum class address_type : std::uint8_t
    {
        // IPv4 地址，值 0x01，占用 4 字节
        ipv4 = 0x01,

        // 域名地址，值 0x03，格式为长度前缀加域名内容
        domain = 0x03,

        // IPv6 地址，值 0x04，占用 16 字节
        ipv6 = 0x04
    };
}
