/**
 * @file message.hpp
 * @brief SS2022 消息结构定义
 * @details 定义 SS2022 协议中使用的请求消息结构。地址类型通过
 * using 声明引用 protocol::common 中的共享定义，避免跨协议重复。
 * 地址格式与 SOCKS5 兼容，支持 IPv4、IPv6 和域名
 */
#pragma once

#include <prism/protocol/shadowsocks/constants.hpp>
#include <prism/protocol/common/address.hpp>
#include <prism/memory/container.hpp>

namespace psm::protocol::shadowsocks
{
    // 引用共享地址类型
    using protocol::common::address;
    using protocol::common::domain_address;
    using protocol::common::ipv4_address;
    using protocol::common::ipv6_address;

    /**
     * @struct request
     * @brief SS2022 请求结构
     * @details 由 handshake 填充，包含加密算法、目标端口和目标地址
     */
    struct request
    {
        cipher_method method;        // 加密算法
        std::uint16_t port{0};       // 目标端口
        address destination_address; // 目标地址
    };
} // namespace psm::protocol::shadowsocks
