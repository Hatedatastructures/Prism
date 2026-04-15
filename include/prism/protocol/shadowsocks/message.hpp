/**
 * @file message.hpp
 * @brief SS2022 消息结构定义
 * @details 定义 SS2022 协议中使用的请求消息结构。地址类型通过
 * using 声明引用 protocol::common 中的共享定义，避免跨协议重复。
 * 地址格式与 SOCKS5 兼容，支持 IPv4、IPv6 和域名。
 */

#pragma once

#include <prism/protocol/shadowsocks/constants.hpp>
#include <prism/protocol/common/address.hpp>
#include <prism/memory/container.hpp>

namespace psm::protocol::shadowsocks
{
    // 引用共享地址类型
    using protocol::common::ipv4_address;
    using protocol::common::ipv6_address;
    using protocol::common::domain_address;
    using protocol::common::address;

    /// SS2022 请求结构（由 handshake 填充）
    struct request
    {
        /// 加密算法
        cipher_method method;

        /// 目标端口
        std::uint16_t port{0};

        /// 目标地址
        address destination_address;

        /// 握手中的初始 payload（可能为空）
        memory::vector<std::byte> initial_payload;
    };

    /**
     * @brief 获取地址的字符串表示
     * @param addr 地址变体
     * @param mr 内存资源指针
     * @return 地址字符串
     */
    [[nodiscard]] inline auto to_string(const address &addr, const memory::resource_pointer mr = memory::current_resource())
        -> memory::string
    {
        return protocol::common::address_to_string(addr, mr);
    }
} // namespace psm::protocol::shadowsocks
