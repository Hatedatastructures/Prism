/**
 * @file message.hpp
 * @brief VLESS 消息结构定义
 * @details 定义 VLESS 协议中使用的请求消息结构。地址类型通过
 * using 声明引用 protocol::common 中的共享定义，避免跨协议重复。
 * 请求结构包含命令、端口、目标地址和用户 UUID，所有结构设计为
 * 零拷贝友好
 */
#pragma once

#include <array>

#include <prism/protocol/vless/constants.hpp>
#include <prism/protocol/common/form.hpp>
#include <prism/protocol/common/address.hpp>
#include <prism/memory/container.hpp>

namespace psm::protocol::vless
{
    // 引用共享地址类型
    using protocol::common::address;
    using protocol::common::domain_address;
    using protocol::common::ipv4_address;
    using protocol::common::ipv6_address;

    /**
     * @struct request
     * @brief VLESS 请求结构
     * @details 包含完整的 VLESS 协议请求信息，包括用户 UUID、
     * 命令类型、目标端口、目标地址和传输形式
     */
    struct request
    {
        std::array<uint8_t, 16> uuid;                           // 用户 UUID（16 字节原始数据）
        command cmd;                                            // 命令类型
        uint16_t port;                                          // 目标端口，主机字节序
        address destination_address;                            // 目标地址
        psm::protocol::form form = psm::protocol::form::stream; // 传输形式，由命令类型决定
    };

    /**
     * @brief 获取地址的字符串表示
     * @details 将 IPv4、IPv6 或域名地址转换为可读的字符串格式
     * @param addr 地址变体
     * @param mr 内存资源指针
     * @return memory::string 地址字符串
     */
    [[nodiscard]] inline auto to_string(const address &addr, memory::resource_pointer mr = memory::current_resource())
        -> memory::string
    {
        return protocol::common::address_to_string(addr, mr);
    }
}
