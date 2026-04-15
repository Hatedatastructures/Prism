/**
 * @file message.hpp
 * @brief Trojan 消息结构定义
 * @details 定义 Trojan 协议中使用的请求消息结构。地址类型通过
 * using 声明引用 protocol::common 中的共享定义，避免跨协议重复。
 * 请求结构包含命令、端口、目标地址和用户凭据，所有结构设计为
 * 零拷贝友好。
 */

#pragma once

#include <array>

#include <boost/asio/ip/address.hpp>
#include <prism/protocol/trojan/constants.hpp>
#include <prism/protocol/common/form.hpp>
#include <prism/protocol/common/address.hpp>
#include <prism/memory/container.hpp>

/**
 * @namespace psm::protocol::trojan
 * @brief Trojan 协议实现
 * @details 实现 Trojan 协议的数据结构和处理逻辑，包含地址解析、
 * 密码哈希验证和流量转发封装。遵循 Trojan 协议规范。
 */
namespace psm::protocol::trojan
{
    // 引用共享地址类型
    using protocol::common::ipv4_address;
    using protocol::common::ipv6_address;
    using protocol::common::domain_address;
    using protocol::common::address;

    /**
     * @struct request
     * @brief Trojan 请求结构
     * @details 包含完整的 Trojan 协议请求信息，包括命令类型、
     * 目标端口、目标地址、用户凭据和传输形式。该结构由握手
     * 过程填充，后续用于路由和转发决策。
     *
     * @note 凭据长度固定为 56 字节，通常为密码的 SHA224 哈希
     */
    struct request
    {
        // 命令类型
        command cmd;

        // 目标端口，网络字节序
        uint16_t port;

        // 目标地址
        address destination_address;

        // 用户凭据，56 字节 SHA224 哈希
        std::array<char, 56> credential;

        // 传输形式，由命令类型决定
        psm::protocol::form form = psm::protocol::form::stream;
    };

    /**
     * @brief 获取地址的字符串表示
     * @param addr 地址变体
     * @param mr 内存资源指针，默认为全局资源
     * @return memory::string 地址字符串
     * @details 将 IPv4、IPv6 或域名地址转换为可读的字符串格式。
     * 返回的字符串使用指定的内存资源分配。
     */
    [[nodiscard]] inline auto to_string(const address &addr, memory::resource_pointer mr = memory::current_resource())
        -> memory::string
    {
        return protocol::common::address_to_string(addr, mr);
    }
}
