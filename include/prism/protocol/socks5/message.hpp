/**
 * @file message.hpp
 * @brief SOCKS5 消息结构定义
 * @details 定义 SOCKS5 协议中使用的请求消息结构。地址类型通过
 * using 声明引用 protocol::common 中的共享定义，避免跨协议重复。
 * 所有结构设计为零拷贝友好，适用于高性能协议处理场景。
 */

#pragma once

#include <prism/protocol/socks5/constants.hpp>
#include <prism/protocol/common/form.hpp>
#include <prism/protocol/common/address.hpp>
#include <prism/memory/container.hpp>

namespace psm::protocol::socks5
{
    // 引用共享地址类型
    using protocol::common::address;
    using protocol::common::domain_address;
    using protocol::common::ipv4_address;
    using protocol::common::ipv6_address;

    /**
     * @struct request
     * @brief SOCKS5 请求结构
     * @details 封装客户端请求的完整信息，包括命令类型、目标端口、
     * 目标地址和传输形式。请求结构由 handshake 方法解析填充，
     * 传递给上层业务逻辑进行路由决策和连接建立。
     */
    struct request
    {
        // 命令类型
        command cmd;

        // 目标端口（主机字节序）
        uint16_t destination_port;

        // 目标地址
        address destination_address;

        // 传输形式（stream 或 datagram）
        form form = form::stream;
    };

    /**
     * @brief 获取地址的字符串表示
     * @param addr 地址变体
     * @param mr 内存资源指针
     * @return memory::string 地址字符串
     * @details 将地址变体转换为可读的字符串表示。IPv4 和 IPv6 地址
     * 使用 inet_ntop 进行格式化，域名直接返回原始内容。支持
     * 自定义内存分配器，适用于日志记录和调试输出场景。
     */
    [[nodiscard]] inline auto to_string(const address &addr, memory::resource_pointer mr = memory::current_resource())
        -> memory::string
    {
        return protocol::common::address_to_string(addr, mr);
    }
}
