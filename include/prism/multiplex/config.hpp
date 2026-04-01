/**
 * @file config.hpp
 * @brief 多路复用通用配置
 * @details 定义多路复用层的通用行为参数，所有 mux 协议实现
 * （smux、yamux、h2mux 等）共享此配置结构。
 * 包括最大流数、缓冲区大小、心跳间隔和 UDP 中继参数。
 *
 * @note 默认配置适用于大多数场景，可根据实际需求调整
 */
#pragma once

#include <cstdint>

namespace psm::multiplex
{
    /**
     * @struct config
     * @brief 多路复用通用配置
     * @details 控制 mux 服务端的通用行为参数。各协议实现可继承此
     * 结构添加协议特有的配置字段。mux 服务端管理多个并发流，每个
     * 新流创建时检查 max_streams 限制，每流独立连接目标服务器，
     * 流之间相互独立，互不影响。
     */
    struct config
    {
        bool enabled = false; // 是否启用多路复用服务端

        std::uint32_t max_streams = 32; // 单个 mux 会话最大并发流数

        std::uint32_t buffer_size = 4096; // 每流缓冲区大小（字节）

        std::uint32_t keepalive_interval_ms = 30000; // 心跳间隔（毫秒）

        std::uint32_t udp_idle_timeout_ms = 60000; // UDP 管道空闲超时（毫秒），超时自动关闭

        std::uint32_t udp_max_datagram = 65535; // UDP 数据报最大长度（字节）
    }; // struct config
} // namespace psm::multiplex