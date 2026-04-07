/**
 * @file config.hpp
 * @brief smux 协议配置
 * @details 定义 smux 协议的全部配置参数，包括流数量限制、读取缓冲区、
 * 保活心跳和 UDP 中继参数。作为 multiplex::config 的 smux 子配置存在，
 * 由 agent 配置统一加载。
 */
#pragma once

#include <cstdint>

namespace psm::multiplex::smux
{
    /**
     * @struct config
     * @brief smux 协议配置
     * @details 控制 smux 服务端行为的完整参数集。
     * max_streams 限制单会话并发流数，buffer_size 控制每流
     * target 读取的单次数据量上限（不超过帧最大载荷 65535），
     * keepalive_interval_ms 控制 NOP 心跳帧发送间隔。
     */
    struct config
    {
        std::uint32_t max_streams = 32;              // 单个 mux 会话最大并发流数
        std::uint32_t buffer_size = 4096;            // 每流读取缓冲区大小（字节），实际限制为 min(buffer_size, 65535)
        std::uint32_t keepalive_interval_ms = 30000; // 心跳间隔（毫秒），0 表示禁用心跳
        std::uint32_t udp_idle_timeout_ms = 60000;   // UDP 管道空闲超时（毫秒），超时自动关闭
        std::uint32_t udp_max_datagram = 65535;      // UDP 数据报最大长度（字节）
    }; // struct config

} // namespace psm::multiplex::smux
