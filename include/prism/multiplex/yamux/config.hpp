/**
 * @file config.hpp
 * @brief yamux 协议配置
 * @details 定义 yamux 协议的全部配置参数，包括流数量限制、流量控制窗口、
 * 心跳和超时设置以及 UDP 中继参数。作为 multiplex::config 的 yamux
 * 子配置存在，由 agent 配置统一加载。
 */
#pragma once

#include <cstdint>

namespace psm::multiplex::yamux
{
    /**
     * @struct config
     * @brief yamux 协议配置
     * @details 控制 yamux 服务端行为的完整参数集。
     * initial_window 影响单流吞吐量，增大可提升高延迟链路的传输效率。
     * enable_ping 和 ping_interval_ms 控制 Ping 心跳行为，
     * stream_open/close_timeout_ms 控制流生命周期超时。
     */
    struct config
    {
        std::uint32_t max_streams = 32;                // 单个 mux 会话最大并发流数
        std::uint32_t buffer_size = 4096;              // 每流读取缓冲区大小（字节）
        std::uint32_t initial_window = 256 * 1024;     // 初始流窗口大小（字节），控制单流发送量
        bool enable_ping = true;                       // 是否启用心跳
        std::uint32_t ping_interval_ms = 30000;        // 心跳间隔（毫秒）
        std::uint32_t stream_open_timeout_ms = 30000;  // 流打开超时（毫秒）
        std::uint32_t stream_close_timeout_ms = 30000; // 流关闭超时（毫秒）
        std::uint32_t udp_idle_timeout_ms = 60000;     // UDP 管道空闲超时（毫秒），超时自动关闭
        std::uint32_t udp_max_datagram = 65535;        // UDP 数据报最大长度（字节）
    }; // struct config

} // namespace psm::multiplex::yamux
