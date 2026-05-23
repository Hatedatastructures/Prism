/**
 * @file config.hpp
 * @brief h2mux 协议配置
 * @details 定义 h2mux（HTTP/2 CONNECT 多路复用）协议的全部配置参数。
 * h2mux 利用 HTTP/2 原生 stream 实现应用层多路复用，每个 CONNECT 请求
 * 对应一个独立的双向数据流。流量控制由 HTTP/2 标准流控自动管理，
 * 无需应用层窗口机制。
 */
#pragma once

#include <cstdint>

namespace psm::multiplex::h2mux
{
    /**
     * @struct config
     * @brief h2mux 协议配置
     * @details 控制 h2mux 服务端行为的完整参数集。
     * max_streams 限制单会话并发 HTTP/2 stream 数，
     * max_frame_size 控制单个 DATA 帧最大载荷，
     * idle_timeout_ms 控制 HTTP/2 连接空闲超时。
     */
    struct config
    {
        std::uint32_t max_streams = 256;           // 单个 mux 会话最大并发流数（HTTP/2 默认允许更多）
        std::uint32_t buffer_size = 4096;          // 每流读取缓冲区大小（字节）
        std::uint32_t max_frame_size = 16384;      // HTTP/2 最大帧载荷大小（字节），默认 16384
        std::uint32_t idle_timeout_ms = 30000;     // 连接空闲超时（毫秒）
        std::uint32_t udp_idle_timeout_ms = 60000; // UDP 管道空闲超时（毫秒），超时自动关闭
        std::uint32_t udp_max_datagram = 65535;    // UDP 数据报最大长度（字节）
    }; // struct config

} // namespace psm::multiplex::h2mux
