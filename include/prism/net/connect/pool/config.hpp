/**
 * @file config.hpp
 * @brief 连接池配置
 * @details 控制连接池的行为参数，包括缓存容量、超时、
 * 缓冲区大小等。
 */
#pragma once

#include <cstdint>


namespace psm::connect
{

    /**
     * @struct config
     * @brief 连接池配置
     * @details 控制连接池的行为参数，包括缓存容量、超时、
     * 缓冲区大小等。所有字段均有默认值。
     * @warning 设置过大的 cache_peraddr 可能导致
     * 内存压力。
     */
    struct config
    {
        std::uint32_t cache_peraddr = 32U; // 单个目标端点最大缓存连接数
        std::uint64_t conn_timeout = 300ULL;   // 连接超时（毫秒）
        std::uint64_t idle_sec = 30ULL;    // 空闲连接最大存活时间（秒）
        std::uint64_t clean_interval = 10ULL; // 后台清理间隔（秒）
        std::uint32_t recv_bufsz = 65536U;     // 接收缓冲区大小（字节）
        std::uint32_t send_bufsz = 65536U;     // 发送缓冲区大小（字节）
        bool tcp_nodelay = true;                    // 是否启用 TCP_NODELAY
        bool keep_alive = true;                     // 是否启用 SO_KEEPALIVE
        bool cache_ipv6 = false;                    // 是否缓存 IPv6 连接
    }; // struct config
} // namespace psm::connect
