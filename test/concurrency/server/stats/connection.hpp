/**
 * @file connection.hpp
 * @brief 连接信息结构体定义
 * @details 定义了服务器连接信息的存储结构，包含客户端地址、请求路径、流量统计等。
 *
 * 核心特性：
 * - 完整连接状态：记录客户端 IP、端口、请求路径、用户代理等
 * - 流量统计：记录发送/接收字节数、请求计数
 * - 时间追踪：记录连接时间和最后活跃时间
 * - SSL 标识：标记连接是否使用 SSL/TLS
 *
 * @note 设计原则：
 * - 简单数据载体：仅存储连接信息，不包含业务逻辑
 * - 非线程安全：实例应在单个线程内使用
 * - 默认初始化：所有数值字段初始化为 0
 *
 */
#pragma once

#include <string>
#include <chrono>
#include <cstdint>

namespace srv::stats
{
    /**
     * @struct connection_info
     * @brief 连接信息结构体
     * @details 记录单个连接的详细信息，包括客户端地址、请求路径、流量统计等
     */
    struct connection_info final
    {
        std::string client_ip;
        std::uint16_t client_port;
        std::string request_path;
        std::string user_agent;
        std::chrono::steady_clock::time_point connect_time;
        std::chrono::steady_clock::time_point last_active;
        std::uint64_t bytes_sent;
        std::uint64_t bytes_received;
        std::uint32_t request_count;
        bool is_ssl;

        connection_info() noexcept
            : client_ip(),
              client_port(0),
              request_path(),
              user_agent(),
              connect_time(std::chrono::steady_clock::now()),
              last_active(std::chrono::steady_clock::now()),
              bytes_sent(0),
              bytes_received(0),
              request_count(0),
              is_ssl(false)
        {
        }
    };
}
