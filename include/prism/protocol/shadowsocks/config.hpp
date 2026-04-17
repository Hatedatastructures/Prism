/**
 * @file config.hpp
 * @brief SS2022 协议配置
 * @details 定义 SS2022 协议的运行时配置结构，包括 PSK、
 * 加密方法选择、TCP/UDP 开关和时间戳窗口参数
 */
#pragma once

#include <prism/memory/container.hpp>

namespace psm::protocol::shadowsocks
{
    /**
     * @struct config
     * @brief SS2022 协议配置
     * @details PSK 以 base64 编码存储，运行时解码为原始字节。
     * 解码后必须为 16 字节（AES-128）或 32 字节（AES-256/ChaCha20）。
     * method 字段用于区分 32 字节 PSK 对应的加密算法
     */
    struct config
    {
        memory::string psk; // Base64 编码的 PSK

        // 加密方法名（可选，自动推断：16B→aes-128, 32B→aes-256）
        // 显式设置时支持 "2022-blake3-chacha20-poly1305"
        memory::string method;

        bool enable_tcp = true; // 是否启用 TCP 代理
        bool enable_udp = false; // 是否启用 UDP 代理
        std::int64_t timestamp_window = 30; // 时间戳重放窗口（秒）
        std::int64_t salt_pool_ttl = 60; // Salt 池 TTL（秒）
        std::uint32_t udp_idle_timeout = 60; // UDP 会话空闲超时（秒）
    };
} // namespace psm::protocol::shadowsocks
