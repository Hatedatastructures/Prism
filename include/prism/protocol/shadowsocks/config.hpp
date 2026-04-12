/**
 * @file config.hpp
 * @brief SS2022 协议配置
 * @details 定义 SS2022 协议的运行时配置结构，包括 PSK、
 * 时间戳窗口和 salt 池参数。
 */

#pragma once

#include <prism/memory/container.hpp>

namespace psm::protocol::shadowsocks
{
    /**
     * @struct config
     * @brief SS2022 协议配置
     * @details PSK 以 base64 编码存储，运行时解码为原始字节。
     * 解码后必须为 16 字节（AES-128）或 32 字节（AES-256）。
     */
    struct config
    {
        /// Base64 编码的 PSK
        memory::string psk;

        /// 是否启用 TCP 代理
        bool enable_tcp = true;

        /// 时间戳重放窗口（秒）
        std::int64_t timestamp_window = 30;

        /// Salt 池 TTL（秒）
        std::int64_t salt_pool_ttl = 60;
    };
} // namespace psm::protocol::shadowsocks
