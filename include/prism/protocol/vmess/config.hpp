/**
 * @file config.hpp
 * @brief VMess 协议配置结构
 * @details 定义 VMess 协议的能力开关。用户 UUID 统一在
 *          agent::authentication.users 中配置，通过 user::directory
 *          查询 UUID 凭证（与 VLESS 共用）。
 */

#pragma once

#include <cstdint>

namespace psm::protocol::vmess
{

    /**
     * @struct config
     * @brief VMess 协议配置
     * @details 控制 VMess 协议的能力开关与 UDP 参数。配置结构由
     *          agent::config 持有，初始化后只读，可安全多线程读取。
     */
    struct config
    {
        bool enable_tcp = false;         // 是否允许 TCP 命令，默认禁用（须显式开启）
        bool enable_udp = false;         // 是否允许 UDP 关联，默认禁用
        bool enable_mux = false;         // 是否允许 v2ray mux 命令（cmd=0x03）
        std::uint32_t idle_timeout = 60; // UDP 会话空闲超时（秒）
        std::uint32_t max_dgram = 65535; // UDP 数据报最大长度
    };
} // namespace psm::protocol::vmess
