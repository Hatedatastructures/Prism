/**
 * @file config.hpp
 * @brief VLESS 协议配置结构
 * @details 定义 VLESS 协议的配置参数。用户认证已统一到
 * agent::authentication 中，VLESS 通过 account::directory
 * 查询 UUID 凭证
 */
#pragma once

namespace psm::protocol::vless
{
    /**
     * @struct config
     * @brief VLESS 协议配置
     * @details 控制 VLESS 协议的能力开关和 UDP 参数。配置结构由
     * agent::config 持有，随服务启动时初始化，传递给 relay
     * 构造函数后在生命周期内保持不变。配置结构本身是只读的，
     * 可安全多线程读取
     */
    struct config
    {
        bool enable_udp = false;                // 是否允许 UDP 命令（UDP over TLS），默认禁用
        std::uint32_t udp_idle_timeout = 60;    // UDP 会话空闲超时时间（秒），默认 60 秒
        std::uint32_t udp_max_datagram = 65535; // UDP 数据报最大长度，默认 65535 字节
    };
} // namespace psm::protocol::vless
