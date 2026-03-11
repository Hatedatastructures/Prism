/**
 * @file config.hpp
 * @brief SOCKS5 协议配置结构
 * @details 定义了 SOCKS5 协议的能力开关和 UDP relay 配置参数。
 * 该配置用于控制协议层支持的命令类型和 UDP 中继行为。
 *
 * 默认值设计：
 * - TCP 默认启用（最常用场景）
 * - UDP 默认禁用（需要额外资源）
 * - BIND 默认禁用（安全考虑）
 *
 * @note 配置在 stream 构造时传入，运行时不可修改
 * @see ngx::protocol::socks5::stream
 */

#pragma once

namespace ngx::protocol::socks5
{
    /**
     * @struct config
     * @brief SOCKS5 协议配置
     * @details 控制 SOCKS5 协议的能力开关和 UDP relay 参数。
     * 该配置由 agent::config 持有，随服务启动时初始化，并传递给 socks5::stream 构造函数，
     * 在 stream 生命周期内保持不变。配置结构本身是只读的，可安全多线程读取；修改配置需要重启服务。
     */
    struct config
    {
        bool enable_tcp = true; // 是否允许 CONNECT 命令（TCP 隧道）

        bool enable_udp = true; // 是否允许 UDP_ASSOCIATE 命令（UDP 中继）

        bool enable_bind = false; // 是否允许 BIND 命令（通常禁用）

        std::uint16_t udp_bind_port = 0; // UDP relay 绑定端口，0 表示自动分配

        std::uint32_t udp_idle_timeout = 60; // UDP 会话空闲超时（秒）

        std::uint32_t udp_max_datagram = 65535; // UDP 数据报最大长度
    };
}
