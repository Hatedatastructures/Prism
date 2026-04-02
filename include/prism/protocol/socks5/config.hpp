/**
 * @file config.hpp
 * @brief SOCKS5 协议配置结构
 * @details 定义 SOCKS5 协议的能力开关和 UDP 中继参数。配置用于
 * 控制协议层支持的命令类型和 UDP 中继行为。默认值设计遵循最小
 * 权限原则：TCP 默认启用以满足最常用场景，UDP 默认启用以支持
 * 代理转发，BIND 默认禁用以降低安全风险。配置在 stream 构造时
 * 传入，运行时不可修改，由 agent::config 持有并随服务启动初始化。
 */

#pragma once
#include <cstdint>

namespace psm::protocol::socks5
{
    /**
     * @struct config
     * @brief SOCKS5 协议配置
     * @details 控制 SOCKS5 协议的能力开关和 UDP relay 参数。该配置
     * 由 agent::config 持有，随服务启动时初始化，并传递给 socks5::stream
     * 构造函数，在 stream 生命周期内保持不变。配置结构本身是只读的，
     * 可安全多线程读取；修改配置需要重启服务。
     * @note 配置在 stream 构造时传入，运行时不可修改
     * @warning 修改配置后需要重启服务才能生效
     */
    struct config
    {
        // 是否允许 CONNECT 命令（TCP 隧道）
        bool enable_tcp = true;

        // 是否允许 UDP_ASSOCIATE 命令（UDP 中继）
        bool enable_udp = true;

        // 是否允许 BIND 命令（通常禁用）
        bool enable_bind = false;

        // UDP relay 绑定端口，0 表示自动分配
        std::uint16_t udp_bind_port = 0;

        // UDP 会话空闲超时（秒）
        std::uint32_t udp_idle_timeout = 60;

        // UDP 数据报最大长度
        std::uint32_t udp_max_datagram = 65535;
    };
}
