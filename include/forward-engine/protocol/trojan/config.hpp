/**
 * @file config.hpp
 * @brief Trojan 协议配置结构
 * @details 定义了 Trojan 协议的能力开关和 UDP 配置参数。
 * 该配置用于控制协议层支持的命令类型和 UDP 行为。
 *
 * 配置项说明：
 * - enable_tcp: 是否允许 CONNECT 命令（TCP 隧道）
 * - enable_udp: 是否允许 UDP_ASSOCIATE 命令（UDP over TLS）
 * - udp_idle_timeout: UDP 会话空闲超时（秒）
 * - udp_max_datagram: UDP 数据报最大长度
 *
 * 默认值设计：
 * - TCP 默认启用（最常用场景）
 * - UDP 默认禁用（需要额外资源）
 *
 * @note 配置在 stream 构造时传入，运行时不可修改
 * @see ngx::protocol::trojan::trojan_stream
 */

#pragma once

#include <cstdint>

namespace ngx::protocol::trojan
{
    /**
     * @struct config
     * @brief Trojan 协议配置
     * @details 控制 Trojan 协议的能力开关和 UDP 参数。
     *
     * 生命周期：
     * - 由 agent::config 持有，随服务启动时初始化
     * - 传递给 trojan_stream 构造函数
     * - stream 生命周期内保持不变
     *
     * 线程安全：
     * - 配置结构本身是只读的，可安全多线程读取
     * - 修改配置需要重启服务
     */
    struct config
    {
        bool enable_tcp = true;

        bool enable_udp = false;

        std::uint32_t udp_idle_timeout = 60;

        std::uint32_t udp_max_datagram = 65535;
    };
}
