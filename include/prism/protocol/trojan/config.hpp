/**
 * @file config.hpp
 * @brief Trojan 协议配置结构
 * @details 定义 Trojan 协议的能力开关和 UDP 配置参数。该配置用于
 * 控制协议层支持的命令类型和 UDP 行为。配置项包括 TCP 隧道开关、
 * UDP 关联开关、UDP 会话空闲超时时间和 UDP 数据报最大长度。默认
 * 情况下 TCP 隧道启用，UDP 关联禁用。配置在 stream 构造时传入，
 * 运行期间不可修改。
 */

#pragma once

#include <cstdint>

/**
 * @namespace psm::protocol::trojan
 * @brief Trojan 协议实现
 * @details 实现 Trojan 协议的数据结构和处理逻辑，包含地址解析、
 * 密码哈希验证和流量转发封装。遵循 Trojan 协议规范。
 */
namespace psm::protocol::trojan
{
    /**
     * @struct config
     * @brief Trojan 协议配置
     * @details 控制 Trojan 协议的能力开关和 UDP 参数。配置结构由
     * agent::config 持有，随服务启动时初始化，传递给 relay
     * 构造函数后在 stream 生命周期内保持不变。配置结构本身是只读的，
     * 可安全多线程读取，修改配置需要重启服务。
     *
     * @note 配置在 stream 构造时传入，运行时不可修改
     * @warning 修改配置后需要重启服务才能生效
     */
    struct config
    {
        // 是否允许 CONNECT 命令（TCP 隧道），默认启用
        bool enable_tcp = true;

        // 是否允许 UDP_ASSOCIATE 命令（UDP over TLS），默认禁用
        bool enable_udp = false;

        // UDP 会话空闲超时时间（秒），默认 60 秒
        std::uint32_t udp_idle_timeout = 60;

        // UDP 数据报最大长度，默认 65535 字节
        std::uint32_t udp_max_datagram = 65535;
    };
}
