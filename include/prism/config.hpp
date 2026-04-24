/**
 * @file config.hpp
 * @brief Config 模块聚合头文件
 * @details 聚合引入系统全局配置定义，将各子系统的独立配置
 * 组合为统一的顶层配置。包含代理服务、连接池、缓冲区、
 * 协议、多路复用、伪装、DNS 和日志追踪配置。
 * 配置结构采用强类型设计，确保编译期类型安全。
 */
#pragma once

#include <prism/agent/config.hpp>
#include <prism/channel/connection/pool.hpp>
#include <prism/multiplex/config.hpp>
#include <prism/resolve/dns/config.hpp>
#include <prism/trace/config.hpp>

namespace psm
{
    /**
     * @struct config
     * @brief 全局配置聚合结构体
     * @details 聚合所有子系统的配置项，提供统一的配置访问入口。
     * 每个模块配置独立在顶层，不耦合到单一字段内。
     * @note 配置应在程序初始化阶段完成加载，避免运行时频繁修改。
     */
    struct config
    {
        agent::config agent;              // 代理服务核心配置
        channel::config pool;             // 连接池配置
        agent::buffer buffer;             // 缓冲区配置
        agent::protocol::config protocol; // 协议配置 (socks5/trojan/vless/shadowsocks)
        multiplex::config mux;            // 多路复用配置
        agent::stealth::config stealth;   // 伪装配置 (reality/shadowtls)
        resolve::dns::config dns;         // DNS 解析器配置
        trace::config trace;              // 日志追踪配置
    };

} // namespace psm

#include <glaze/glaze.hpp>

template <>
struct glz::meta<psm::config>
{
    using T = psm::config;
    static constexpr auto value = glz::object(
        "agent",    &T::agent,
        "pool",     &T::pool,
        "buffer",   &T::buffer,
        "protocol", &T::protocol,
        "multiplex",&T::mux,
        "stealth",  &T::stealth,
        "dns",      &T::dns,
        "trace",    &T::trace);
};
