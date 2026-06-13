/**
 * @file config.hpp
 * @brief Config 模块聚合头文件
 * @details 聚合引入系统全局配置定义，将各子系统的独立配置
 * 组合为统一的顶层配置。包含代理服务、连接池、缓冲区、
 * 协议、多路复用、伪装、DNS 和日志追踪配置。
 * 配置结构采用强类型设计，确保编译期类型安全。
 */
#pragma once

#include <prism/net/connect/pool/pool.hpp>
#include <prism/instance/config.hpp>
#include <prism/proto/multiplex/config.hpp>
#include <prism/net/resolve/dns/config.hpp>
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
        instance::config instance;              // 代理服务核心配置
        connect::config pool;                   // 连接池配置
        instance::buffer buffer;                // 缓冲区配置
        instance::protocol::config protocol;    // 协议配置 (socks5/trojan/vless/shadowsocks)
        multiplex::config mux;                  // 多路复用配置
        instance::stealth::config stealth;      // 伪装配置 (reality/shadowtls)
        resolve::dns::config dns;               // DNS 解析器配置
        trace::config trace;                    // 日志追踪配置
    };

} // namespace psm

#include <glaze/glaze.hpp>
#include <prism/instance/serialize.hpp>
#include <prism/proto/multiplex/serialize.hpp>
#include <prism/net/resolve/dns/serialize.hpp>
#include <prism/stealth/serialize.hpp>


// ============================================================================
// trace::config
// ============================================================================

template <>
struct glz::meta<psm::trace::config>
{
    using T = psm::trace::config;
    static constexpr auto value = glz::object(
        "file_name",      &T::file_name,
        "path_name",      &T::path_name,
        "max_size",       &T::max_size,
        "max_files",      &T::max_files,
        "queue_size",     &T::queue_size,
        "thread_count",   &T::thread_count,
        "enable_console", &T::enable_console,
        "enable_file",    &T::enable_file,
        "log_level",      &T::log_level,
        "pattern",        &T::pattern,
        "trace_name",     &T::trace_name);
};

// ============================================================================
// connect::config (pool)
// ============================================================================

template <>
struct glz::meta<psm::connect::config>
{
    using T = psm::connect::config;
    static constexpr auto value = glz::object(
        "max_cache_per_endpoint", &T::cache_peraddr,
        "connect_timeout_ms",     &T::conn_timeout,
        "max_idle_seconds",       &T::idle_sec,
        "cleanup_interval_sec",   &T::clean_interval,
        "recv_buffer_size",       &T::recv_bufsz,
        "send_buffer_size",       &T::send_bufsz,
        "tcp_nodelay",            &T::tcp_nodelay,
        "keep_alive",             &T::keep_alive,
        "cache_ipv6",             &T::cache_ipv6);
};

template <>
struct glz::meta<psm::config>
{
    using T = psm::config;
    static constexpr auto value = glz::object(
        "agent",    &T::instance,
        "pool",     &T::pool,
        "buffer",   &T::buffer,
        "protocol", &T::protocol,
        "multiplex",&T::mux,
        "stealth",  &T::stealth,
        "dns",      &T::dns,
        "trace",    &T::trace);
};
