/**
 * @file config.hpp
 * @brief Config 模块聚合头文件
 * @details 聚合引入系统全局配置定义，将各子系统的独立配置
 * 组合为统一的顶层配置。包含代理服务、连接池、缓冲区、
 * 协议、多路复用、伪装、DNS 和日志追踪配置。
 * 配置结构采用强类型设计，确保编译期类型安全。
 */
#pragma once

#include <prism/diagnose/config.hpp>
#include <prism/net/dns/config.hpp>
#include <prism/protocol/multiplex/config.hpp>
#include <prism/runtime/config.hpp>

namespace psm
{

    /**
     * @struct settings
     * @brief 全局配置聚合结构体（settings）
     * @details 聚合所有子系统的配置项，提供统一的配置访问入口。
     * 每个模块配置独立在顶层，不耦合到单一字段内。
     * @note 配置应在程序初始化阶段完成加载，避免运行时频繁修改。
     */
    struct settings
    {
        std::uint32_t version{1};           // 配置版本号（schema 演进用）
        runtime::config instance;           // 代理服务核心配置
        runtime::buffer buffer;             // 缓冲区配置
        runtime::protocol::config protocol; // 协议配置 (socks5/trojan/vless/shadowsocks)
        multiplex::config mux;              // 多路复用配置
        runtime::stealth::config stealth;   // 伪装配置 (reality/shadowtls)
        dns::config dns;                    // DNS 解析器配置
        diagnose::config trace;             // 日志追踪配置
    };

} // namespace psm

#include <prism/handshake/serialize.hpp>
#include <prism/net/dns/serialize.hpp>
#include <prism/protocol/multiplex/serialize.hpp>
#include <prism/runtime/serialize.hpp>

#include <glaze/glaze.hpp>

// ============================================================================
// diagnose::config
// ============================================================================

template <>
struct glz::meta<psm::diagnose::config>
{
    using T = psm::diagnose::config;
    // clang-format off
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
    // clang-format on
};

template <>
struct glz::meta<psm::settings>
{
    using T = psm::settings;
    // clang-format off
    static constexpr auto value = glz::object(
        "version",  &T::version,
        "agent",    &T::instance,
        "buffer",   &T::buffer,
        "protocol", &T::protocol,
        "multiplex",&T::mux,
        "stealth",  &T::stealth,
        "dns",      &T::dns,
        "trace",    &T::trace);
    // clang-format on
};
