/**
 * @file serialize.hpp
 * @brief DNS 模块 Glaze 序列化集中定义
 * @details 将 DNS 配置结构的 glz::meta<> 特化集中于此文件，
 * 避免 config.hpp 引入 glaze 重型依赖，减少编译单元的
 * 不必要 include 开销。使用 glaze 反序列化 JSON 配置的编译单元
 * 需显式 include 此文件。
 * @note config.hpp 仅保留纯数据结构定义，
 * 序列化映射统一在此维护。
 */
#pragma once

#include <prism/resolve/dns/config.hpp>

#include <glaze/glaze.hpp>

// ============================================================================
// dns_protocol
// ============================================================================

template <>
struct glz::meta<psm::resolve::dns::dns_protocol>
{
    static constexpr auto value = glz::enumerate(
        "udp", psm::resolve::dns::dns_protocol::udp,
        "tcp", psm::resolve::dns::dns_protocol::tcp,
        "tls", psm::resolve::dns::dns_protocol::tls,
        "https", psm::resolve::dns::dns_protocol::https);
};

// ============================================================================
// resolve_mode
// ============================================================================

template <>
struct glz::meta<psm::resolve::dns::resolve_mode>
{
    static constexpr auto value = glz::enumerate(
        "fastest", psm::resolve::dns::resolve_mode::fastest,
        "first", psm::resolve::dns::resolve_mode::first,
        "fallback", psm::resolve::dns::resolve_mode::fallback);
};

// ============================================================================
// dns_remote
// ============================================================================

template <>
struct glz::meta<psm::resolve::dns::dns_remote>
{
    using T = psm::resolve::dns::dns_remote;
    static constexpr auto value = glz::object(
        "address", &T::address,
        "protocol", &T::protocol,
        "hostname", &T::hostname,
        "port", &T::port,
        "timeout_ms", &T::timeout_ms,
        "http_path", &T::http_path,
        "no_check_certificate", &T::no_check_certificate);
};

// ============================================================================
// address_rule
// ============================================================================

template <>
struct glz::meta<psm::resolve::dns::address_rule>
{
    using T = psm::resolve::dns::address_rule;
    static constexpr auto value = glz::object(
        "domain", &T::domain,
        "negative", &T::negative);
};

// ============================================================================
// cname_rule
// ============================================================================

template <>
struct glz::meta<psm::resolve::dns::cname_rule>
{
    using T = psm::resolve::dns::cname_rule;
    static constexpr auto value = glz::object(
        "domain", &T::domain,
        "target", &T::target);
};

// ============================================================================
// config
// ============================================================================

template <>
struct glz::meta<psm::resolve::dns::config>
{
    using T = psm::resolve::dns::config;
    static constexpr auto value = glz::object(
        "servers", &T::servers,
        "mode", &T::mode,
        "timeout_ms", &T::timeout_ms,
        "cache_enabled", &T::cache_enabled,
        "cache_size", &T::cache_size,
        "cache_ttl", &T::cache_ttl,
        "serve_stale", &T::serve_stale,
        "negative_ttl", &T::negative_ttl,
        "ttl_min", &T::ttl_min,
        "ttl_max", &T::ttl_max,
        "address_rules", &T::address_rules,
        "cname_rules", &T::cname_rules,
        "disable_ipv6", &T::disable_ipv6);
};
