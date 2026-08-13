/**
 * @file serialize.hpp
 * @brief Instance 模块 Glaze 序列化集中定义
 * @details 将 Instance 配置结构的 glz::meta<> 特化集中于此文件，
 * 避免 config.hpp 引入 glaze 重型依赖，减少编译单元的
 * 不必要 include 开销。使用 glaze 反序列化 JSON 配置的编译单元
 * 需显式 include 此文件。
 * @note config.hpp 仅保留纯数据结构定义，
 * 序列化映射统一在此维护。
 */
#pragma once

#include <prism/runtime/config.hpp>

#include <glaze/glaze.hpp>

template <>
struct glz::meta<psm::runtime::endpoint>
{
    using T = psm::runtime::endpoint;
    // clang-format off
    static constexpr auto value = glz::object("host", &T::host, "port", &T::port);
    // clang-format on
};

template <>
struct glz::meta<psm::runtime::limit>
{
    using T = psm::runtime::limit;
    // clang-format off
    static constexpr auto value = glz::object("blacklist", &T::blacklist);
    // clang-format on
};

template <>
struct glz::meta<psm::runtime::certificate>
{
    using T = psm::runtime::certificate;
    // clang-format off
    static constexpr auto value = glz::object("key", &T::key, "cert", &T::cert);
    // clang-format on
};

template <>
struct glz::meta<psm::runtime::authentication::user>
{
    using T = psm::runtime::authentication::user;
    // clang-format off
    static constexpr auto value = glz::object(
        "password", &T::password, "uuid", &T::uuid, "max_connections", &T::max_connections);
    // clang-format on
};

template <>
struct glz::meta<psm::runtime::authentication>
{
    using T = psm::runtime::authentication;
    // clang-format off
    static constexpr auto value = glz::object("users", &T::users);
    // clang-format on
};

template <>
struct glz::meta<psm::runtime::buffer>
{
    using T = psm::runtime::buffer;
    // clang-format off
    static constexpr auto value = glz::object("size", &T::size);
    // clang-format on
};

template <>
struct glz::meta<psm::runtime::protocol::config>
{
    using T = psm::runtime::protocol::config;
    // clang-format off
    static constexpr auto value = glz::object(
        "socks5",       &T::socks5,
        "trojan",       &T::trojan,
        "vless",        &T::vless,
        "shadowsocks",  &T::shadowsocks,
        "vmess",        &T::vmess);
    // clang-format on
};

// ============================================================================
// protocol sub-configs (字段名与 JSON key 不匹配，需要显式映射)
// ============================================================================

template <>
struct glz::meta<psm::protocol::socks5::config>
{
    using T = psm::protocol::socks5::config;
    // clang-format off
    static constexpr auto value = glz::object(
        "enable_tcp",        &T::enable_tcp,
        "enable_udp",        &T::enable_udp,
        "enable_bind",       &T::enable_bind,
        "udp_bind_port",     &T::bind_port,
        "udp_idle_timeout",  &T::idle_timeout,
        "udp_max_datagram",  &T::max_dgram,
        "enable_auth",       &T::enable_auth);
    // clang-format on
};

template <>
struct glz::meta<psm::protocol::trojan::config>
{
    using T = psm::protocol::trojan::config;
    // clang-format off
    static constexpr auto value = glz::object(
        "enable_tcp",        &T::enable_tcp,
        "enable_udp",        &T::enable_udp,
        "udp_idle_timeout",  &T::idle_timeout,
        "udp_max_datagram",  &T::max_dgram);
    // clang-format on
};

template <>
struct glz::meta<psm::protocol::vless::config>
{
    using T = psm::protocol::vless::config;
    // clang-format off
    static constexpr auto value = glz::object(
        "enable_udp",        &T::enable_udp,
        "udp_idle_timeout",  &T::idle_timeout,
        "udp_max_datagram",  &T::max_dgram);
    // clang-format on
};

template <>
struct glz::meta<psm::protocol::shadowsocks::config>
{
    using T = psm::protocol::shadowsocks::config;
    // clang-format off
    static constexpr auto value = glz::object(
        "psk",               &T::psk,
        "method",            &T::method,
        "enable_tcp",        &T::enable_tcp,
        "enable_udp",        &T::enable_udp,
        "udp_idle_timeout",  &T::idle_timeout);
    // clang-format on
};

template <>
struct glz::meta<psm::protocol::vmess::config>
{
    using T = psm::protocol::vmess::config;
    // clang-format off
    static constexpr auto value = glz::object(
        "enable_tcp",        &T::enable_tcp,
        "enable_udp",        &T::enable_udp,
        "enable_mux",        &T::enable_mux,
        "udp_idle_timeout",  &T::idle_timeout,
        "udp_max_datagram",  &T::max_dgram);
    // clang-format on
};

template <>
struct glz::meta<psm::runtime::stealth::config>
{
    using T = psm::runtime::stealth::config;
    // clang-format off
    static constexpr auto value = glz::object(
        "reality",      &T::reality,
        "shadowtls",    &T::shadowtls,
        "restls",       &T::restls,
        "anytls",       &T::anytls,
        "trusttunnel",  &T::trusttunnel,
        "gun",          &T::gun,
        "ech",          &T::ech,
        "ws",           &T::ws,
        "xhttp",        &T::xhttp,
        "hysteria2",    &T::hysteria2,
        "tuic",         &T::tuic,
        "native_tls",   &T::native_tls,
        "pad",          &T::pad,
        "probe",        &T::probe);
    // clang-format on
};

template <>
struct glz::meta<psm::runtime::config>
{
    using T = psm::runtime::config;
    // clang-format off
    static constexpr auto value = glz::object(
        "limit",           &T::limits,
        "positive",        &T::positive,
        "addressable",     &T::addressable,
        "certificate",     &T::cert,
        "authentication",  &T::auth,
        "camouflage",      &T::camouflage,
        "reverse_map",     &T::reverse_map);
    // clang-format on
};
