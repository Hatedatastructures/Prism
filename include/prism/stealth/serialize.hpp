/**
 * @file serialize.hpp
 * @brief Stealth 模块 Glaze 序列化集中定义
 * @details 将所有伪装层配置结构的 glz::meta<> 特化集中于此文件，
 * 避免各 config.hpp 引入 glaze 重型依赖，减少编译单元的
 * 不必要 include 开销。使用 glaze 反序列化 JSON 配置的编译单元
 * 需显式 include 此文件。
 * @note 各伪装层 config.hpp 仅保留纯数据结构定义，
 * 序列化映射统一在此维护。
 */
#pragma once

#include <prism/stealth/anytls/config.hpp>
#include <prism/stealth/ech/config.hpp>
#include <prism/stealth/native/config.hpp>
#include <prism/stealth/reality/config.hpp>
#include <prism/stealth/restls/config.hpp>
#include <prism/stealth/shadowtls/config.hpp>
#include <prism/stealth/trusttunnel/config.hpp>

#include <glaze/glaze.hpp>


// ============================================================================
// reality
// ============================================================================

template <>
struct glz::meta<psm::stealth::reality::config>
{
    using T = psm::stealth::reality::config;
    static constexpr auto value = glz::object(
        "dest",         &T::dest,
        "server_names", &T::server_names,
        "private_key",  &T::private_key,
        "short_ids",    &T::short_ids);
};

// ============================================================================
// shadowtls
// ============================================================================

// shadowtls::user
template <>
struct glz::meta<psm::stealth::shadowtls::user>
{
    using T = psm::stealth::shadowtls::user;
    static constexpr auto value = glz::object(
        "name",     &T::name,
        "password", &T::password);
};

// shadowtls::config
template <>
struct glz::meta<psm::stealth::shadowtls::config>
{
    using T = psm::stealth::shadowtls::config;
    static constexpr auto value = glz::object(
        "version",              &T::version,
        "password",             &T::password,
        "users",                &T::users,
        "handshake_dest",       &T::handshake_dest,
        "server_names",         &T::server_names,
        "strict_mode",          &T::strict_mode,
        "handshake_timeout_ms", &T::hs_timeout);
};

// ============================================================================
// restls
// ============================================================================

// restls::config
template <>
struct glz::meta<psm::stealth::restls::config>
{
    using T = psm::stealth::restls::config;
    static constexpr auto value = glz::object(
        "server_names",         &T::server_names,
        "host",                 &T::host,
        "password",             &T::password,
        "version_hint",         &T::version_hint,
        "restls_script",        &T::restls_script,
        "handshake_timeout_ms", &T::hs_timeout);
};

// ============================================================================
// anytls
// ============================================================================

// anytls::user
template <>
struct glz::meta<psm::stealth::anytls::user>
{
    using T = psm::stealth::anytls::user;
    static constexpr auto value = glz::object(
        "username", &T::username,
        "password", &T::password);
};

// anytls::config
template <>
struct glz::meta<psm::stealth::anytls::config>
{
    using T = psm::stealth::anytls::config;
    static constexpr auto value = glz::object(
        "server_names",             &T::server_names,
        "certificate",              &T::certificate,
        "private_key",              &T::private_key,
        "users",                    &T::users,
        "ech_key",                  &T::ech_key,
        "padding_scheme",           &T::padding_scheme,
        "handshake_timeout_ms",     &T::hs_timeout,
        "idle_session_timeout_ms",  &T::idle_sess_timeout);
};

// ============================================================================
// ech
// ============================================================================

// ech::config
template <>
struct glz::meta<psm::stealth::ech::config>
{
    using T = psm::stealth::ech::config;
    static constexpr auto value = glz::object(
        "ech_key",      &T::ech_key,
        "public_name",  &T::public_name);
};

// ============================================================================
// trusttunnel
// ============================================================================

// trusttunnel::user
template <>
struct glz::meta<psm::stealth::trusttunnel::user>
{
    using T = psm::stealth::trusttunnel::user;
    static constexpr auto value = glz::object(
        "username", &T::username,
        "password", &T::password);
};

// trusttunnel::network_type
template <>
struct glz::meta<psm::stealth::trusttunnel::network_type>
{
    static constexpr auto value = glz::enumerate(
        "tcp", psm::stealth::trusttunnel::network_type::tcp,
        "udp", psm::stealth::trusttunnel::network_type::udp,
        "both", psm::stealth::trusttunnel::network_type::both);
};

// trusttunnel::congestion_controller
template <>
struct glz::meta<psm::stealth::trusttunnel::congestion_controller>
{
    static constexpr auto value = glz::enumerate(
        "cubic", psm::stealth::trusttunnel::congestion_controller::cubic,
        "bbr", psm::stealth::trusttunnel::congestion_controller::bbr,
        "new_reno", psm::stealth::trusttunnel::congestion_controller::new_reno);
};

// trusttunnel::config
template <>
struct glz::meta<psm::stealth::trusttunnel::config>
{
    using T = psm::stealth::trusttunnel::config;
    static constexpr auto value = glz::object(
        "server_names",         &T::server_names,
        "certificate",          &T::certificate,
        "private_key",          &T::private_key,
        "users",                &T::users,
        "network",              &T::network,
        "congestion",           &T::congestion,
        "handshake_timeout_ms", &T::hs_timeout,
        "idle_timeout_ms",      &T::idle_timeout);
};

// ============================================================================
// native
// ============================================================================

template <>
struct glz::meta<psm::stealth::native::config>
{
    using T = psm::stealth::native::config;
    static constexpr auto value = glz::object(
        "enabled", &T::enabled);
};
