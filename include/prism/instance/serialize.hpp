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

#include <prism/instance/config.hpp>

#include <glaze/glaze.hpp>

template <>
struct glz::meta<psm::instance::endpoint>
{
    using T = psm::instance::endpoint;
    static constexpr auto value = glz::object("host", &T::host, "port", &T::port);
};

template <>
struct glz::meta<psm::instance::limit>
{
    using T = psm::instance::limit;
    static constexpr auto value = glz::object("blacklist", &T::blacklist);
};

template <>
struct glz::meta<psm::instance::certificate>
{
    using T = psm::instance::certificate;
    static constexpr auto value = glz::object("key", &T::key, "cert", &T::cert);
};

template <>
struct glz::meta<psm::instance::authentication::user>
{
    using T = psm::instance::authentication::user;
    static constexpr auto value = glz::object(
        "password", &T::password, "uuid", &T::uuid, "max_connections", &T::max_connections);
};

template <>
struct glz::meta<psm::instance::authentication>
{
    using T = psm::instance::authentication;
    static constexpr auto value = glz::object("users", &T::users);
};

template <>
struct glz::meta<psm::instance::buffer>
{
    using T = psm::instance::buffer;
    static constexpr auto value = glz::object("size", &T::size);
};

template <>
struct glz::meta<psm::instance::protocol::config>
{
    using T = psm::instance::protocol::config;
    static constexpr auto value = glz::object(
        "socks5",       &T::socks5,
        "trojan",       &T::trojan,
        "vless",        &T::vless,
        "shadowsocks",  &T::shadowsocks);
};

template <>
struct glz::meta<psm::instance::stealth::config>
{
    using T = psm::instance::stealth::config;
    static constexpr auto value = glz::object(
        "reality",      &T::reality,
        "shadowtls",    &T::shadowtls,
        "restls",       &T::restls,
        "anytls",       &T::anytls,
        "trusttunnel",  &T::trusttunnel);
};

template <>
struct glz::meta<psm::instance::config>
{
    using T = psm::instance::config;
    static constexpr auto value = glz::object(
        "limit",           &T::limits,
        "positive",        &T::positive,
        "addressable",     &T::addressable,
        "certificate",     &T::cert,
        "authentication",  &T::auth,
        "camouflage",      &T::camouflage,
        "reverse_map",     &T::reverse_map);
};
