/**
 * @file serialize.hpp
 * @brief Multiplex 模块 Glaze 序列化集中定义
 * @details 将多路复用配置结构的 glz::meta<> 特化集中于此文件，
 * 避免 config.hpp 引入 glaze 重型依赖。
 */
#pragma once

#include <prism/multiplex/config.hpp>

#include <glaze/glaze.hpp>


template <>
struct glz::meta<psm::multiplex::smux::config>
{
    using T = psm::multiplex::smux::config;
    static constexpr auto value = glz::object(
        "max_streams",          &T::max_streams,
        "buffer_size",          &T::buffer_size,
        "keepalive_interval",   &T::keepalive_interval,
        "udp_idle_timeout",     &T::idle_timeout,
        "udp_max_dgram",        &T::max_dgram);
};

template <>
struct glz::meta<psm::multiplex::yamux::config>
{
    using T = psm::multiplex::yamux::config;
    static constexpr auto value = glz::object(
        "max_streams",          &T::max_streams,
        "buffer_size",          &T::buffer_size,
        "initial_window",       &T::initial_window,
        "enable_ping",          &T::enable_ping,
        "ping_interval",        &T::ping_interval,
        "stream_open_timeout",  &T::open_timeout,
        "stream_close_timeout", &T::close_timeout,
        "udp_idle_timeout",     &T::udp_idle,
        "udp_max_dgram",        &T::max_dgram);
};

template <>
struct glz::meta<psm::multiplex::h2mux::config>
{
    using T = psm::multiplex::h2mux::config;
    static constexpr auto value = glz::object(
        "max_streams",     &T::max_streams,
        "buffer_size",     &T::buffer_size,
        "max_frame_size",  &T::max_frame_size,
        "idle_timeout",    &T::idle_timeout,
        "udp_idle_timeout",&T::udp_idle,
        "udp_max_dgram",   &T::max_dgram);
};

template <>
struct glz::meta<psm::multiplex::config>
{
    using T = psm::multiplex::config;
    static constexpr auto value = glz::object(
        "enabled", &T::enabled,
        "smux",    &T::smux,
        "yamux",   &T::yamux,
        "h2mux",   &T::h2mux);
};
