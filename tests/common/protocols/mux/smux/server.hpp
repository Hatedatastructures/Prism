/**
 * @file server.hpp
 * @brief smux server 会话容器（共享模板实例化）
 * @details 别名转发到 mux::server<codec>，提供 smux 协议的
 * server 视角会话。与共享会话引擎解耦，仅绑定本族帧编解码。
 */

#pragma once

#include <common/protocols/mux/server.hpp>
#include <common/protocols/mux/smux/codec.hpp>

namespace preview::mux::smux
{

    /**
     * @brief smux server 会话（共享模板实例化，可注入内存策略）
     * @tparam Memory 会话内存策略（默认 8KB arena）
     */
    template <preview::memory::restrict Memory = preview::memory::session_resource<>>
    using server = mux::server<codec, Memory>;

} // namespace preview::mux::smux