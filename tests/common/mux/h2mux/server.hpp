/**
 * @file server.hpp
 * @brief h2mux server 会话容器（共享模板实例化）
 * @details 别名转发到 mux::server<codec>，提供 h2mux 协议的
 * server 视角会话。与共享会话引擎解耦，仅绑定本族帧编解码。
 */

#pragma once

#include <common/mux/client.hpp>
#include <common/mux/server.hpp>

namespace psmtest::mux::h2mux
{

    /**
     * @brief h2mux server 会话（共享模板实例化，可注入内存策略）
     * @tparam Memory 会话内存策略（默认 8KB arena）
     */
    template <psmtest::memory::memory_policy Memory = psmtest::memory::session_memory<>>
    using server = mux::server<codec, Memory>;

} // namespace psmtest::mux::h2mux