/**
 * @file client.hpp
 * @brief yamux client 会话容器（共享模板实例化）
 * @details 别名转发到 mux::client<codec>，提供 yamux 协议的
 * client 视角会话。与共享会话引擎解耦，仅绑定本族帧编解码。
 */

#pragma once

#include <common/protocols/mux/client.hpp>
#include <common/protocols/mux/yamux/codec.hpp>

namespace preview::mux::yamux
{

    /**
     * @brief yamux client 会话（共享模板实例化，可注入内存策略）
     * @tparam Memory 会话内存策略（默认 8KB arena）
     */
    template <preview::memory::restrict Memory = preview::memory::session_resource<>>
    using client = mux::client<codec, Memory>;

} // namespace preview::mux::yamux