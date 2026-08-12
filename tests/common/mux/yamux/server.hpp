/**
 * @file server.hpp
 * @brief yamux server 会话容器（共享模板实例化）
 * @details 别名转发到 mux::server<codec>，提供 yamux 协议的
 * server 视角会话。与共享会话引擎解耦，仅绑定本族帧编解码。
 */

#pragma once

#include <common/mux/client.hpp>
#include <common/mux/server.hpp>

namespace psmtest::mux::yamux
{

    /// yamux server 会话（共享模板实例化）
    using server = mux::server<codec>;

} // namespace psmtest::mux::yamux