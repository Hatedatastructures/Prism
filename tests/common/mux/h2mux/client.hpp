/**
 * @file client.hpp
 * @brief h2mux client 会话容器（共享模板实例化）
 * @details 别名转发到 mux::client<codec>，提供 h2mux 协议的
 * client 视角会话。与共享会话引擎解耦，仅绑定本族帧编解码。
 */

#pragma once

#include <common/mux/client.hpp>
#include <common/mux/server.hpp>

namespace psmtest::mux::h2mux
{

    /// h2mux client 会话（共享模板实例化）
    using client = mux::client<codec>;

} // namespace psmtest::mux::h2mux