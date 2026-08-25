/**
 * @file Client.hpp
 * @brief yamux Client 会话容器（共享模板实例化）
 * @details 别名转发到 Mux::Client<Codec>，提供 yamux 协议的
 * Client 视角会话。与共享会话引擎解耦，仅绑定本族帧编解码。
 */

#pragma once

#include <common/Protocols/Mux/Client.hpp>
#include <common/Protocols/Mux/Yamux/Codec.hpp>

namespace Preview::Mux::Yamux
{

    /**
     * @brief yamux Client 会话（共享模板实例化，可注入内存策略）
     * @tparam Memory 会话内存策略（默认 8KB Arena）
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    using Client = Mux::Client<Codec, Memory>;

} // namespace Preview::Mux::Yamux