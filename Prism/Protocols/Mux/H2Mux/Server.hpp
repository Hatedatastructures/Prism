/**
 * @file Server.hpp
 * @brief h2mux Server 会话容器（共享模板实例化）
 * @details 别名转发到 Mux::Server<Codec>，提供 h2mux 协议的
 * Server 视角会话。与共享会话引擎解耦，仅绑定本族帧编解码。
 * @note Server 别名与默认 Memory 参数属于公共聚合 API，保持现有模板
 *       实例化和共享 SessionOptions 语义兼容。
 */

#pragma once

#include <Prism/Protocols/Mux/Server.hpp>
#include <Prism/Protocols/Mux/H2Mux/Codec.hpp>

namespace Prism::Mux::H2Mux
{

    /**
     * @brief h2mux Server 会话（共享模板实例化，可注入内存策略）
     * @tparam Memory 会话内存策略（默认 8KB Arena）
     */
    template <Prism::Memory::Restrict Memory = Prism::Memory::SessionResource<>>
    using Server = Mux::Server<Codec, Memory>;

} // namespace Prism::Mux::H2Mux
