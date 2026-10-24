/** @file Types.hpp @brief sing-mux 会话协商的公开请求类型。 */
#pragma once

#include <Prism/Protocols/Mux/Types.hpp>

#include <cstdint>

namespace Prism::Mux::SingMux
{
    /** @brief 已解析的 sing-mux 会话协商；Wire 不会是 Auto。 */
    struct SessionRequest final
    {
        std::uint8_t Version{0};
        Prism::Mux::Mode Wire{Prism::Mux::Mode::Smux};
        bool Padding{false};
    };
}
