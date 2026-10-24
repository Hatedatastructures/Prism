/**
 * @file Types.hpp
 * @brief 多路复用协议族共享的根 wire 选择。
 */
#pragma once

#include <cstdint>

namespace Prism::Mux
{
    /** @brief 根 binding 的 wire 选择；Auto 仅用于配置与监听前装配。 */
    enum class Mode : std::uint8_t
    {
        /// 由首个根握手选择协议。
        Auto,
        /// smux wire。
        Smux,
        /// yamux wire。
        Yamux,
        /// h2mux wire。
        H2Mux,
    };
}
