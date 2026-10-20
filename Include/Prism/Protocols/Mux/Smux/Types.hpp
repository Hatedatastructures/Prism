/**
 * @file Types.hpp
 * @brief smux wire 类型（兼容 Mihomo/xtaci/smux v1）。
 * @details 帧头为 8 字节定长：[Version 1B][Cmd 1B][Length 2B LE][StreamID 4B LE]。
 */
#pragma once

#include <cstddef>
#include <cstdint>

namespace Prism::Mux::Smux
{
    /** @brief smux 帧命令。 */
    enum class Command : std::uint8_t
    {
        Syn = 0,
        Fin = 1,
        Push = 2,
        Nop = 3,
    };

    inline constexpr std::uint8_t ProtocolVersion = 0x01;
    inline constexpr std::size_t FrameHdrsize = 8;
    inline constexpr std::size_t MaxFrameLength = 65535;

    /** @brief smux 帧头；字段名称与聚合初始化顺序属于 wire 契约。 */
    struct FrameHeader
    {
        std::uint8_t version{ProtocolVersion};
        Command cmd{Command::Push};
        std::uint16_t length{0};
        std::uint32_t StreamId{0};
    };
}
