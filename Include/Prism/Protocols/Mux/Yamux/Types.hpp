/**
 * @file Types.hpp
 * @brief yamux wire 类型（兼容 Hashicorp/yamux）。
 * @details 帧头为 12 字节定长，多字节字段使用大端序。
 */
#pragma once

#include <cstddef>
#include <cstdint>

namespace Prism::Mux::Yamux
{
    inline constexpr std::uint8_t ProtocolVersion = 0x00;
    inline constexpr std::size_t FrameHdrsize = 12;
    inline constexpr std::uint32_t DefaultWindow = 256 * 1024;

    /** @brief yamux 帧消息类型。 */
    enum class MessageType : std::uint8_t
    {
        Data = 0x00,
        WindowUpdate = 0x01,
        Ping = 0x02,
        GoAway = 0x03,
    };

    /** @brief yamux 帧标志位。 */
    enum class Flags : std::uint16_t
    {
        None = 0x0000,
        Syn = 0x0001,
        Ack = 0x0002,
        Fin = 0x0004,
        Rst = 0x0008,
    };

    [[nodiscard]] constexpr auto operator&(Flags Left, Flags Right) noexcept -> Flags
    {
        return static_cast<Flags>(static_cast<std::uint16_t>(Left) &
                                  static_cast<std::uint16_t>(Right));
    }

    [[nodiscard]] constexpr auto HasFlag(Flags FlagsValue, Flags FlagValue) noexcept -> bool
    {
        return (FlagsValue & FlagValue) != Flags::None;
    }

    /** @brief yamux GoAway 终止原因码。 */
    enum class AwayCode : std::uint32_t
    {
        ProtocolError = 1,
    };

    /** @brief yamux 帧头；字段名称与聚合初始化顺序属于 wire 契约。 */
    struct FrameHeader
    {
        std::uint8_t version{ProtocolVersion};
        MessageType Type{MessageType::Data};
        Flags flag{Flags::None};
        std::uint32_t StreamId{0};
        std::uint32_t length{0};

        [[nodiscard]] auto IsSession() const noexcept -> bool
        {
            return StreamId == 0;
        }
    };
}
