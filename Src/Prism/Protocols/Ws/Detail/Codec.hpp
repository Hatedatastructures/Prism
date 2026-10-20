/**
 * @file Codec.hpp
 * @brief WebSocket 帧 wire 类型与编解码接口。
 */
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace Prism::Ws::Detail
{
    inline constexpr std::string_view WsGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    inline constexpr std::size_t Sha1Len = 20;
    inline constexpr std::size_t AcceptLen = 28;
    inline constexpr std::size_t MaskLen = 4;

    enum class Opcode : std::uint8_t
    {
        Continuation = 0x0,
        Text = 0x1,
        Binary = 0x2,
        Close = 0x8,
        Ping = 0x9,
        Pong = 0xA,
    };

    struct FrameHeader final
    {
        bool Fin{false};
        std::uint8_t Opcode{0};
        bool Masked{false};
        std::uint64_t PayloadLen{0};
        std::size_t HeaderLen{0};
        std::array<std::uint8_t, MaskLen> MaskKey{};
    };

    struct FrameInput final
    {
        Opcode op{Opcode::Binary};
        bool Fin{true};
        std::span<const std::byte> payload;
    };

    [[nodiscard]] auto ComputeAccept(std::string_view Key) -> std::string;
    [[nodiscard]] auto ParseFrameHeader(
        std::span<const std::byte> Input,
        FrameHeader &Header) -> bool;
    auto ApplyMask(std::span<std::byte> Data, std::span<const std::uint8_t, MaskLen> Key) -> void;
    [[nodiscard]] auto EncodeFrame(
        const FrameInput &FrameValue,
        std::span<std::byte> Output) -> std::size_t;
}
