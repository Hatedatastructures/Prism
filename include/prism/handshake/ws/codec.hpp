/**
 * @file codec.hpp
 * @brief WebSocket 帧编解码
 * @details RFC 6455 帧格式：
 *   byte0: FIN(0x80)|RSV(0)|opcode
 *   byte1: MASK(0x80 仅客户端)|len7
 *   len7==126 → +2B len；len7==127 → +8B len
 *   客户端帧含 4B mask key，payload 与 mask 32bit 循环 XOR
 *   服务端帧不 mask
 */

#pragma once

#include <prism/foundation/fault/code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace psm::handshake::ws::codec
{

    /// WebSocket 魔数（GUID）
    inline constexpr std::string_view ws_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    /// 帧 opcode
    enum class opcode : std::uint8_t
    {
        continuation = 0x0,
        text = 0x1,
        binary = 0x2,
        close = 0x8,
        ping = 0x9,
        pong = 0xA,
    };

    /**
     * @brief 计算 Sec-WebSocket-Accept
     * @param key Sec-WebSocket-Key（客户端提供）
     * @param out 输出 28 字节 base64 结果
     * @return 是否成功
     */
    [[nodiscard]] auto compute_accept(std::string_view key, std::span<char, 28> out) -> bool;

    /**
     * @struct frame_header
     * @brief 解析出的帧头
     */
    struct frame_header
    {
        bool fin{false};              ///< FIN 标志
        std::uint8_t opcode{0};       ///< 帧类型
        bool masked{false};           ///< 是否掩码
        std::uint64_t payload_len{0}; ///< 载荷长度
        std::size_t header_len{0};    ///< 帧头总长度（含 mask key）
        std::array<std::uint8_t, 4> mask{}; ///< 掩码键（masked 时有效）
    };

    /**
     * @brief 解析帧头
     * @param in 输入数据
     * @param header 输出帧头
     * @return 解析是否成功（数据不足返回 false）
     */
    [[nodiscard]] auto parse_frame_header(std::span<const std::byte> in, frame_header &header) -> bool;

    /**
     * @brief 编码服务端帧（不掩码）
     * @param op 帧类型
     * @param fin 是否 FIN
     * @param payload 载荷
     * @param out 输出缓冲区
     * @return 写入字节数，0 表示缓冲区不足
     */
    [[nodiscard]] auto encode_frame(opcode op, bool fin, std::span<const std::byte> payload,
                                    std::span<std::byte> out) -> std::size_t;

} // namespace psm::handshake::ws::codec
