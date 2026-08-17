/**
 * @file types.hpp
 * @brief WebSocket 协议基础类型（RFC 6455）
 * @details WebSocket 是 HTTP 升级伪装方案（对齐 mihomo transport/ws）：
 *          - 握手：Sec-WebSocket-Accept = base64(SHA1(key + GUID))
 *          - 帧：FIN|RSV|opcode + MASK|len7 + [ext len] + [mask] + payload
 *          本测试库实现纯逻辑帧编解码。
 * @note 参考 RFC 6455 协议规范。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace preview::ws
{

    /// WebSocket 魔数（GUID）
    inline constexpr std::string_view ws_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    /// SHA1 摘要长度
    inline constexpr std::size_t sha1_len = 20;

    /// Sec-WebSocket-Accept base64 长度（20 字节 → 28 字符）
    inline constexpr std::size_t accept_len = 28;

    /// 掩码键长度（4 字节）
    inline constexpr std::size_t mask_len = 4;

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

} // namespace preview::ws
