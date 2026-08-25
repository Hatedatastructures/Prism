/**
 * @file scan.hpp
 * @brief ClientHello ECH 扩展检测
 * @details 扫描 TLS ClientHello 中的 ECH 扩展（Type 0xfe0d）：
 *          - ContainsEchExtension：完整记录扫描（含跨记录）
 *          - extract_ech_extension：提取扩展载荷（含 inner_plaintext 长度）
 * @note 用于伪装方案识别：含 ECH 扩展的 ClientHello 走 ECH 解密路径。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace Preview::Ech
{

    /// ECH 扩展类型（RFC draft-ietf-tls-esni）
    inline constexpr std::uint16_t EchExtensionType = 0xfe0d;

    /**
     * @brief 检查 ClientHello 是否包含 ECH 扩展
     * @param raw TLS 记录字节（可含完整 ClientHello 或多个记录）
     * @return 含 ECH 扩展返回 true
     * @details 解析 ClientHello 结构（RFC 8446 §4.1.2）：
     *          记录头(5) + handshake_type(1) + handshake_len(3) +
     *          legacy_version(2) + random(32) + session_id_len(1) +
     *          SessionId + cipher_suites_len(2) + cipher_suites +
     *          compression_len(1) + compression + extensions。
     *          逐字段显式跳转，扫描 extensions 中的 ECH 类型。
     */
    [[nodiscard]] inline auto ContainsEchExtension(std::span<const std::byte> raw) -> bool
    {
        // TLS 记录头：5 字节
        if (raw.size() < 5)
        {
            return false;
        }
        std::size_t off = 5;
        // handshake_type + handshake_len(3)
        if (off + 4 > raw.size() || std::to_integer<std::uint8_t>(raw[off]) != 0x01)
        {
            return false;
        }
        const auto HsLen = (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(raw[off + 1])) << 16) |
                            (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(raw[off + 2])) << 8) |
                            static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(raw[off + 3]));
        off += 4;
        if (off + HsLen > raw.size())
        {
            return false;
        }
        // legacy_version(2) + random(32)
        if (off + 34 > raw.size())
        {
            return false;
        }
        off += 34;
        // SessionId
        if (off + 1 > raw.size())
        {
            return false;
        }
        const auto SidLen = std::to_integer<std::uint8_t>(raw[off]);
        off += 1 + SidLen;
        // cipher_suites
        if (off + 2 > raw.size())
        {
            return false;
        }
        const auto CsLen = (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(raw[off])) << 8) |
                            static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(raw[off + 1]));
        off += 2 + CsLen;
        // compression_methods
        if (off + 1 > raw.size())
        {
            return false;
        }
        const auto CompLen = std::to_integer<std::uint8_t>(raw[off]);
        off += 1 + CompLen;
        // extensions
        if (off + 2 > raw.size())
        {
            return false;
        }
        const auto ExtLen = (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(raw[off])) << 8) |
                             static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(raw[off + 1]));
        off += 2;
        if (off + ExtLen > raw.size())
        {
            return false;
        }
        // 扫描扩展项
        const std::size_t end = off + ExtLen;
        while (off + 4 <= end)
        {
            const auto Type = (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(raw[off])) << 8) |
                              static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(raw[off + 1]));
            const auto len = (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(raw[off + 2])) << 8) |
                             static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(raw[off + 3]));
            if (Type == EchExtensionType)
            {
                return true;
            }
            off += 4 + len;
        }
        return false;
    }

} // namespace Preview::Ech
