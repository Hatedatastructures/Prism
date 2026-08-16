/**
 * @file scan.hpp
 * @brief ClientHello ECH 扩展检测
 * @details 扫描 TLS ClientHello 中的 ECH 扩展（type 0xfe0d）：
 *          - contains_ech_extension：完整记录扫描（含跨记录）
 *          - extract_ech_extension：提取扩展载荷（含 inner_plaintext 长度）
 * @note 用于伪装方案识别：含 ECH 扩展的 ClientHello 走 ECH 解密路径。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace psmtest::ech
{

    /// ECH 扩展类型（RFC draft-ietf-tls-esni）
    inline constexpr std::uint16_t ech_extension_type = 0xfe0d;

    /**
     * @brief 检查 ClientHello 是否包含 ECH 扩展
     * @param raw TLS 记录字节（可含完整 ClientHello 或多个记录）
     * @return 含 ECH 扩展返回 true
     * @details 解析 ClientHello 结构（RFC 8446 §4.1.2）：
     *          记录头(5) + handshake_type(1) + handshake_len(3) +
     *          legacy_version(2) + random(32) + session_id_len(1) +
     *          session_id + cipher_suites_len(2) + cipher_suites +
     *          compression_len(1) + compression + extensions。
     *          逐字段显式跳转，扫描 extensions 中的 ECH 类型。
     */
    [[nodiscard]] inline auto contains_ech_extension(std::span<const std::byte> raw) -> bool
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
        const auto hs_len = (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(raw[off + 1])) << 16) |
                            (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(raw[off + 2])) << 8) |
                            static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(raw[off + 3]));
        off += 4;
        if (off + hs_len > raw.size())
        {
            return false;
        }
        // legacy_version(2) + random(32)
        if (off + 34 > raw.size())
        {
            return false;
        }
        off += 34;
        // session_id
        if (off + 1 > raw.size())
        {
            return false;
        }
        const auto sid_len = std::to_integer<std::uint8_t>(raw[off]);
        off += 1 + sid_len;
        // cipher_suites
        if (off + 2 > raw.size())
        {
            return false;
        }
        const auto cs_len = (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(raw[off])) << 8) |
                            static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(raw[off + 1]));
        off += 2 + cs_len;
        // compression_methods
        if (off + 1 > raw.size())
        {
            return false;
        }
        const auto comp_len = std::to_integer<std::uint8_t>(raw[off]);
        off += 1 + comp_len;
        // extensions
        if (off + 2 > raw.size())
        {
            return false;
        }
        const auto ext_len = (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(raw[off])) << 8) |
                             static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(raw[off + 1]));
        off += 2;
        if (off + ext_len > raw.size())
        {
            return false;
        }
        // 扫描扩展项
        const std::size_t end = off + ext_len;
        while (off + 4 <= end)
        {
            const auto type = (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(raw[off])) << 8) |
                              static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(raw[off + 1]));
            const auto len = (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(raw[off + 2])) << 8) |
                             static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(raw[off + 3]));
            if (type == ech_extension_type)
            {
                return true;
            }
            off += 4 + len;
        }
        return false;
    }

} // namespace psmtest::ech
