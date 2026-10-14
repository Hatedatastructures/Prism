/**
 * @file Hello.hpp
 * @brief ClientHello ECH 扩展检测
 * @details 仅识别单个完整 TLS handshake record 内 ClientHello 的 ECH 扩展（Type 0xfe0d）。
 *          本函数不重组跨 record 的握手，也不解密 ClientHello。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace Preview::Ech::Detail
{

    /// ECH 扩展类型（RFC draft-ietf-tls-esni）
    inline constexpr std::uint16_t EchExtensionType = 0xfe0d;

    /**
     * @brief 检查 ClientHello 是否包含 ECH 扩展
     * @param Raw 含完整 ClientHello 的单个 TLS handshake record
     * @return 含 ECH 扩展返回 true
     * @details 解析 ClientHello 结构（RFC 8446 §4.1.2）：
     *          记录头(5) + handshake_type(1) + handshake_len(3) +
     *          LegacyVersion(2) + random(32) + session_id_len(1) +
     *          SessionId + cipher_suites_len(2) + cipher_suites +
     *          compression_len(1) + compression + extensions。
     *          逐字段显式跳转，扫描 extensions 中的 ECH 类型；不会拼接多个 record。
     */
    [[nodiscard]] inline auto ContainsEchExtension(std::span<const std::byte> Raw) -> bool
    {
        // TLS 记录头：5 字节
        if (Raw.size() < 5 || std::to_integer<std::uint8_t>(Raw[0]) != 0x16)
        {
            return false;
        }
        const auto RecordLen = (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Raw[3])) << 8) |
                               static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Raw[4]));
        if (RecordLen < 4 || RecordLen > Raw.size() - 5)
        {
            return false;
        }
        std::size_t Off = 5;
        // handshake_type + handshake_len(3)
        if (Off > 5 + RecordLen || 5 + RecordLen - Off < 4 ||
            std::to_integer<std::uint8_t>(Raw[Off]) != 0x01)
        {
            return false;
        }
        const auto HsLen = (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Raw[Off + 1])) << 16) |
                           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Raw[Off + 2])) << 8) |
                           static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Raw[Off + 3]));
        Off += 4;
        if (HsLen > 5 + RecordLen - Off)
        {
            return false;
        }
        const auto HandshakeEnd = Off + HsLen;
        // LegacyVersion(2) + random(32)
        if (Off > HandshakeEnd || HandshakeEnd - Off < 34)
        {
            return false;
        }
        Off += 34;
        // SessionId
        if (Off >= HandshakeEnd)
        {
            return false;
        }
        const auto SidLen = std::to_integer<std::uint8_t>(Raw[Off]);
        ++Off;
        if (SidLen > HandshakeEnd - Off)
        {
            return false;
        }
        Off += SidLen;
        // cipher_suites
        if (Off > HandshakeEnd || HandshakeEnd - Off < 2)
        {
            return false;
        }
        const auto CsLen = (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Raw[Off])) << 8) |
                           static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Raw[Off + 1]));
        if (CsLen > HandshakeEnd - Off - 2)
        {
            return false;
        }
        Off += 2 + CsLen;
        // compression_methods
        if (Off >= HandshakeEnd)
        {
            return false;
        }
        const auto CompLen = std::to_integer<std::uint8_t>(Raw[Off]);
        ++Off;
        if (CompLen > HandshakeEnd - Off)
        {
            return false;
        }
        Off += CompLen;
        // extensions
        if (Off > HandshakeEnd || HandshakeEnd - Off < 2)
        {
            return false;
        }
        const auto ExtLen = (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Raw[Off])) << 8) |
                            static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Raw[Off + 1]));
        Off += 2;
        if (Off > HandshakeEnd || ExtLen > HandshakeEnd - Off)
        {
            return false;
        }
        // 扫描扩展项
        const std::size_t End = Off + ExtLen;
        while (End - Off >= 4)
        {
            const auto Type = (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Raw[Off])) << 8) |
                             static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Raw[Off + 1]));
            const auto Len = (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Raw[Off + 2])) << 8) |
                             static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Raw[Off + 3]));
            if (Len > End - Off - 4)
            {
                return false;
            }
            if (Type == EchExtensionType)
            {
                return true;
            }
            Off += 4 + Len;
        }
        return false;
    }

} // namespace Preview::Ech::Detail
