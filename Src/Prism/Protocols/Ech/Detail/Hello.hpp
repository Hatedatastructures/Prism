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

namespace Prism::Ech::Detail
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
    [[nodiscard]] auto ContainsEchExtension(std::span<const std::byte> Raw) -> bool;

} // namespace Prism::Ech::Detail
