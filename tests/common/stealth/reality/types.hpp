/**
 * @file types.hpp
 * @brief Reality 协议基础类型
 * @details Reality 是 TLS 1.3 指纹伪装方案（对齐 mihomo
 * component/tls/reality.go）：
 *          - 认证：X25519 ECDH + HKDF 派生 auth_key，用 AES-256-GCM
 *            加密 ClientHello.session_id（短 ID 内嵌）
 *          - 身份：服务端 Ed25519 证书 + HMAC-SHA512 签名
 *          本测试库实现纯逻辑密钥工具与认证编解码。
 * @note 参考 Reality 协议规范。
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace psmtest::reality
{

    /// X25519 密钥长度
    inline constexpr std::size_t key_len = 32;

    /// session_id 内认证数据长度（加密后 32 字节 = 明文 16 + tag 16）
    inline constexpr std::size_t session_id_auth_len = 32;

    /// 认证密钥 HKDF info（"REALITY"）
    inline constexpr char reality_info[] = "REALITY";

    /// 最大短 ID 长度（8 字节）
    inline constexpr std::size_t max_short_id_len = 8;

} // namespace psmtest::reality
