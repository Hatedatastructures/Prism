/**
 * @file Types.hpp
 * @brief Reality 协议基础类型
 * @details Reality 是 TLS 1.3 指纹伪装方案（对齐 mihomo
 * component/tls/reality.go）：
 *          - 认证：X25519 ECDH + HKDF 派生 AuthKey，用 AES-256-GCM
 *            加密 ClientHello.SessionId（短 ID 内嵌）
 *          - 身份：服务端 Ed25519 证书 + HMAC-SHA512 签名
 *          本测试库实现纯逻辑密钥工具与认证编解码。
 * @note 参考 Reality 协议规范。
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace Preview::Reality
{

    /// X25519 密钥长度
    inline constexpr std::size_t KeyLen = 32;

    /// SessionId 内认证数据长度（加密后 32 字节 = 明文 16 + tag 16）
    inline constexpr std::size_t SessionIdAuthLen = 32;

    /// 认证密钥 HKDF Info（"REALITY"）
    inline constexpr char RealityInfo[] = "REALITY";

    /// 最大短 ID 长度（8 字节）
    inline constexpr std::size_t MaxShortIdLen = 8;

} // namespace Preview::Reality
