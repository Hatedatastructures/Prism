/**
 * @file CarrierTypes.hpp
 * @brief Reality 协议基础类型
 * @details Reality 是 TLS 1.3 指纹伪装方案（对齐 mihomo
 * component/tls/reality.go）：
 *          - 认证：X25519 ECDH + HKDF 派生 AuthKey，用 AES-256-GCM
 *            加密 ClientHello.SessionId（短 ID 内嵌）
 *          - 身份：服务端 Ed25519 证书 + HMAC-SHA512 签名
 *          本测试库实现纯逻辑密钥工具与认证编解码。
 * @note KeyLen、SessionIdAuthLen、RealityInfo 和 MaxShortIdLen 属于 wire/crypto
 *       公共常量，保持名称和值兼容。
 * @note 参考 Reality 协议规范。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <array>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Reality
{

    /// X25519 密钥长度
    inline constexpr std::size_t KeyLen = 32;

    /// SessionId 内认证数据长度（加密后 32 字节 = 明文 16 + tag 16）
    inline constexpr std::size_t SessionIdAuthLen = 32;

    /// 认证密钥 HKDF Info（"REALITY"）
    inline constexpr char RealityInfo[] = "REALITY";

    /// 最大短 ID 长度（8 字节）
    inline constexpr std::size_t MaxShortIdLen = 8;

    /** @brief Reality 服务端握手的 owning 冷材料。 */
    struct PreparedConfig final
    {
        std::array<std::uint8_t, KeyLen> PrivateKey{};
        std::vector<std::array<std::uint8_t, MaxShortIdLen>> ShortIds;
        std::vector<std::string> ServerNames;
    };

    /** @brief recognition 预读 ClientHello 后交给协议 owner 的请求。 */
    struct PreparedRequest final
    {
        Prism::SharedTransmission Inbound;
        PreparedConfig Config;
        std::span<const std::uint8_t> Random;
        std::span<const std::uint8_t> SessionId;
        std::span<const std::uint8_t> X25519Key;
        std::span<const std::uint8_t> RawMessage;
        std::string_view ServerName;
    };
} // namespace Prism::Reality
