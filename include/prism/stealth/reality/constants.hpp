/**
 * @file constants.hpp
 * @brief Stealth 模块 TLS 常量定义
 * @details 定义 TLS 1.3 记录层和握手协议的常量，用于 ClientHello 解析、
 * ServerHello 生成和加密记录处理。这些常量遵循 RFC 8446 (TLS 1.3)
 * 和 RFC 5246 (TLS 1.2) 的定义。
 */

#pragma once

#include <cstdint>
#include <prism/memory/container.hpp>

namespace psm::stealth::tls
{
    // TLS 记录头长度（字节）：ContentType(1) + Version(2) + Length(2)
    constexpr std::size_t RECORD_HEADER_LEN = 5;

    // TLS 记录最大载荷长度
    constexpr std::size_t MAX_RECORD_PAYLOAD = 16384;

    // Content Type
    constexpr std::uint8_t CONTENT_TYPE_CHANGE_CIPHER_SPEC = 0x14;
    constexpr std::uint8_t CONTENT_TYPE_ALERT = 0x15;
    constexpr std::uint8_t CONTENT_TYPE_HANDSHAKE = 0x16;
    constexpr std::uint8_t CONTENT_TYPE_APPLICATION_DATA = 0x17;

    // Handshake Type
    constexpr std::uint8_t HANDSHAKE_TYPE_CLIENT_HELLO = 0x01;
    constexpr std::uint8_t HANDSHAKE_TYPE_SERVER_HELLO = 0x02;
    constexpr std::uint8_t HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 0x08;
    constexpr std::uint8_t HANDSHAKE_TYPE_CERTIFICATE = 0x0B;
    constexpr std::uint8_t HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 0x0F;
    constexpr std::uint8_t HANDSHAKE_TYPE_FINISHED = 0x14;

    // Extension Type
    constexpr std::uint16_t EXT_SERVER_NAME = 0x0000;
    constexpr std::uint16_t EXT_SUPPORTED_GROUPS = 0x000A;
    constexpr std::uint16_t EXT_SIGNATURE_ALGORITHMS = 0x000D;
    constexpr std::uint16_t EXT_KEY_SHARE = 0x0033;
    constexpr std::uint16_t EXT_SUPPORTED_VERSIONS = 0x002B;
    constexpr std::uint16_t EXT_PSK_KEY_EXCHANGE_MODES = 0x002D;
    constexpr std::uint16_t EXT_ALPN = 0x0010;

    // Named Groups
    constexpr std::uint16_t NAMED_GROUP_SECP256R1 = 0x0017;
    constexpr std::uint16_t NAMED_GROUP_SECP384R1 = 0x0018;
    constexpr std::uint16_t NAMED_GROUP_X25519 = 0x001D;
    constexpr std::uint16_t NAMED_GROUP_X25519_MLKEM768 = 0x11EC;

    // TLS Version
    constexpr std::uint16_t VERSION_TLS10 = 0x0301;
    constexpr std::uint16_t VERSION_TLS12 = 0x0303;
    constexpr std::uint16_t VERSION_TLS13 = 0x0304;

    // Cipher Suite (TLS 1.3)
    constexpr std::uint16_t CIPHER_AES_128_GCM_SHA256 = 0x1301;
    constexpr std::uint16_t CIPHER_AES_256_GCM_SHA384 = 0x1302;
    constexpr std::uint16_t CIPHER_CHACHA20_POLY1305_SHA256 = 0x1303;

    // Server Name Type
    constexpr std::uint8_t SERVER_NAME_TYPE_HOSTNAME = 0x00;

    // Reality 认证
    constexpr std::size_t REALITY_KEY_LEN = 32;    // X25519 密钥/公钥长度
    constexpr std::size_t SHORT_ID_MAX_LEN = 16;   // Reality short ID 最大长度
    constexpr std::size_t SESSION_ID_MAX_LEN = 32; // TLS session_id 最大长度
    constexpr std::size_t AEAD_TAG_LEN = 16;       // AEAD tag 长度
    constexpr std::size_t AEAD_NONCE_LEN = 12;     // AEAD nonce 长度
    constexpr std::size_t AES_128_KEY_LEN = 16;    // AES-128-GCM 密钥长度

    // Signature Scheme (TLS 1.3)
    constexpr std::uint16_t SIGNATURE_SCHEME_ED25519 = 0x0807; // Ed25519 签名算法

    // TLS 记录层写入工具

    inline auto write_u8(memory::vector<std::uint8_t> &buf, std::uint8_t val) -> void
    {
        buf.push_back(val);
    }

    inline auto write_u16(memory::vector<std::uint8_t> &buf, std::uint16_t val) -> void
    {
        buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
    }

    inline auto write_u24(memory::vector<std::uint8_t> &buf, std::size_t val) -> void
    {
        buf.push_back(static_cast<std::uint8_t>((val >> 16) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
    }
} // namespace psm::stealth::tls
