/**
 * @file constants.hpp
 * @brief ShadowTLS v3 协议常量
 * @details 定义 ShadowTLS v3 协议中使用的固定常数值。
 * 这些常量与 TLS 1.3 记录层格式和 ShadowTLS 认证机制相关。
 */
#pragma once

#include <cstddef>
#include <cstdint>

namespace psm::stealth::shadowtls
{
    // TLS 记录层常量
    constexpr std::size_t tls_header_size = 5;          // TLS 记录头长度
    constexpr std::size_t tls_random_size = 32;         // TLS Random 长度
    constexpr std::size_t tls_session_id_max = 32;      // SessionID 最大长度
    constexpr std::size_t tls_session_id_size = 32;     // ShadowTLS 要求的 SessionID 长度
    constexpr std::size_t hmac_size = 4;                // HMAC 标签长度（4 字节）

    // TLS 内容类型
    constexpr std::uint8_t content_type_handshake = 0x16;
    constexpr std::uint8_t content_type_application_data = 0x17;
    constexpr std::uint8_t content_type_alert = 0x15;
    constexpr std::uint8_t content_type_change_cipher_spec = 0x14;

    // TLS 握手类型
    constexpr std::uint8_t handshake_type_client_hello = 0x01;
    constexpr std::uint8_t handshake_type_server_hello = 0x02;

    // TLS 1.3 版本号
    constexpr std::uint16_t tls_version_1_3 = 0x0304;

    // TLS 扩展类型
    constexpr std::uint16_t extension_supported_versions = 43;

    // SessionID 中 HMAC 的位置
    // TLS Header(5) + Handshake Header(4) + SessionID Length(1) = 10
    // SessionID 32 字节，HMAC 在最后 4 字节
    constexpr std::size_t session_id_length_index = 43; // ClientHello 中 SessionID 长度字节的偏移
    constexpr std::size_t hmac_index = 43 + 1 + tls_session_id_size - hmac_size; // HMAC 在 SessionID 中的偏移（28）

    // 数据帧头大小 (TLS Header 5 + HMAC 4)
    constexpr std::size_t tls_hmac_header_size = tls_header_size + hmac_size; // 9

    // KDF 派生密钥长度
    constexpr std::size_t write_key_size = 64; // SHA256 输出
} // namespace psm::stealth::shadowtls
