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
    constexpr std::size_t tls_hdrsize = 5;               // TLS 记录头长度
    constexpr std::size_t tls_rndsize = 32;              // TLS Random 长度
    constexpr std::size_t tls_session_id_sz = 32;        // ShadowTLS 要求的 SessionID 长度
    constexpr std::size_t hmac_size = 4;                 // HMAC 标签长度（4 字节）

    // TLS 内容类型
    constexpr std::uint8_t content_handshake = 0x16;
    constexpr std::uint8_t content_appdata = 0x17;

    // TLS 握手类型
    constexpr std::uint8_t hs_type_clienthello = 0x01;
    constexpr std::uint8_t hs_type_serverhello = 0x02;

    // TLS 1.3 版本号
    constexpr std::uint16_t tls_ver13 = 0x0304;

    // TLS 扩展类型
    constexpr std::uint16_t ext_supported_versions = 43;

    // SessionID 中 HMAC 的位置
    // TLS Header(5) + Handshake Header(4) + SessionID Length(1) = 10
    // SessionID 32 字节，HMAC 在最后 4 字节
    constexpr std::size_t session_id_len_idx = 43; // ClientHello 中 SessionID 长度字节的偏移

    // Data frame header size (TLS Header 5 + HMAC 4)
    constexpr std::size_t tls_hmac_hdrsize = tls_hdrsize + hmac_size; // 9
} // namespace psm::stealth::shadowtls
