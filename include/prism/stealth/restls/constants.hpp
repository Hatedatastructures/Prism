/**
 * @file constants.hpp
 * @brief Restls 协议常量
 * @details 定义 Restls 协议中使用的固定常数值。
 */
#pragma once

#include <cstddef>
#include <cstdint>

namespace psm::stealth::restls
{
    // TLS 记录层常量（与 ShadowTLS 共享）
    constexpr std::size_t tls_header_size = 5;          ///< TLS 记录头长度
    constexpr std::size_t tls_random_size = 32;         ///< TLS Random 长度

    // TLS 内容类型
    constexpr std::uint8_t content_type_handshake = 0x16;
    constexpr std::uint8_t content_type_application_data = 0x17;

    // TLS 握手类型
    constexpr std::uint8_t handshake_type_client_hello = 0x01;
    constexpr std::uint8_t handshake_type_server_hello = 0x02;

    // TLS 版本号
    constexpr std::uint16_t tls_version_1_2 = 0x0303;
    constexpr std::uint16_t tls_version_1_3 = 0x0304;

    // Restls 认证标签长度
    constexpr std::size_t auth_tag_size = 4;            ///< HMAC 标签长度（4 字节）

    // Restls 默认端口
    constexpr std::uint16_t default_tls_port = 443;
} // namespace psm::stealth::restls