/**
 * @file constants.hpp
 * @brief SS2022 (SIP022) 协议常量定义
 * @details 定义 Shadowsocks 2022 协议中使用的加密算法枚举、
 * 协议常量和配置参数。包含 TCP 和 UDP 两种传输模式
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace psm::protocol::shadowsocks
{
    /**
     * @enum cipher_method
     * @brief 支持的 AEAD 加密算法
     */
    enum class cipher_method : std::uint8_t
    {
        /** @brief 2022-blake3-aes-128-gcm，16 字节密钥/salt */
        aes_128_gcm,
        /** @brief 2022-blake3-aes-256-gcm，32 字节密钥/salt */
        aes_256_gcm,
        /** @brief 2022-blake3-chacha20-poly1305，32 字节密钥/salt */
        chacha20_poly1305
    };

    // 请求固定头类型字节
    static constexpr std::uint8_t request_type = 0x00;

    // 响应固定头类型字节
    static constexpr std::uint8_t response_type = 0x01;

    // AEAD 认证 tag 长度（AES-GCM / ChaCha20 固定 16 字节）
    static constexpr std::size_t aead_tag_len = 16;

    // 固定头明文长度：type(1) + timestamp(8) + varHeaderLen(2) = 11
    static constexpr std::size_t fixed_header_plain = 11;

    // 固定头密文长度：明文 + tag(16) = 27
    static constexpr std::size_t fixed_header_size = fixed_header_plain + aead_tag_len;

    // BLAKE3 KDF context（SIP022 规范：所有方法统一使用此字符串）
    static constexpr std::string_view kdf_context = "shadowsocks 2022 session subkey";

    // 数据块最大 payload 长度（SIP022 规范 0x3FFF）
    static constexpr std::uint16_t max_chunk_size = 0x3FFF;

    // 加密长度块大小：2 字节长度 + 16 字节 tag = 18
    static constexpr std::size_t length_block_size = 2 + aead_tag_len;

    // SOCKS5 地址类型
    static constexpr std::uint8_t atyp_ipv4 = 0x01;
    static constexpr std::uint8_t atyp_domain = 0x03;
    static constexpr std::uint8_t atyp_ipv6 = 0x04;

    // UDP Session ID 长度
    static constexpr std::size_t session_id_len = 8;

    // UDP Packet ID 长度
    static constexpr std::size_t packet_id_len = 8;

    // UDP Separate Header 总长度（SessionID + PacketID）
    static constexpr std::size_t separate_header_len = session_id_len + packet_id_len;

    // 方法名映射（配置用）
    static constexpr std::string_view method_aes_128 = "2022-blake3-aes-128-gcm";
    static constexpr std::string_view method_aes_256 = "2022-blake3-aes-256-gcm";
    static constexpr std::string_view method_chacha20 = "2022-blake3-chacha20-poly1305";
} // namespace psm::protocol::shadowsocks
