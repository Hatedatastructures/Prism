/**
 * @file types.hpp
 * @brief Shadowsocks 2022 协议基础类型（SIP022 规范）
 * @details 定义 SS2022 常量、方法类型与地址结构。
 *          握手首包：[Salt 16B][固定头密文 27B][变长头密文（含地址）]。
 *          固定头明文：[Type 1B][Timestamp 8B BE][VarHeaderLen 2B BE] = 11B。
 *          数据采用 AEAD 分块（长度块 + 载荷块）。
 * @note 参考 SIP022 规范与主库 include/prism/protocol/shadowsocks/。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace preview::shadowsocks2022
{

    /// 加密方法
    enum class cipher_method : std::uint8_t
    {
        /// 2022-blake3-aes-128-gcm（16 字节密钥）
        aes_128_gcm,
        /// 2022-blake3-aes-256-gcm（32 字节密钥）
        aes_256_gcm,
        /// 2022-blake3-chacha20-poly1305（32 字节密钥）
        chacha20_poly1305,
    };

    /// 请求头类型字节（客户端）
    inline constexpr std::uint8_t header_type_client = 0x00;

    /// 响应头类型字节（服务端）
    inline constexpr std::uint8_t header_type_server = 0x01;

    /// AEAD tag 长度
    inline constexpr std::size_t aead_tag_len = 16;

    /// 固定头明文长度：type(1) + ts(8) + varLen(2) = 11
    inline constexpr std::size_t fixed_hdr_plain = 11;

    /// 固定头密文长度：11 + 16 = 27
    inline constexpr std::size_t fixed_hdr_size = fixed_hdr_plain + aead_tag_len;

    /// 响应固定头明文长度：type(1) + ts(8) + requestSalt(16) + payloadLen(2) = 27
    inline constexpr std::size_t resp_fixed_hdr_plain = 1 + 8 + 16 + 2;

    /// 响应固定头密文长度：27 + 16 = 43
    inline constexpr std::size_t resp_fixed_hdr_size = resp_fixed_hdr_plain + aead_tag_len;

    /// 数据块最大载荷（SIP022：0x3FFF）
    inline constexpr std::uint16_t max_chunk_size = 0x3FFF;

    /// 长度块大小：2 + 16 = 18
    inline constexpr std::size_t len_block_size = 2 + aead_tag_len;

    /// BLAKE3 KDF 上下文字符串
    inline constexpr std::string_view kdf_context = "shadowsocks 2022 session subkey";

    /// SOCKS5 风格地址类型
    enum class address_type : std::uint8_t
    {
        /// IPv4（0x01）
        ipv4 = 0x01,
        /// 域名（0x03）
        domain = 0x03,
        /// IPv6（0x04）
        ipv6 = 0x04,
    };

    /// 目标地址
    struct address
    {
        /// 地址类型
        address_type type{address_type::domain};
        /// 主机
        std::string host;
        /// 端口
        std::uint16_t port{0};
    };

} // namespace preview::shadowsocks2022
