/**
 * @file constants.hpp
 * @brief VMess 协议线格式常量
 * @details 定义 VMess 协议的版本号、命令码、选项位、安全类型
 *          与 KDF 盐串。对齐 sing-vmess v0.2.5 服务端实现。
 */

#pragma once

#include <cstdint>
#include <string_view>

namespace psm::protocol::vmess
{

    /// 协议版本号
    inline constexpr std::uint8_t version = 0x01;

    /// AEAD 认证头最小长度（16 authID + 18 len 块 + 8 connNonce + 16 tag）
    inline constexpr std::size_t aead_min_header_len = 100;

    /// 时间戳容忍窗口（秒）
    inline constexpr std::int64_t time_tolerance = 120;

    /// 认证头时间戳长度（8 字节大端）
    inline constexpr std::size_t timestamp_len = 8;

    /// 认证头随机数长度
    inline constexpr std::size_t auth_random_len = 4;

    /// 认证头总长度（含 CRC32）
    inline constexpr std::size_t auth_header_len = 16;

    /// 指令头请求随机数长度
    inline constexpr std::size_t request_nonce_len = 16;

    /// 指令头请求密钥长度
    inline constexpr std::size_t request_key_len = 16;

    /// 数据块最大明文长度
    inline constexpr std::size_t max_chunk_len = 16384;

    /**
     * @enum command
     * @brief VMess 命令码
     */
    enum class command : std::uint8_t
    {
        tcp = 0x01, ///< TCP 代理
        udp = 0x02, ///< UDP 关联
        mux = 0x03, ///< v2ray mux 会话
    };

    /**
     * @enum option
     * @brief VMess 选项位
     */
    enum class option : std::uint8_t
    {
        chunk_stream = 0x01,         ///< 分块流
        connection_reuse = 0x02,     ///< 连接复用
        chunk_masking = 0x04,        ///< 长度掩码
        global_padding = 0x08,       ///< 全局填充
        authenticated_length = 0x10, ///< 认证长度
    };

    /**
     * @enum security
     * @brief 数据流安全类型
     */
    enum class security : std::uint8_t
    {
        legacy = 0x01,            ///< AES-128-CFB（旧式）
        auto_ = 0x02,             ///< 自动选择
        aes_128_gcm = 0x03,       ///< AES-128-GCM
        chacha20_poly1305 = 0x04, ///< ChaCha20-Poly1305
        none = 0x05,              ///< 无加密
        zero = 0x06,              ///< 零加密
    };

    /**
     * @enum address_type
     * @brief VMess 地址类型（端口在前，地址在后）
     */
    enum class address_type : std::uint8_t
    {
        ipv4 = 0x01,   ///< IPv4（4 字节）
        domain = 0x02, ///< 域名（1 字节长度 + 内容）
        ipv6 = 0x03,   ///< IPv6（16 字节）
    };

    // === KDF 盐串常量 ===

    /// UUID 派生密钥盐（所有 alterID 共享同一 cmdKey）
    inline constexpr std::string_view uuid_salt = "c48619fe-8f02-49e0-b9e9-edf763e17e21";

    /// 认证头加密盐
    inline constexpr std::string_view kdf_auth_id = "AES Auth ID Encryption";

    /// 指令头长度块密钥盐
    inline constexpr std::string_view kdf_header_len_key = "VMess Header AEAD Key_Length";

    /// 指令头长度块 nonce 盐
    inline constexpr std::string_view kdf_header_len_nonce = "VMess Header AEAD Nonce_Length";

    /// 指令头载荷密钥盐
    inline constexpr std::string_view kdf_header_key = "VMess Header AEAD Key";

    /// 指令头载荷 nonce 盐
    inline constexpr std::string_view kdf_header_nonce = "VMess Header AEAD Nonce";

    /// 响应头长度块密钥盐
    inline constexpr std::string_view kdf_resp_len_key = "AEAD Resp Header Len Key";

    /// 响应头长度块 nonce 盐
    inline constexpr std::string_view kdf_resp_len_iv = "AEAD Resp Header Len IV";

    /// 响应头载荷密钥盐
    inline constexpr std::string_view kdf_resp_key = "AEAD Resp Header Key";

    /// 响应头载荷 nonce 盐
    inline constexpr std::string_view kdf_resp_iv = "AEAD Resp Header IV";

    /// 认证长度块密钥盐
    inline constexpr std::string_view kdf_auth_len = "auth_len";

    /// 数据长度掩码/填充派生源（SHAKE128 流）
    inline constexpr std::size_t max_padding_len = 64;

} // namespace psm::protocol::vmess
