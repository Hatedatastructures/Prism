/**
 * @file types.hpp
 * @brief VMess 协议基础类型（兼容 Xray/mihomo/sing-vmess AEAD）
 * @details 定义 VMess 常量、命令、安全类型与地址结构。
 *          VMess AEAD 认证头：AuthID(16) + Length(2) + Nonce(8) + Tag(16)，
 *          请求头经 AES-128-GCM 加密，数据采用 AEAD 分块。
 * @note 参考 mihomo transport/vmess/conn.go 与主库 include/prism/protocol/vmess/。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace preview::vmess
{

    /// 协议版本号
    inline constexpr std::uint8_t protocol_version = 0x01;

    /// 认证头最小长度（16 authID + 2 len + 8 nonce + 16 tag）
    inline constexpr std::size_t aead_min_header_len = 100;

    /// 时间容忍窗口（秒）
    inline constexpr std::int64_t time_tolerance = 120;

    /// 认证头时间戳长度（8 字节大端）
    inline constexpr std::size_t timestamp_len = 8;

    /// 认证头随机数长度
    inline constexpr std::size_t auth_random_len = 4;

    /// 认证头总长度（含 CRC32）
    inline constexpr std::size_t auth_header_len = 16;

    /// 请求 nonce 长度
    inline constexpr std::size_t request_nonce_len = 16;

    /// 请求密钥长度
    inline constexpr std::size_t request_key_len = 16;

    /// 最大分块长度
    inline constexpr std::size_t max_chunk_len = 16384;

    /// 命令类型
    enum class command : std::uint8_t
    {
        /// TCP 数据
        tcp = 0x01,
        /// UDP 数据
        udp = 0x02,
        /// v2ray mux 会话
        mux = 0x03,
    };

    /// 命令字节：TCP（Beast 风格别名，对齐 command::tcp）
    inline constexpr std::uint8_t cmd_tcp = static_cast<std::uint8_t>(command::tcp);
    /// 命令字节：UDP（Beast 风格别名，对齐 command::udp）
    inline constexpr std::uint8_t cmd_udp = static_cast<std::uint8_t>(command::udp);
    /// 命令字节：多路复用（Beast 风格别名，对齐 command::mux）
    inline constexpr std::uint8_t cmd_mux = static_cast<std::uint8_t>(command::mux);

    /// 选项位
    enum class option : std::uint8_t
    {
        /// 分块传输
        chunk_stream = 0x01,
        /// 连接复用
        connection_reuse = 0x02,
        /// 分块掩码
        chunk_masking = 0x04,
        /// 全局填充
        global_padding = 0x08,
        /// 认证长度
        authenticated_length = 0x10,
    };

    /// 安全类型
    enum class security : std::uint8_t
    {
        /// AES-128-CFB 旧式
        legacy = 0x01,
        /// 自动选择
        auto_ = 0x02,
        /// AES-128-GCM
        aes_128_gcm = 0x03,
        /// ChaCha20-Poly1305
        chacha20_poly1305 = 0x04,
        /// 无加密
        none = 0x05,
        /// 零加密
        zero = 0x06,
    };

    /// 地址类型
    enum class address_type : std::uint8_t
    {
        /// IPv4（4 字节）
        ipv4 = 0x01,
        /// 域名（1 字节长度 + 数据）
        domain = 0x02,
        /// IPv6（16 字节）
        ipv6 = 0x03,
    };

    /// KDF 派生路径常量
    inline constexpr std::string_view kdf_inner_marker = "VMess AEAD KDF";
    inline constexpr std::string_view kdf_header_key = "VMess Header AEAD Key";
    inline constexpr std::string_view kdf_header_iv = "VMess Header AEAD Nonce";
    inline constexpr std::string_view kdf_header_len_key = "VMess Header AEAD Key_Length";
    inline constexpr std::string_view kdf_header_len_iv = "VMess Header AEAD Nonce_Length";
    inline constexpr std::string_view kdf_resp_len_key = "AEAD Resp Header Len Key";
    inline constexpr std::string_view kdf_resp_len_iv = "AEAD Resp Header Len IV";
    inline constexpr std::string_view kdf_resp_key = "AEAD Resp Header Key";
    inline constexpr std::string_view kdf_resp_iv = "AEAD Resp Header IV";
    /// UUID 盐（cmdKey = MD5(uuid || salt)）
    inline constexpr std::string_view uuid_salt = "c48619fe-8f02-49e0-b9e9-edf763e17e21";

    /// VMess 目标地址
    struct address
    {
        /// 地址类型
        address_type type{address_type::domain};
        /// 主机（域名或 IP 字符串）
        std::string host;
        /// 端口
        std::uint16_t port{0};
    };

    /// 请求头（加密前明文）
    struct request_header
    {
        /// 协议版本
        std::uint8_t version{protocol_version};
        /// 命令
        command cmd{command::tcp};
        /// 选项
        std::uint8_t opt{0};
        /// 安全类型
        security sec{security::aes_128_gcm};
        /// 保留字段
        std::uint8_t reserved{0};
        /// 目标地址
        address target;
        /// 全局填充
        std::vector<std::uint8_t> padding;
    };

    /// 响应头
    struct response_header
    {
        /// 版本（0x01 = 认证成功）
        std::uint8_t version{0x01};
        /// 附加数据（长度 = 余数）
        std::array<std::uint8_t, 4> v{};
    };

} // namespace preview::vmess
