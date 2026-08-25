/**
 * @file types.hpp
 * @brief VMess 协议基础类型（兼容 Xray/mihomo/sing-vmess AEAD）
 * @details 定义 VMess 常量、命令、安全类型与地址结构。
 *          VMess AEAD 认证头：AuthID(16) + Length(2) + Nonce(8) + Tag(16)，
 *          请求头经 AES-128-GCM 加密，数据采用 AEAD 分块。
 * @note 参考 mihomo transport/vmess/Conn.go 与主库 include/prism/Protocol/vmess/。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace Preview::Vmess
{

    /// 协议版本号
    inline constexpr std::uint8_t ProtocolVersion = 0x01;

    /// 认证头最小长度（16 authID + 2 len + 8 Nonce + 16 tag）
    inline constexpr std::size_t AeadMinHeaderLen = 100;

    /// 时间容忍窗口（秒）
    inline constexpr std::int64_t TimeTolerance = 120;

    /// 认证头时间戳长度（8 字节大端）
    inline constexpr std::size_t TimestampLen = 8;

    /// 认证头随机数长度
    inline constexpr std::size_t AuthRandomLen = 4;

    /// 认证头总长度（含 CRC32）
    inline constexpr std::size_t AuthHeaderLen = 16;

    /// 请求 Nonce 长度
    inline constexpr std::size_t RequestNonceLen = 16;

    /// 请求密钥长度
    inline constexpr std::size_t RequestKeyLen = 16;

    /// 最大分块长度
    inline constexpr std::size_t MaxChunkLen = 16384;

    /// 命令类型
    enum class Command : std::uint8_t
    {
        /// TCP 数据
        Tcp = 0x01,
        /// UDP 数据
        Udp = 0x02,
        /// v2ray mux 会话
        Mux = 0x03,
    };

    /// 命令字节：TCP（Beast 风格别名，对齐 Command::Tcp）
    inline constexpr std::uint8_t CmdTcp = static_cast<std::uint8_t>(Command::Tcp);
    /// 命令字节：UDP（Beast 风格别名，对齐 Command::Udp）
    inline constexpr std::uint8_t CmdUdp = static_cast<std::uint8_t>(Command::Udp);
    /// 命令字节：多路复用（Beast 风格别名，对齐 Command::Mux）
    inline constexpr std::uint8_t CmdMux = static_cast<std::uint8_t>(Command::Mux);

    /// 选项位
    enum class Option : std::uint8_t
    {
        /// 分块传输
        ChunkStream = 0x01,
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
    enum class Security : std::uint8_t
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
    enum class AddressType : std::uint8_t
    {
        /// IPv4（4 字节）
        Ipv4 = 0x01,
        /// 域名（1 字节长度 + 数据）
        Domain = 0x02,
        /// IPv6（16 字节）
        Ipv6 = 0x03,
    };

    /// KDF 派生路径常量
    inline constexpr std::string_view KdfInnerMarker = "VMess AEAD KDF";
    inline constexpr std::string_view KdfHeaderKey = "VMess Header AEAD Key";
    inline constexpr std::string_view KdfHeaderIv = "VMess Header AEAD Nonce";
    inline constexpr std::string_view KdfHeaderLenKey = "VMess Header AEAD Key_Length";
    inline constexpr std::string_view KdfHeaderLenIv = "VMess Header AEAD Nonce_Length";
    inline constexpr std::string_view KdfRespLenKey = "AEAD Resp Header Len Key";
    inline constexpr std::string_view KdfRespLenIv = "AEAD Resp Header Len IV";
    inline constexpr std::string_view KdfRespKey = "AEAD Resp Header Key";
    inline constexpr std::string_view KdfRespIv = "AEAD Resp Header IV";
    /// UUID 盐（cmdKey = MD5(uuid || salt)）
    inline constexpr std::string_view UuidSalt = "c48619fe-8f02-49e0-b9e9-edf763e17e21";

    /// VMess 目标地址
    struct Address
    {
        /// 地址类型
        AddressType Type{AddressType::Domain};
        /// 主机（域名或 IP 字符串）
        std::string Host;
        /// 端口
        std::uint16_t Port{0};
    };

    /// 请求头（加密前明文）
    struct RequestHeader
    {
        /// 协议版本
        std::uint8_t Version{ProtocolVersion};
        /// 命令
        std::uint8_t Cmd{static_cast<std::uint8_t>(Command::Tcp)};
        /// 选项
        std::uint8_t opt{0};
        /// 安全类型
        Security sec{Security::aes_128_gcm};
        /// 保留字段
        std::uint8_t reserved{0};
        /// 目标地址
        Address Target;
        /// 全局填充
        std::vector<std::uint8_t> padding;
    };

    /// 响应头
    struct ResponseHeader
    {
        /// 版本（0x01 = 认证成功）
        std::uint8_t Version{0x01};
        /// 附加数据（长度 = 余数）
        std::array<std::uint8_t, 4> v{};
    };

} // namespace Preview::Vmess
