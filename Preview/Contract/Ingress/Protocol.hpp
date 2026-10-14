/** @file Protocol.hpp @brief 稳定协议身份及诊断名称。 */
#pragma once
#include <cstdint>
#include <string_view>
namespace Preview::Contract
{
    /**
     * @enum ProtocolType
     * @brief 协议类型
     */
    enum class ProtocolType : std::uint8_t
    {
        Unknown,     ///< 未知
        Http,        ///< HTTP（含 CONNECT）
        Socks5,      ///< SOCKS5（0x05）
        Trojan,      ///< Trojan（认证凭据与命令，不使用固定魔数）
        Vless,       ///< VLESS（二进制版本、UUID 与命令）
        Shadowsocks, ///< Shadowsocks（2022 系）
        Vmess,       ///< VMess（认证首部，不使用固定魔数）
        Hysteria2,   ///< Hysteria2（QUIC，不适用 TCP 探测）
        Tuic,        ///< TUIC（QUIC，不适用 TCP 探测）
        Tls,         ///< TLS（0x16 0x03）
        AnyTls,      ///< AnyTLS
        TrustTunnel, ///< TrustTunnel
    };

    /**
     * @brief 协议类型转字符串
     * @param Type 协议类型
     * @return 字符串表示
     */
    [[nodiscard]] inline auto ToStringView(ProtocolType Type) noexcept -> std::string_view
    {
        switch (Type)
        {
        case ProtocolType::Unknown: return "unknown";
        case ProtocolType::Http: return "http";
        case ProtocolType::Socks5: return "socks5";
        case ProtocolType::Trojan: return "trojan";
        case ProtocolType::Vless: return "vless";
        case ProtocolType::Shadowsocks: return "shadowsocks";
        case ProtocolType::Vmess: return "vmess";
        case ProtocolType::Hysteria2: return "hysteria2";
        case ProtocolType::Tuic: return "tuic";
        case ProtocolType::Tls: return "tls";
        case ProtocolType::AnyTls: return "anytls";
        case ProtocolType::TrustTunnel: return "trusttunnel";
        default: return "unknown";
        }
    }

}
