/**
 * @file types.hpp
 * @brief VLESS 协议基础类型（兼容 Xray/mihomo/sing-box）
 * @details 定义 VLESS 常量、命令、地址类型与请求结构。
 *          VLESS 是无加密的轻量协议，通常承载于 TLS 内部，
 *          UUID 用于用户认证。请求头格式：
 *          [Version 1B][UUID 16B][AddnlLen 1B][Addnl var][Cmd 1B]
 *          [Port 2B BE][Atyp 1B][Addr var]
 * @note 参考 Xray VLESS 规范与主库 include/prism/Protocol/vless/。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace Preview::Vless
{

    /// 协议版本号（固定 0x00）
    inline constexpr std::uint8_t ProtocolVersion = 0x00;

    /// 命令常量（BeastTest 兼容别名）
    inline constexpr std::uint8_t CmdTcp = 0x01;
    inline constexpr std::uint8_t CmdUdp = 0x02;
    inline constexpr std::uint8_t CmdMux = 0x7F;

    /// UUID 长度
    inline constexpr std::size_t UuidLen = 16;

    /// 命令类型
    enum class Command : std::uint8_t
    {
        /// TCP 数据（0x01）
        Tcp = 0x01,
        /// UDP 数据（0x02）
        Udp = 0x02,
        /// 多路复用（0x7F，sing-box 扩展）
        Mux = 0x7F,
    };

    /// 地址类型（注意：与 Trojan/SOCKS5 的值不同！）
    enum class AddressType : std::uint8_t
    {
        /// IPv4（0x01）
        Ipv4 = 0x01,
        /// 域名（0x02，长度前缀）
        Domain = 0x02,
        /// IPv6（0x03）
        Ipv6 = 0x03,
    };

    /// 目标地址
    struct Address
    {
        /// 地址类型
        AddressType Type{AddressType::Domain};
        /// 主机（域名或 IP 字符串）
        std::string Host;
        /// 端口
        std::uint16_t Port{0};
    };

    /// VLESS 请求头（解析结果）
    struct RequestHeader
    {
        /// 协议版本
        std::uint8_t Version{ProtocolVersion};
        /// 用户 UUID（16 字节）
        std::array<std::uint8_t, UuidLen> Uuid{};
        /// 附加信息（流控等）
        std::vector<std::uint8_t> Addons;
        /// 命令
        Command Cmd{Command::Tcp};
        /// 目标地址
        Address Target;
    };

} // namespace Preview::Vless
