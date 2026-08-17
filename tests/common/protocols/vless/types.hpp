/**
 * @file types.hpp
 * @brief VLESS 协议基础类型（兼容 Xray/mihomo/sing-box）
 * @details 定义 VLESS 常量、命令、地址类型与请求结构。
 *          VLESS 是无加密的轻量协议，通常承载于 TLS 内部，
 *          UUID 用于用户认证。请求头格式：
 *          [Version 1B][UUID 16B][AddnlLen 1B][Addnl var][Cmd 1B]
 *          [Port 2B BE][Atyp 1B][Addr var]
 * @note 参考 Xray VLESS 规范与主库 include/prism/protocol/vless/。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace preview::vless
{

    /// 协议版本号（固定 0x00）
    inline constexpr std::uint8_t protocol_version = 0x00;

    /// 命令常量（BeastTest 兼容别名）
    inline constexpr std::uint8_t cmd_tcp = 0x01;
    inline constexpr std::uint8_t cmd_udp = 0x02;
    inline constexpr std::uint8_t cmd_mux = 0x7F;

    /// UUID 长度
    inline constexpr std::size_t uuid_len = 16;

    /// 命令类型
    enum class command : std::uint8_t
    {
        /// TCP 数据（0x01）
        tcp = 0x01,
        /// UDP 数据（0x02）
        udp = 0x02,
        /// 多路复用（0x7F，sing-box 扩展）
        mux = 0x7F,
    };

    /// 地址类型（注意：与 Trojan/SOCKS5 的值不同！）
    enum class address_type : std::uint8_t
    {
        /// IPv4（0x01）
        ipv4 = 0x01,
        /// 域名（0x02，长度前缀）
        domain = 0x02,
        /// IPv6（0x03）
        ipv6 = 0x03,
    };

    /// 目标地址
    struct address
    {
        /// 地址类型
        address_type type{address_type::domain};
        /// 主机（域名或 IP 字符串）
        std::string host;
        /// 端口
        std::uint16_t port{0};
    };

    /// VLESS 请求头（解析结果）
    struct request_header
    {
        /// 协议版本
        std::uint8_t version{protocol_version};
        /// 用户 UUID（16 字节）
        std::array<std::uint8_t, uuid_len> uuid{};
        /// 附加信息（流控等）
        std::vector<std::uint8_t> addons;
        /// 命令
        command cmd{command::tcp};
        /// 目标地址
        address target;
    };

} // namespace preview::vless
