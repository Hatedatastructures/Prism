/**
 * @file types.hpp
 * @brief Trojan 协议基础类型（兼容 trojan-gfw）
 * @details 定义 Trojan 常量、命令、地址类型与请求结构。
 *          Trojan 头部格式：
 *          [SHA224(password) hex 56B][CRLF]
 *          [CMD 1B][ATYP 1B][ADDR][PORT 2B BE][CRLF]
 *          地址类型沿用 SOCKS5：IPv4=0x01, Domain=0x03, IPv6=0x04。
 * @note 参考 trojan-gfw 协议规范与主库 include/prism/protocol/trojan/。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace psmtest::trojan
{

    /// 凭据长度（SHA224 hex 56 字符）
    inline constexpr std::size_t credential_len = 56;

    /// 命令类型
    enum class command : std::uint8_t
    {
        /// TCP CONNECT（0x01）
        connect = 0x01,
        /// UDP ASSOCIATE（0x03）
        udp_associate = 0x03,
        /// 多路复用（0x7F，Mihomo 扩展）
        mux = 0x7F,
    };

    /// 地址类型（SOCKS5 风格）
    enum class address_type : std::uint8_t
    {
        /// IPv4（0x01，4 字节）
        ipv4 = 0x01,
        /// 域名（0x03，长度前缀）
        domain = 0x03,
        /// IPv6（0x04，16 字节）
        ipv6 = 0x04,
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

    /// Trojan 请求头（解析结果）
    struct request_header
    {
        /// 命令
        command cmd{command::connect};
        /// 目标地址
        address target;
    };

} // namespace psmtest::trojan
