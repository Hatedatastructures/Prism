/**
 * @file types.hpp
 * @brief Trojan 协议基础类型（兼容 trojan-gfw）
 * @details 定义 Trojan 常量、命令、地址类型与请求结构。
 *          Trojan 头部格式：
 *          [SHA224(password) hex 56B][CRLF]
 *          [CMD 1B][ATYP 1B][ADDR][PORT 2B BE][CRLF]
 *          地址类型沿用 SOCKS5：IPv4=0x01, Domain=0x03, IPv6=0x04。
 * @note 参考 trojan-gfw 协议规范与主库 include/prism/Protocol/trojan/。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace Preview::Trojan
{

    /// 凭据长度（SHA224 hex 56 字符）
    inline constexpr std::size_t CredentialLen = 56;

    /// 命令类型
    enum class Command : std::uint8_t
    {
        /// TCP CONNECT（0x01）
        Connect = 0x01,
        /// UDP ASSOCIATE（0x03）
        UdpAssociate = 0x03,
        /// 多路复用（0x7F，Mihomo 扩展）
        Mux = 0x7F,
    };

    /// 地址类型（SOCKS5 风格）
    enum class AddressType : std::uint8_t
    {
        /// IPv4（0x01，4 字节）
        Ipv4 = 0x01,
        /// 域名（0x03，长度前缀）
        Domain = 0x03,
        /// IPv6（0x04，16 字节）
        Ipv6 = 0x04,
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

    /// Trojan 请求头（解析结果）
    struct RequestHeader
    {
        /// 命令
        Command Cmd{Command::Connect};
        /// 目标地址
        Address Target;
    };

} // namespace Preview::Trojan
