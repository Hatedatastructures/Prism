/**
 * @file types.hpp
 * @brief Hysteria2 协议基础类型
 * @details Hysteria2 是 QUIC 之上的代理协议：
 *          - 认证：HTTP/3 风格 HEADERS 帧（:Method POST, :Path /Auth, authorization）
 *          - TCP/UDP 数据：可变长帧，UDP 携带 SessionId + PacketId
 *          本测试库实现纯逻辑帧编解码（不含 QUIC 传输）。
 * @note 参考 hysteria2 协议规范。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace Preview::Hysteria2
{

    /// 地址类型
    enum class AddressType : std::uint8_t
    {
        /// IPv4（1 字节类型 + 4 字节）
        Ipv4 = 0x01,
        /// 域名（1 字节类型 + 1 长度 + 数据）
        Domain = 0x02,
        /// IPv6（1 字节类型 + 16 字节）
        Ipv6 = 0x03,
    };

    /// 目标地址
    struct Address
    {
        /// 地址类型
        AddressType Type{AddressType::Domain};
        /// 主机
        std::string Host;
        /// 端口
        std::uint16_t Port{0};
    };

    /// Hysteria2 消息（帧）
    struct Message
    {
        /// 消息类型
        enum class Kind : std::uint8_t
        {
            /// TCP 数据
            Tcp = 0x01,
            /// UDP 数据（带 Session/packet Id）
            udp = 0x02,
        };

        /// 消息类型
        Kind Type{Kind::Tcp};
        /// UDP 会话 ID（Type == udp）
        std::uint32_t SessionId{0};
        /// UDP 包 ID（Type == udp）
        std::uint32_t PacketId{0};
        /// 目标地址
        Address dst;
        /// 载荷
        std::string payload;
    };

} // namespace Preview::Hysteria2
