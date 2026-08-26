/**
 * @file Types.hpp
 * @brief Tuic 协议基础类型
 * @details Tuic 是 QUIC 之上的代理协议，消息经 TLV 编码：
 *          [Ver 1B][Cmd 1B][...载荷]
 *          本测试库实现纯逻辑帧编解码（不含 QUIC 传输）。
 * @note 参考 tuic 协议规范。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace Preview::Tuic
{

    /// 协议版本
    inline constexpr std::uint8_t ProtocolVersion = 0x04;

    /// 命令常量（对齐 tuic 规范）
    inline constexpr std::uint8_t CmdConnect = 0x06;
    inline constexpr std::uint8_t CmdPacket = 0x07;
    inline constexpr std::uint8_t CmdDissociate = 0x08;
    inline constexpr std::uint8_t CmdHeartbeat = 0x09;

    /// 地址类型
    enum class AddressType : std::uint8_t
    {
        /// IPv4
        Ipv4 = 0x01,
        /// 域名
        Domain = 0x03,
        /// IPv6
        Ipv6 = 0x04,
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

    /// Tuic 消息
    struct Message
    {
        /// 命令
        std::uint8_t Cmd{CmdConnect};
        /// 会话关联 ID（packet/dissociate）
        std::uint32_t AssocId{0};
        /// 包 ID（packet）
        std::uint32_t PktId{0};
        /// 目标地址
        Address dst;
        /// 载荷
        std::string payload;
    };

} // namespace Preview::Tuic
