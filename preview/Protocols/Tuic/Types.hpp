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
#include <functional>
#include <span>
#include <string>
#include <string_view>

namespace Preview::Tuic
{

    /// 协议版本
    inline constexpr std::uint8_t ProtocolVersion = 0x05;

    /// UUID 长度
    inline constexpr std::size_t UuidLen = 16;

    /// TLS exporter 令牌长度
    inline constexpr std::size_t TokenLen = 32;

    /// 认证帧长度
    inline constexpr std::size_t AuthenticateFrameLen = 2 + UuidLen + TokenLen;

    /// 命令常量（TUIC v5）
    inline constexpr std::uint8_t CmdAuthenticate = 0x00;

    inline constexpr std::uint8_t CmdConnect = 0x01;
    inline constexpr std::uint8_t CmdPacket = 0x02;
    inline constexpr std::uint8_t CmdDissociate = 0x03;
    inline constexpr std::uint8_t CmdHeartbeat = 0x04;

    /// 地址类型
    enum class AddressType : std::uint8_t
    {
        /// 域名
        Domain = 0x00,
        /// IPv4
        Ipv4 = 0x01,
        /// IPv6
        Ipv6 = 0x02,
        /// 后续分片无地址
        None = 0xFF,
    };

    /// TLS exporter 回调。Label 必须为原始 UUID，Context 必须为密码。
    using KeyingMaterialExporter = std::function<bool(std::span<std::uint8_t> Output,
                                                       std::span<const std::uint8_t> Label,
                                                       std::string_view Context)>;

    /// TUIC v5 认证帧
    struct AuthenticateFrame
    {
        std::array<std::uint8_t, UuidLen> Uuid{};
        std::array<std::uint8_t, TokenLen> Token{};
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
        std::uint16_t AssocId{0};
        /// 包 ID（packet）
        std::uint16_t PktId{0};
        /// 分片总数（packet）
        std::uint8_t FragTotal{1};
        /// 分片序号（packet）
        std::uint8_t FragId{0};
        /// 载荷长度（packet）
        std::uint16_t Size{0};
        /// 目标地址
        Address dst;
        /// 载荷
        std::string payload;
    };

} // namespace Preview::Tuic
