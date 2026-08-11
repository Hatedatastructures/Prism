/**
 * @file types.hpp
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

namespace psmtest::tuic
{

    /// 协议版本
    inline constexpr std::uint8_t protocol_version = 0x04;

    /// 命令常量（对齐 tuic 规范）
    inline constexpr std::uint8_t cmd_connect = 0x06;
    inline constexpr std::uint8_t cmd_packet = 0x07;
    inline constexpr std::uint8_t cmd_dissociate = 0x08;
    inline constexpr std::uint8_t cmd_heartbeat = 0x09;

    /// 地址类型
    enum class address_type : std::uint8_t
    {
        /// IPv4
        ipv4 = 0x01,
        /// 域名
        domain = 0x03,
        /// IPv6
        ipv6 = 0x04,
    };

    /// 目标地址
    struct address
    {
        /// 地址类型
        address_type type{address_type::domain};
        /// 主机
        std::string host;
        /// 端口
        std::uint16_t port{0};
    };

    /// Tuic 消息
    struct message
    {
        /// 命令
        std::uint8_t cmd{cmd_connect};
        /// 会话关联 ID（packet/dissociate）
        std::uint32_t assoc_id{0};
        /// 包 ID（packet）
        std::uint32_t pkt_id{0};
        /// 目标地址
        address dst;
        /// 载荷
        std::string payload;
    };

} // namespace psmtest::tuic
