/**
 * @file types.hpp
 * @brief Hysteria2 协议基础类型
 * @details Hysteria2 是 QUIC 之上的代理协议：
 *          - 认证：HTTP/3 风格 HEADERS 帧（:method POST, :path /auth, authorization）
 *          - TCP/UDP 数据：可变长帧，UDP 携带 session_id + packet_id
 *          本测试库实现纯逻辑帧编解码（不含 QUIC 传输）。
 * @note 参考 hysteria2 协议规范。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace psmtest::hysteria2
{

    /// 地址类型
    enum class address_type : std::uint8_t
    {
        /// IPv4（1 字节类型 + 4 字节）
        ipv4 = 0x01,
        /// 域名（1 字节类型 + 1 长度 + 数据）
        domain = 0x02,
        /// IPv6（1 字节类型 + 16 字节）
        ipv6 = 0x03,
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

    /// Hysteria2 消息（帧）
    struct message
    {
        /// 消息类型
        enum class kind : std::uint8_t
        {
            /// TCP 数据
            tcp = 0x01,
            /// UDP 数据（带 session/packet id）
            udp = 0x02,
        };

        /// 消息类型
        kind type{kind::tcp};
        /// UDP 会话 ID（type == udp）
        std::uint32_t session_id{0};
        /// UDP 包 ID（type == udp）
        std::uint32_t packet_id{0};
        /// 目标地址
        address dst;
        /// 载荷
        std::string payload;
    };

    /// 认证请求（HTTP/3 HEADERS 帧，首字节 0x01）
    [[nodiscard]] inline auto make_auth_request(std::string_view password) -> std::string
    {
        // QUIC HEADERS 帧：[Type 0x01][Length varint][HTTP/3 头块]
        // 简化头块：:method POST、:path /auth、authorization: <password>
        std::string payload = "POST /auth HTTP/1.1\r\n";
        payload += "Host: hysteria2\r\n";
        payload += "Authorization: " + std::string(password) + "\r\n";
        payload += "\r\n";
        std::string out;
        out.push_back(static_cast<char>(0x01)); // HEADERS 帧类型
        out.push_back(static_cast<char>(payload.size())); // 长度（简化 1 字节）
        out += payload;
        return out;
    }

} // namespace psmtest::hysteria2
