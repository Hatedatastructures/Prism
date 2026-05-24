/**
 * @file analyzer.hpp
 * @brief 外层协议检测与 TLS 内层协议识别
 * @details 通过魔术字节快速判断连接的外层协议类型（HTTP/SOCKS5/TLS/Shadowsocks）。
 * detect() 是纯内存操作，不涉及任何网络 I/O，可安全并发调用。
 * 检测采用排除法：匹配已知协议特征后直接返回，否则返回 unknown。
 * detect_tls() 在 TLS 握手完成后探测内层协议类型（HTTP/VLESS/Trojan）。
 * 60+ 字节无法匹配已知协议时返回 unknown，由调用者根据场景决定后续处理。
 * @note TLS 检测必须检查两字节（0x16 0x03），SS2022 salt 有约 1/256 概率
 * 首字节恰好为 0x16。
 * @warning 探测结果基于有限数据，后续数据可能推翻当前判断。
 */

#pragma once

#include <array>
#include <cstdint>
#include <string_view>
#include <prism/protocol/protocol_type.hpp>

namespace psm::recognition::probe
{
    /**
     * @brief 从预读数据检测外层协议类型
     * @param peek_data 预读数据（通常是前 24 字节）
     * @return 协议类型枚举值
     * @details 检测顺序：SOCKS5（首字节 0x05）→ TLS（前两字节 0x16 0x03）→
     * HTTP 方法名（GET/POST 等）→ Shadowsocks（排除法 fallback）。
     * 空数据返回 unknown。函数为纯计算操作，无状态，线程安全。
     */
    [[nodiscard]] auto detect(std::string_view peek_data)
        -> protocol::protocol_type;

    /// HTTP 方法列表，用于协议检测（最短 4 字节 "GET "）
    inline constexpr std::array<std::string_view, 9> tls_http_methods = {
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
        "CONNECT ", "OPTIONS ", "TRACE ", "PATCH "};

    /**
     * @brief 检查数据是否以已知 HTTP 方法前缀开头
     * @param data 待检查数据
     * @return 若匹配任何 HTTP 方法前缀则返回 true
     */
    inline auto is_http_request(const std::string_view data) noexcept
        -> bool
    {
        for (const auto &method : tls_http_methods)
        {
            if (data.size() >= method.size() && data.substr(0, method.size()) == method)
            {
                return true;
            }
        }
        return false;
    }

    /**
     * @brief 探测 TLS 内部协议类型
     * @details 在 TLS 握手完成后，探测内部承载的应用层协议类型。
     * 该方法用于区分 HTTPS、Trojan over TLS、VLESS 等协议。
     * 检测采用分层排除法：先匹配 HTTP 方法 → VLESS 特征 → Trojan 特征 →
     * 60 字节以上无法识别则返回 unknown，由调用者根据上下文决定（如 fallback 到 SS2022 或继续读取）。
     * @param peek_data TLS 握手后读取的数据，建议至少 60 字节
     * @return protocol_type 检测到的内部协议类型
     * @note 数据不足 60 字节且不匹配 HTTP/VLESS 时返回 protocol_type::unknown。
     *       60+ 字节且不匹配任何已知协议也返回 unknown，不自动 fallback。
     */
    inline auto detect_tls(std::string_view peek_data)
        -> protocol::protocol_type
    {
        // 阶段 1：HTTP 检测（最少 4 字节）
        if (peek_data.size() >= 4 && is_http_request(peek_data))
        {
            return protocol::protocol_type::http;
        }

        // 阶段 2：VLESS 检测（最少 22 字节）
        // byte[0] = 0x00 (version), byte[17] = 0x00 (no additional info)
        // byte[18] in {0x01, 0x02, 0x7F} (valid command)
        // byte[21] in {0x01, 0x02, 0x03} (valid address type)
        if (peek_data.size() >= 22)
        {
            const auto b0 = static_cast<std::uint8_t>(peek_data[0]);
            const auto b17 = static_cast<std::uint8_t>(peek_data[17]);
            const auto b18 = static_cast<std::uint8_t>(peek_data[18]);
            const auto b21 = static_cast<std::uint8_t>(peek_data[21]);

            if (b0 == 0x00 && b17 == 0x00 && (b18 == 0x01 || b18 == 0x02 || b18 == 0x7F) &&
                (b21 == 0x01 || b21 == 0x02 || b21 == 0x03))
            {
                return protocol::protocol_type::vless;
            }
        }

        // 阶段 3：Trojan 检测（最少 60 字节）
        constexpr std::size_t trojan_min_length = 60;
        if (peek_data.size() >= trojan_min_length)
        {
            bool is_trojan = true;
            for (std::size_t i = 0; i < 56; ++i)
            {
                const auto c = static_cast<std::uint8_t>(peek_data[i]);
                const bool is_hex_digit = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                                          (c >= 'A' && c <= 'F');
                if (!is_hex_digit)
                {
                    is_trojan = false;
                    break;
                }
            }

            if (is_trojan && peek_data[56] == '\r' && peek_data[57] == '\n')
            {
                const auto cmd = static_cast<std::uint8_t>(peek_data[58]);
                if (cmd == 0x01 || cmd == 0x03 || cmd == 0x7F)
                {
                    const auto atyp = static_cast<std::uint8_t>(peek_data[59]);
                    if (atyp == 0x01 || atyp == 0x03 || atyp == 0x04)
                    {
                        return protocol::protocol_type::trojan;
                    }
                }
            }

            // 60+ 字节且非 HTTP/VLESS/Trojan，无法确定具体协议
            // 返回 unknown 让调用者根据上下文决定（如 ShadowTLS 场景需更多数据）
            return protocol::protocol_type::unknown;
        }

        // 数据不足 60 字节且不匹配任何已知协议，返回 unknown 让调用者继续读取
        return protocol::protocol_type::unknown;
    }

} // namespace psm::recognition::probe
