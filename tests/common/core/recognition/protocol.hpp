/**
 * @file protocol.hpp
 * @brief 协议类型枚举与首字节识别
 * @details 定义 preview 统一协议类型（对照主项目 connect::protocol_type），
 *          提供首包字节检测（probe 基础）：按特征字节映射到协议类型。
 */

#pragma once

#include <cstdint>
#include <span>
#include <string_view>

namespace preview::recognition
{

    /**
     * @enum protocol_type
     * @brief 协议类型
     */
    enum class protocol_type : std::uint8_t
    {
        unknown,     ///< 未知
        http,        ///< HTTP（含 CONNECT）
        socks5,      ///< SOCKS5（0x05）
        trojan,      ///< Trojan（hex 0x0D 0x0A 0x0D 0x0A）
        vless,       ///< VLESS（0x56 0x4C 0x45 0x53 0x53）
        shadowsocks, ///< Shadowsocks（2022 系）
        vmess,       ///< VMess（0x01 0x00 0x00 ...）
        hysteria2,   ///< Hysteria2（QUIC，不适用 TCP 探测）
        tuic,        ///< TUIC（QUIC，不适用 TCP 探测）
        tls,         ///< TLS（0x16 0x03）
    };

    /**
     * @brief 协议类型转字符串
     * @param type 协议类型
     * @return 字符串表示
     */
    [[nodiscard]] inline auto to_string_view(protocol_type type) noexcept -> std::string_view
    {
        switch (type)
        {
        case protocol_type::unknown: return "unknown";
        case protocol_type::http: return "http";
        case protocol_type::socks5: return "socks5";
        case protocol_type::trojan: return "trojan";
        case protocol_type::vless: return "vless";
        case protocol_type::shadowsocks: return "shadowsocks";
        case protocol_type::vmess: return "vmess";
        case protocol_type::hysteria2: return "hysteria2";
        case protocol_type::tuic: return "tuic";
        case protocol_type::tls: return "tls";
        default: return "unknown";
        }
    }

    /// VMess 特征字节（命令头）
    inline constexpr std::uint8_t vmess_magic = 0x01;

    /// Trojan 特征（前 4 字节 CRLF）
    inline constexpr std::array<std::uint8_t, 4> trojan_magic = {0x0D, 0x0A, 0x0D, 0x0A};

    /// VLESS 特征（"VLESS"）
    inline constexpr std::array<std::uint8_t, 5> vless_magic = {0x56, 0x4C, 0x45, 0x53, 0x53};

    /**
     * @brief 按首包字节检测协议类型
     * @param data 首包字节（≥1 字节）
     * @return 检测到的协议类型
     * @details 特征匹配：
     *          - 0x05 → socks5
     *          - 0x16 0x03 → tls
     *          - "VLESS" 或结构化特征（version 0x00 + 合法 cmd/atyp，
     *            预读窗口内）→ vless
     *          - 0x0D 0x0A 0x0D 0x0A → trojan
     *          - 0x01 且后续 4 字节版本特征 → vmess
     *          - "GET/POST/CONNECT " 前缀 → http
     *          - 其余 → unknown（ss2022 需 salt 分析，此处保守 unknown）
     */
    [[nodiscard]] inline auto detect(std::span<const std::uint8_t> data) noexcept -> protocol_type
    {
        if (data.empty())
        {
            return protocol_type::unknown;
        }
        switch (data[0])
        {
        case 0x05:
            return protocol_type::socks5;
        case 0x16:
            if (data.size() >= 2 && data[1] == 0x03)
            {
                return protocol_type::tls;
            }
            return protocol_type::unknown;
        default: break;
        }
        if (data.size() >= 5 && data[0] == vless_magic[0] && data[1] == vless_magic[1] &&
            data[2] == vless_magic[2] && data[3] == vless_magic[3] && data[4] == vless_magic[4])
        {
            return protocol_type::vless;
        }
        // VLESS 结构化识别（Xray 首字节为 version 0x00）：仅在预读窗口内有效——
        // probe 最多预读 24 字节（见 probe.hpp max_probe_size），头部固定部分
        // 已占 22 字节，故仅 addnl ≤ 2 可命中；更长 addons 无法在窗口内完成
        // 校验，只能回落到上方 "VLESS" 魔数路径
        if (data.size() >= 18 && data[0] == 0x00)
        {
            const std::size_t addnl = data[17];
            const std::size_t need = 18 + addnl + 4;
            if (data.size() >= need)
            {
                const auto cmd = data[18 + addnl];
                const auto atyp = data[21 + addnl];
                if ((cmd == 0x01 || cmd == 0x02) &&
                    (atyp == 0x01 || atyp == 0x02 || atyp == 0x03))
                {
                    return protocol_type::vless;
                }
            }
        }
        if (data.size() >= 4 && data[0] == trojan_magic[0] && data[1] == trojan_magic[1] &&
            data[2] == trojan_magic[2] && data[3] == trojan_magic[3])
        {
            return protocol_type::trojan;
        }
        if (data.size() >= 1 && data[0] == vmess_magic)
        {
            return protocol_type::vmess;
        }
        // HTTP 方法前缀
        constexpr std::string_view methods[] = {"GET ", "POST ", "CONNECT ", "PUT ", "DELETE ", "HEAD "};
        for (const auto &m : methods)
        {
            if (data.size() >= m.size() &&
                std::string_view(reinterpret_cast<const char *>(data.data()), m.size()) == m)
            {
                return protocol_type::http;
            }
        }
        return protocol_type::unknown;
    }

} // namespace preview::recognition
