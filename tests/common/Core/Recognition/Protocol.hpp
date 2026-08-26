/**
 * @file Protocol.hpp
 * @brief 协议类型枚举与首字节识别
 * @details 定义 Preview 统一协议类型（对照主项目 Connect::ProtocolType），
 *          提供首包字节检测（Probe 基础）：按特征字节映射到协议类型。
 */

#pragma once

#include <cstdint>
#include <span>
#include <string_view>

namespace Preview::Recognition
{

    /**
     * @enum ProtocolType
     * @brief 协议类型
     */
    enum class ProtocolType : std::uint8_t
    {
        Unknown,     ///< 未知
        Http,        ///< HTTP（含 CONNECT）
        Socks5,      ///< SOCKS5（0x05）
        Trojan,      ///< Trojan（hex 0x0D 0x0A 0x0D 0x0A）
        Vless,       ///< VLESS（0x56 0x4C 0x45 0x53 0x53）
        Shadowsocks, ///< Shadowsocks（2022 系）
        Vmess,       ///< VMess（0x01 0x00 0x00 ...）
        Hysteria2,   ///< Hysteria2（QUIC，不适用 TCP 探测）
        Tuic,        ///< TUIC（QUIC，不适用 TCP 探测）
        Tls,         ///< TLS（0x16 0x03）
    };

    /**
     * @brief 协议类型转字符串
     * @param Type 协议类型
     * @return 字符串表示
     */
    [[nodiscard]] inline auto ToStringView(ProtocolType Type) noexcept -> std::string_view
    {
        switch (Type)
        {
        case ProtocolType::Unknown: return "unknown";
        case ProtocolType::Http: return "http";
        case ProtocolType::Socks5: return "socks5";
        case ProtocolType::Trojan: return "trojan";
        case ProtocolType::Vless: return "vless";
        case ProtocolType::Shadowsocks: return "shadowsocks";
        case ProtocolType::Vmess: return "vmess";
        case ProtocolType::Hysteria2: return "hysteria2";
        case ProtocolType::Tuic: return "tuic";
        case ProtocolType::Tls: return "tls";
        default: return "unknown";
        }
    }

    /// VMess 特征字节（命令头）
    inline constexpr std::uint8_t VmessMagic = 0x01;

    /// Trojan 特征（前 4 字节 CRLF）
    inline constexpr std::array<std::uint8_t, 4> TrojanMagic = {0x0D, 0x0A, 0x0D, 0x0A};

    /// VLESS 特征（"VLESS"）
    inline constexpr std::array<std::uint8_t, 5> VlessMagic = {0x56, 0x4C, 0x45, 0x53, 0x53};

    /**
     * @brief 按首包字节检测协议类型
     * @param Data 首包字节（≥1 字节）
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
    [[nodiscard]] inline auto Detect(std::span<const std::uint8_t> Data) noexcept -> ProtocolType
    {
        if (Data.empty())
        {
            return ProtocolType::Unknown;
        }
        switch (Data[0])
        {
        case 0x05:
            return ProtocolType::Socks5;
        case 0x16:
            if (Data.size() >= 2 && Data[1] == 0x03)
            {
                return ProtocolType::Tls;
            }
            return ProtocolType::Unknown;
        default: break;
        }
        if (Data.size() >= 5 && Data[0] == VlessMagic[0] && Data[1] == VlessMagic[1] &&
            Data[2] == VlessMagic[2] && Data[3] == VlessMagic[3] && Data[4] == VlessMagic[4])
        {
            return ProtocolType::Vless;
        }
        // VLESS 结构化识别（Xray 首字节为 version 0x00）：仅在预读窗口内有效——
        // Probe 最多预读 24 字节（见 Probe.hpp MaxProbeSize），头部固定部分
        // 已占 22 字节，故仅 addnl ≤ 2 可命中；更长 addons 无法在窗口内完成
        // 校验，只能回落到上方 "VLESS" 魔数路径
        if (Data.size() >= 18 && Data[0] == 0x00)
        {
            const std::size_t Addnl = Data[17];
            const std::size_t Need = 18 + Addnl + 4;
            if (Data.size() >= Need)
            {
                const auto Cmd = Data[18 + Addnl];
                const auto Atyp = Data[21 + Addnl];
                if ((Cmd == 0x01 || Cmd == 0x02) &&
                    (Atyp == 0x01 || Atyp == 0x02 || Atyp == 0x03))
                {
                    return ProtocolType::Vless;
                }
            }
        }
        if (Data.size() >= 4 && Data[0] == TrojanMagic[0] && Data[1] == TrojanMagic[1] &&
            Data[2] == TrojanMagic[2] && Data[3] == TrojanMagic[3])
        {
            return ProtocolType::Trojan;
        }
        if (Data.size() >= 1 && Data[0] == VmessMagic)
        {
            return ProtocolType::Vmess;
        }
        // HTTP 方法前缀
        constexpr std::string_view methods[] = {"GET ", "POST ", "CONNECT ", "PUT ", "DELETE ", "HEAD "};
        for (const auto &m : methods)
        {
            if (Data.size() >= m.size() &&
                std::string_view(reinterpret_cast<const char *>(Data.data()), m.size()) == m)
            {
                return ProtocolType::Http;
            }
        }
        return ProtocolType::Unknown;
    }

} // namespace Preview::Recognition
