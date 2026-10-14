/**
 * @file Protocol.hpp
 * @brief 协议类型枚举与首字节识别
 * @details 定义 Preview 统一协议类型（对照主项目 Connect::Preview::Contract::ProtocolType），
 *          提供首包字节检测（Probe 基础）：按特征字节映射到协议类型。
 */

#pragma once

#include <Preview/Contract/Ingress/Protocol.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <string_view>

namespace Preview::Recognition
{

    /**
     * @brief 按首包字节检测协议类型
     * @param Data 首包字节（≥1 字节）
     * @return 检测到的协议类型
     * @details 特征匹配：
     *          - 0x05 → socks5
     *          - 0x16 0x03 → tls
     *          - 结构化特征（version 0x00 + 合法 cmd/atyp，预读窗口内）→ vless
     *          - Trojan/VMess 首包交给已配置候选认证，不按假魔数猜测
     *          - "GET/POST/CONNECT " 前缀 → http
     *          - 其余 → unknown（ss2022 需 salt 分析，此处保守 unknown）
     */
    [[nodiscard]] inline auto Detect(std::span<const std::uint8_t> Data) noexcept
        -> Preview::Contract::ProtocolType
    {
        if (Data.empty())
        {
            return Preview::Contract::ProtocolType::Unknown;
        }
        switch (Data[0])
        {
        case 0x05:
            // SOCKS5 Greeting 至少包含版本和 NMETHODS；限定方法数量范围，
            // 避免随机 SS2022 salt 仅因首字节为 0x05 被误判。
            if (Data.size() < 2)
            {
                return Preview::Contract::ProtocolType::Unknown;
            }
            if (Data[1] >= 1 && Data[1] <= 16)
            {
                return Preview::Contract::ProtocolType::Socks5;
            }
            return Preview::Contract::ProtocolType::Unknown;
        case 0x16:
            if (Data.size() >= 2 && Data[1] == 0x03)
            {
                return Preview::Contract::ProtocolType::Tls;
            }
            return Preview::Contract::ProtocolType::Unknown;
        default:
            break;
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
                if ((Cmd == 0x01 || Cmd == 0x02) && (Atyp == 0x01 || Atyp == 0x02 || Atyp == 0x03))
                {
                    return Preview::Contract::ProtocolType::Vless;
                }
            }
        }
        // Trojan 首包以 SHA-224 凭据文本开始；没有配置密码时不能安全猜测。
        // VMess AuthID 首字节没有稳定魔数；任意 0x01 都可能是随机流量，
        // 不在无配置的 legacy 探测路径中误判，MixedTrial 由候选认证确认。
        // HTTP 方法前缀；保持与生产 analyzer 的方法集合一致。
        constexpr std::string_view Methods[] = {"GET ", "POST ", "CONNECT ", "PUT ", "DELETE ", "HEAD ",
            "OPTIONS ", "TRACE ", "PATCH "};
        for (const auto& Method : Methods)
        {
            if (Data.size() >= Method.size() &&
                std::string_view(reinterpret_cast<const char*>(Data.data()), Method.size()) == Method)
            {
                return Preview::Contract::ProtocolType::Http;
            }
        }
        return Preview::Contract::ProtocolType::Unknown;
    }

} // namespace Preview::Recognition
