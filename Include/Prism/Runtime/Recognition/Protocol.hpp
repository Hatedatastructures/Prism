/**
 * @file Protocol.hpp
 * @brief 协议类型枚举与首字节识别
 * @details 定义 Prism 统一协议类型（对照主项目 Connect::Prism::Contract::ProtocolType），
 *          提供首包字节检测（Probe 基础）：按特征字节映射到协议类型。
 */

#pragma once

#include <Prism/Contract/Ingress/Protocol.hpp>

#include <cstdint>
#include <span>

namespace Prism::Recognition
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
    [[nodiscard]] auto Detect(std::span<const std::uint8_t> Data) noexcept
        -> Prism::Contract::ProtocolType;

} // namespace Prism::Recognition
