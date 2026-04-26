/**
 * @file analyzer.hpp
 * @brief 协议分析器
 * @details 提供 detect() 和 detect_tls() 函数，用于协议特征检测。
 * 迁移自 protocol/analysis.hpp，职责下沉到 recognition 模块。
 */

#pragma once

#include <string_view>
#include <prism/protocol/analysis.hpp>

namespace psm::recognition::probe
{
    /**
     * @brief 外层协议探测
     * @param peek_data 预读数据（通常是前 24 字节）
     * @return 协议类型
     * @details 检测顺序：HTTP → SOCKS5 → TLS → Shadowsocks(fallback)
     */
    [[nodiscard]] auto detect(std::string_view peek_data) -> protocol::protocol_type;

    /**
     * @brief TLS 内层协议探测
     * @param peek_data TLS 握手后的数据（建议至少 60 字节）
     * @return 协议类型（HTTP/VLESS/Trojan/Shadowsocks）
     * @details 在 TLS 握手完成后探测内部承载的应用层协议
     */
    [[nodiscard]] auto detect_tls(std::string_view peek_data) -> protocol::protocol_type;
} // namespace psm::recognition::probe