/**
 * @file analyzer.hpp
 * @brief 外层协议检测
 * @details 通过魔术字节快速判断连接的外层协议类型（HTTP/SOCKS5/TLS/Shadowsocks）。
 * 该函数是纯内存操作，不涉及任何网络 I/O，可安全并发调用。
 * 检测采用排除法：匹配已知协议特征后直接返回，否则 fallback 到 Shadowsocks。
 * @note TLS 检测必须检查两字节（0x16 0x03），SS2022 salt 有约 1/256 概率
 * 首字节恰好为 0x16。
 * @warning 探测结果基于有限数据，后续数据可能推翻当前判断。
 */

#pragma once

#include <string_view>
#include <prism/protocol/analysis.hpp>

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
    [[nodiscard]] auto detect(std::string_view peek_data) -> protocol::protocol_type;

} // namespace psm::recognition::probe