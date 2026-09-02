/**
 * @file Types.hpp
 * @brief TrustTunnel 协议基础类型
 * @details TrustTunnel 是 HTTP/2 CONNECT 伪装方案（对齐 mihomo
 * transport/trusttunnel）：
 *          - 认证：Proxy-Authorization: Basic base64(user:pass)
 *          - 数据：HTTP/2 CONNECT 隧道（TCP）+ HTTP/2 数据帧（UDP）
 *          本测试库实现纯逻辑认证编解码（不含真实 HTTP/2 传输）。
 * @note 参考 TrustTunnel 协议规范。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace Preview::Trusttunnel
{

    /// Basic Auth 前缀
    inline constexpr std::string_view BasicPrefix = "Basic ";

    /// 最大帧载荷（16MB，防恶意声明）
    inline constexpr std::size_t MaxPayloadLen = 16 * 1024 * 1024;

} // namespace Preview::Trusttunnel
