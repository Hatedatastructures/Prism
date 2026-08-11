/**
 * @file types.hpp
 * @brief HTTP 代理协议基础类型（CONNECT 隧道）
 * @details 定义 HTTP CONNECT 隧道所需的常量与消息结构：
 *          - CONNECT 请求行 + Host 头
 *          - 响应状态行（200/403）
 *          - 增量行解析器（flat_buffer + CRLF 扫描）
 * @note 参考 RFC 7230 / RFC 7231。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace psmtest::http
{

    /// 代理成功状态码
    inline constexpr int status_ok = 200;

    /// CONNECT 请求行前缀
    inline constexpr std::string_view connect_method = "CONNECT";

    /// 响应 200 状态行
    inline constexpr std::string_view status_line_ok = "HTTP/1.1 200 Connection established\r\n\r\n";

    /// 响应 403 状态行
    inline constexpr std::string_view status_line_forbidden = "HTTP/1.1 403 Forbidden\r\n\r\n";

    /// 目标地址（host:port）
    struct address
    {
        /// 主机
        std::string host;
        /// 端口
        std::uint16_t port{0};
    };

} // namespace psmtest::http