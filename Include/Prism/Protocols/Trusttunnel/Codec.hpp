/**
 * @file Codec.hpp
 * @brief TrustTunnel 认证编解码（纯函数）
 * @details 对齐 mihomo transport/trusttunnel/Protocol.go 与
 * Prism TrustTunnel 认证编码契约：
 *          - BasicAuth：Basic base64(user:pass)
 *          - ParseBasicAuth：解析校验 "Basic <base64>"
 * @note 参考 TrustTunnel 协议规范。
 */

#pragma once

#include <string>
#include <string_view>

namespace Prism::Trusttunnel
{

    /// base64 编码表（标准，RFC 4648）
    inline constexpr char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /**
     * @brief 构造 Basic Auth 头值
     * @param Username 用户名
     * @param Password 密码
     * @return "Basic base64(user:pass)"
     */
    [[nodiscard]] auto BasicAuth(
        std::string_view Username,
        std::string_view Password) -> std::string;

    /**
     * @brief 解析校验 Basic Auth 头值
     * @param Authorization "Basic <base64>"
     * @param Username 输出用户名
     * @param Password 输出密码
     * @return true = 解析成功
     */
    [[nodiscard]] auto ParseBasicAuth(
        std::string_view Authorization,
        std::string &Username,
        std::string &Password) -> bool;

    /**
     * @brief 校验 Basic Auth（服务端侧）
     * @param Authorization 客户端头值
     * @param ExpectUser 期望用户名
     * @param ExpectPass 期望密码
     * @return true = 匹配
     */
    [[nodiscard]] auto VerifyBasicAuth(
        std::string_view Authorization,
        std::string_view ExpectUser,
        std::string_view ExpectPass) -> bool;

} // namespace Prism::Trusttunnel
