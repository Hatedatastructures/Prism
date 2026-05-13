/**
 * @file config.hpp
 * @brief AnyTLS 伪装方案配置
 * @details AnyTLS 是一种 TLS 伪装协议，使用标准 TLS 证书，
 * 通过应用层认证实现代理功能。可以叠加 ECH 加密 ClientHello SNI。
 *
 * 协议参考: https://github.com/anytls/anytls
 */
#pragma once

#include <prism/memory/container.hpp>
#include <cstdint>

namespace psm::stealth::anytls
{
    /**
     * @struct user
     * @brief AnyTLS 用户配置
     */
    struct user
    {
        memory::string username;  ///< 用户名
        memory::string password;  ///< 密码
    };

    /**
     * @struct config
     * @brief AnyTLS 服务端配置
     * @details 包含 TLS 证书、SNI 白名单、用户认证和可选的 ECH 配置。
     *
     * **配置项说明**：
     * - `server_names`: SNI 白名单，只有匹配的 ClientHello 才会执行认证
     * - `certificate`: TLS 证书文件路径（PEM 格式）
     * - `private_key`: TLS 私钥文件路径（PEM 格式）
     * - `users`: 用户认证列表
     * - `ech_key`: 可选的 ECH 密钥（base64 编码），用于叠加 ECH 加密
     * - `padding_scheme`: 可选的 padding 方案，用于隐藏流量特征
     */
    struct config
    {
        // === SNI 配置（必需）===
        memory::vector<memory::string> server_names;  ///< SNI 白名单

        // === TLS 证书（必需）===
        memory::string certificate;      ///< 证书文件路径（PEM）
        memory::string private_key;      ///< 私钥文件路径（PEM）

        // === 用户认证 ===
        memory::vector<user> users;      ///< 用户列表

        // === ECH 配置（可选）===
        memory::string ech_key;          ///< ECH 密钥（base64，可叠加）

        // === Padding 配置（可选）===
        memory::string padding_scheme;   ///< Padding 方案字符串

        // === 超时配置 ===
        std::uint32_t handshake_timeout_ms{5000};        ///< 握手超时（毫秒）
        std::uint32_t idle_session_timeout_ms{30000};    ///< 空闲会话超时（毫秒）

        /**
         * @brief 检查配置是否有效
         * @return 如果 server_names、certificate、private_key 和 users 都非空，返回 true
         */
        [[nodiscard]] auto enabled() const noexcept -> bool
        {
            return !server_names.empty()
                && !certificate.empty()
                && !private_key.empty()
                && !users.empty();
        }
    };
} // namespace psm::stealth::anytls

#include <glaze/glaze.hpp>

template <>
struct glz::meta<psm::stealth::anytls::user>
{
    using T = psm::stealth::anytls::user;
    static constexpr auto value = glz::object(
        "username", &T::username,
        "password", &T::password);
};

template <>
struct glz::meta<psm::stealth::anytls::config>
{
    using T = psm::stealth::anytls::config;
    static constexpr auto value = glz::object(
        "server_names",             &T::server_names,
        "certificate",              &T::certificate,
        "private_key",              &T::private_key,
        "users",                    &T::users,
        "ech_key",                  &T::ech_key,
        "padding_scheme",           &T::padding_scheme,
        "handshake_timeout_ms",     &T::handshake_timeout_ms,
        "idle_session_timeout_ms",  &T::idle_session_timeout_ms);
};