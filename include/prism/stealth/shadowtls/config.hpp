/**
 * @file config.hpp
 * @brief ShadowTLS v3 服务端配置
 * @details ShadowTLS v3 是一种 TLS 伪装协议，通过将代理流量包装成
 * 正常的 TLS 1.3 连接来对抗深度包检测。服务端在 TLS ClientHello
 * 的 SessionID 中验证客户端身份，认证成功后透传后续 TLS 流量。
 */
#pragma once

#include <prism/memory/container.hpp>
#include <cstdint>

namespace psm::stealth::shadowtls
{
    /**
     * @struct user
     * @brief ShadowTLS v3 用户配置
     * @details v3 支持多用户认证，每个用户有独立的名称和密码。
     */
    struct user
    {
        memory::string name;     ///< 用户名称
        memory::string password; ///< 认证密码
    };

    /**
     * @struct config
     * @brief ShadowTLS v3 服务端配置
     * @details 包含用户列表、握手目标、SNI 白名单和严格模式。
     * v3 版本必须配置至少一个用户，v2 兼容模式使用单一 password。
     * server_names 为 SNI 白名单，只有匹配的 ClientHello 才会执行认证。
     */
    struct config
    {
        std::int32_t version{3};                              ///< 协议版本 (2 或 3)
        memory::string password;                     ///< v2 兼容密码
        memory::vector<user> users;                  ///< v3 多用户
        memory::string handshake_dest;               ///< 握手后端目标 host:port
        memory::vector<memory::string> server_names; ///< SNI 白名单
        bool strict_mode{true};                      ///< 严格模式：仅 TLS 1.3
        std::uint32_t hs_timeout{5000};    ///< 握手超时（毫秒）

        /**
         * @brief 检查配置是否启用
         * @return 配置完整返回 true
         * @details v3 需要 users + handshake_dest + server_names
         *          v2 需要 password + handshake_dest + server_names
         */
        [[nodiscard]] auto enabled() const noexcept
            -> bool
        {
            if (version == 3)
                return !users.empty() && !handshake_dest.empty() && !server_names.empty();
            return !password.empty() && !handshake_dest.empty() && !server_names.empty();
        }
    };
} // namespace psm::stealth::shadowtls