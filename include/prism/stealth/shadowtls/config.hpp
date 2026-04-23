/**
 * @file config.hpp
 * @brief ShadowTLS v3 服务端配置
 * @details ShadowTLS v3 是一种 TLS 伪装协议，通过将代理流量包装成
 * 正常的 TLS 1.3 连接来对抗深度包检测。服务端在 TLS ClientHello
 * 的 SessionID 中验证客户端身份，认证成功后透传后续 TLS 流量。
 */
#pragma once

#include <string>
#include <vector>
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
        std::string name;     // 用户名称
        std::string password; // 认证密码
    };

    /**
     * @struct config
     * @brief ShadowTLS v3 服务端配置
     * @details 包含用户列表、握手目标和严格模式。
     * v3 版本必须配置至少一个用户，v2 兼容模式使用单一 password。
     */
    struct config
    {
        int version{3};                                  // 协议版本 (2 或 3)
        std::string password;                            // v2 兼容密码
        std::vector<user> users;                         // v3 多用户
        std::string handshake_dest;                      // 握手后端目标 host:port
        bool strict_mode{true};                          // 严格模式：仅 TLS 1.3
        std::uint32_t handshake_timeout_ms{5000};        // 握手超时（毫秒）
    }; // struct config
} // namespace psm::stealth::shadowtls
