/**
 * @file config.hpp
 * @brief TrustTunnel 伪装方案配置
 * @details TrustTunnel 是一种支持 TCP 和 HTTP/3（QUIC）的 TLS 伪装协议。
 * 使用标准 TLS 证书，支持 BBR 拥塞控制。
 *
 * 协议参考: https://github.com/trusttunnel/trusttunnel
 */
#pragma once

#include <prism/memory/container.hpp>
#include <cstdint>

namespace psm::stealth::trusttunnel
{
    /**
     * @struct user
     * @brief TrustTunnel 用户配置
     */
    struct user
    {
        memory::string username;  ///< 用户名
        memory::string password;  ///< 密码
    };

    /**
     * @enum network_type
     * @brief 传输网络类型
     */
    enum class network_type : std::uint8_t
    {
        tcp,    ///< HTTP/2 (TCP)
        udp,    ///< HTTP/3 (QUIC)
        both    ///< 同时支持 TCP 和 UDP
    };

    /**
     * @enum congestion_controller
     * @brief 拥塞控制算法
     */
    enum class congestion_controller : std::uint8_t
    {
        cubic,
        bbr,
        new_reno
    };

    /**
     * @struct config
     * @brief TrustTunnel 服务端配置
     * @details 包含 TLS 证书、SNI 白名单、用户认证和网络配置。
     *
     * **配置项说明**：
     * - `server_names`: SNI 白名单，只有匹配的 ClientHello 才会执行认证
     * - `certificate`: TLS 证书文件路径（PEM 格式）
     * - `private_key`: TLS 私钥文件路径（PEM 格式）
     * - `users`: 用户认证列表
     * - `network`: 传输网络类型（TCP/UDP/both）
     * - `congestion`: 拥塞控制算法（cubic/bbr/new_reno）
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

        // === 网络配置 ===
        network_type network{network_type::both};              ///< 传输网络类型
        congestion_controller congestion{congestion_controller::bbr}; ///< 拥塞控制

        // === 超时配置 ===
        std::uint32_t handshake_timeout_ms{5000};  ///< 握手超时（毫秒）
        std::uint32_t idle_timeout_ms{30000};      ///< 空闲超时（毫秒）

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
} // namespace psm::stealth::trusttunnel