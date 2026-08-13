/**
 * @file config.hpp
 * @brief TUIC v5 QUIC 入站配置
 */

#pragma once

#include <prism/foundation/memory/container.hpp>

#include <cstdint>

namespace psm::handshake::tuic
{

    /**
     * @struct user
     * @brief TUIC 用户（uuid + password）
     * @details 与 mihomo 客户端 tuic 节点对应：uuid 为节点 uuid，
     *          password 用于派生认证 token（TLS exporter context）。
     */
    struct user
    {
        memory::string uuid;     ///< UUID（36 字符连字符格式）
        memory::string password; ///< 认证密码
    };

    /**
     * @struct config
     * @brief TUIC v5 入站配置
     * @details 启用后 QUIC 网关在监听端口提供 TUIC v5 协议。
     *          users 为认证用户表（uuid + password）。
     */
    struct config
    {
        bool enable{false};         ///< 是否启用
        memory::vector<user> users; ///< 认证用户表

        /**
         * @brief 是否启用
         * @return 是否启用
         */
        [[nodiscard]] auto enabled() const noexcept -> bool
        {
            return enable;
        }
    };

} // namespace psm::handshake::tuic
