/**
 * @file config.hpp
 * @brief Hysteria2 QUIC 入站配置
 */

#pragma once

#include <prism/foundation/memory/container.hpp>

#include <cstdint>

namespace psm::handshake::hysteria2
{

    /**
     * @struct config
     * @brief Hysteria2 入站配置
     * @details 启用后 QUIC 网关在监听端口提供 Hysteria2 协议。
     *          users 为允许的密码列表（HTTP/3 认证 Hysteria-Auth 头匹配）。
     */
    struct config
    {
        bool enable{false}; ///< 是否启用
        memory::vector<memory::string> users; ///< 认证密码列表（与 mihomo 客户端 password 对应）

        /// 是否启用
        [[nodiscard]] auto enabled() const noexcept -> bool
        {
            return enable;
        }
    };

} // namespace psm::handshake::hysteria2
