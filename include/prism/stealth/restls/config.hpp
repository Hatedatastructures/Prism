/**
 * @file config.hpp
 * @brief Restls 伪装方案配置
 * @details Restls 是一种 TLS 伪装协议，通过模拟真实 TLS 流量来隐藏代理特征。
 * 服务端通过 TLS 应用数据中的认证信息验证客户端身份。
 *
 * 协议参考: https://github.com/3andne/restls
 */
#pragma once

#include <prism/memory/container.hpp>
#include <cstdint>

namespace psm::stealth::restls
{
    /**
     * @struct config
     * @brief Restls 服务端配置
     * @details 包含 TLS 后端目标、认证密码、版本提示和流量控制脚本。
     *
     * **配置项说明**：
     * - `host`: TLS 后端目标服务器（必须是 TLS 1.2 或 TLS 1.3 服务器）
     * - `password`: 认证密码
     * - `version_hint`: 版本提示，"tls12" 或 "tls13"
     * - `restls_script`: 流量控制脚本，用于隐藏代理特征
     *
     * **Restls Script 语法**：
     * - `300?100`: 发送 300 字节，等待 100ms
     * - `400~100`: 等待 100ms 后发送 400 字节
     * - `<1`: 等待客户端数据
     */
    struct config
    {
        memory::string host;              ///< TLS 后端目标 host:port
        memory::string password;          ///< 认证密码
        memory::string version_hint;      ///< 版本提示: "tls12" 或 "tls13"
        memory::string restls_script;     ///< 流量控制脚本
        std::uint32_t handshake_timeout_ms{5000}; ///< 握手超时（毫秒）

        /**
         * @brief 检查配置是否有效
         * @return 如果 host 和 password 都非空，返回 true
         */
        [[nodiscard]] auto enabled() const noexcept -> bool
        {
            return !host.empty() && !password.empty();
        }
    }; // struct config
} // namespace psm::stealth::restls