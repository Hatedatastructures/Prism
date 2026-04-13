/**
 * @file config.hpp
 * @brief Reality 协议配置
 * @details 定义 Reality 协议的服务端配置结构体，包含目标伪装网站、
 * 允许的 SNI 列表、X25519 静态私钥和短 ID 列表。
 * Reality 配置与标准 TLS 证书配置互斥：启用 Reality 时不使用
 * 自身证书，而是使用目标网站的真实证书。
 */

#pragma once

#include <prism/memory/container.hpp>

namespace psm::protocol::reality
{
    /**
     * @struct config
     * @brief Reality 服务端配置
     * @details 配置 Reality 协议所需的所有参数。
     * - dest: 目标伪装网站，用于回退时的透明代理和证书获取
     * - server_names: 允许的 SNI 列表，只有匹配的 ClientHello 才会尝试认证
     * - private_key: 服务端 X25519 静态私钥（base64 编码）
     * - short_ids: 客户端 short ID 列表（hex 编码），空字符串表示接受任意
     */
    struct config
    {
        /// 目标伪装网站（host:port 格式），如 "www.microsoft.com:443"
        memory::string dest;

        /// 允许的 SNI 列表，如 ["www.microsoft.com", "www.apple.com"]
        memory::vector<memory::string> server_names;

        /// X25519 静态私钥（base64 编码，32 字节原始数据）
        memory::string private_key;

        /// 短 ID 列表（hex 编码，最长 16 字节）
        /// 空字符串 "" 表示接受任意 short ID
        memory::vector<memory::string> short_ids;

        /**
         * @brief 检查 Reality 是否已启用
         * @return 配置完整返回 true
         */
        [[nodiscard]] auto enabled() const noexcept -> bool
        {
            return !dest.empty() && !private_key.empty() && !server_names.empty();
        }
    };
} // namespace psm::protocol::reality
