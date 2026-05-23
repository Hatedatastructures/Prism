/**
 * @file config.hpp
 * @brief ECH（Encrypted Client Hello）配置
 * @details ECH 是 TLS 扩展，加密 ClientHello 中的 SNI，防止 SNI 泄露。
 * 可以叠加在任意 TLS 伪装协议上（如 Reality、AnyTLS、TrustTunnel）。
 *
 * 协议参考: https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni
 */
#pragma once

#include <prism/memory/container.hpp>
#include <cstdint>

namespace psm::stealth::ech
{
    /**
     * @struct config
     * @brief ECH 服务端配置
     * @details ECH 是叠加层，可叠加在各 TLS 伪装协议上。
     * 服务端需要 ECH 密钥配置才能解密 ECH payload。
     */
    struct config
    {
        memory::string ech_key;         ///< ECH 密钥（base64 编码）
        memory::string public_name;     ///< 公开的伪装域名

        /**
         * @brief 检查是否启用
         * @return ech_key 非空时返回 true
         */
        [[nodiscard]] auto enabled() const noexcept
            -> bool
        {
            return !ech_key.empty();
        }
    };
} // namespace psm::stealth::ech