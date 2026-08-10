/**
 * @file config.hpp
 * @brief ECH（Encrypted Client Hello）配置
 * @details ECH 是 TLS 扩展，加密 ClientHello 中的 SNI，防止 SNI 泄露。
 *          可叠加在任意 TLS 伪装协议上（Reality、AnyTLS、TrustTunnel 等）。
 *          服务端需要 ECH 密钥配置才能解密 ECH payload。
 *          协议参考：draft-ietf-tls-esni
 */

#pragma once

#include <prism/foundation/memory/container.hpp>

#include <cstdint>

namespace psm::handshake::ech
{

    /**
     * @struct config
     * @brief ECH 服务端配置
     */
    struct config
    {
        memory::vector<memory::string> server_names; ///< SNI 白名单
        memory::string key;                          ///< X25519 私钥（base64，32 字节）
        memory::string public_name;                  ///< 公开伪装域名
        std::uint32_t max_name_len = 64;             ///< 匿名集合最大名称长度

        /**
         * @brief 检查是否启用
         * @return key 与 public_name 非空时返回 true
         */
        [[nodiscard]] auto enabled() const noexcept -> bool
        {
            return !key.empty() && !public_name.empty();
        }
    };

} // namespace psm::handshake::ech
