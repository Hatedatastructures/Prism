/**
 * @file scheme.hpp
 * @brief ECH 伪装方案（TLS 扩展层）
 */

#pragma once

#include <prism/handshake/ech/config.hpp>
#include <prism/handshake/scheme.hpp>

namespace psm::handshake::ech
{

    /**
     * @class scheme
     * @brief ECH 传输伪装方案
     * @details Tier 1：检测 ClientHello 是否携带 ECH 扩展（0xfe0d）。
     *          handshake：使用带 ECH 密钥的独立 SSL_CTX 完成 TLS 握手，
     *          BoringSSL 自动解密 inner ClientHello，返回加密传输层
     *          交由 executor 二次探测内层协议。
     */
    class scheme final : public psm::handshake::scheme
    {
    public:
        [[nodiscard]] auto name() const noexcept -> std::string_view override;

        [[nodiscard]] auto active(const psm::settings &cfg) const noexcept -> bool override;

        [[nodiscard]] auto tier() const noexcept -> std::uint8_t override
        {
            return 1;
        }

        [[nodiscard]] auto verify(const hello_features &features, std::span<const std::byte> raw,
                                  const psm::settings &cfg) const -> verify_result override;

        [[nodiscard]] auto handshake(handshake::handshake_context ctx)
            -> net::awaitable<handshake::handshake_result> override;
    };

} // namespace psm::handshake::ech
