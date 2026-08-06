/**
 * @file scheme.hpp
 * @brief ShadowTLS v3 伪装方案
 * @details 封装 ShadowTLS 握手和协议检测逻辑，继承 scheme 基类。
 * ShadowTLS 是 Tier 1 方案，需要 HMAC 验证确认身份。
 */
#pragma once

#include <prism/settings/settings.hpp>
#include <prism/handshake/scheme.hpp>


namespace psm::handshake::shadowtls
{

    class scheme final : public handshake::scheme
    {
    public:
        // === 基本信息 ===
        [[nodiscard]] auto name() const noexcept
            -> std::string_view override;
        [[nodiscard]] auto tier() const noexcept
            -> std::uint8_t override { return 1; }
        [[nodiscard]] auto unique() const noexcept
            -> bool override { return false; }

        // === 配置检查 ===
        [[nodiscard]] auto active(const psm::settings &cfg) const noexcept
            -> bool override;
        [[nodiscard]] auto snis(const psm::settings &cfg) const
            -> memory::vector<memory::string> override;

        // === Tier 0: 快速检测 ===
        [[nodiscard]] auto sniff(std::uint32_t bitmap, const hello_features &features) const
            -> sniff_result override;

        // === Tier 1: 详细检测（HMAC 验证）===
        [[nodiscard]] auto verify(const hello_features &features, std::span<const std::byte> raw, const psm::settings &cfg) const
            -> verify_result override;

        // === 执行 ===
        [[nodiscard]] auto handshake(handshake::handshake_context ctx)
            -> net::awaitable<handshake::handshake_result> override;

    protected:
        [[nodiscard]] auto weight() const noexcept
            -> std::uint16_t override { return 100; }
    };
} // namespace psm::handshake::shadowtls