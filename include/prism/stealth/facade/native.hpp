/**
 * @file native.hpp
 * @brief 原生 TLS 伪装方案（兜底）
 * @details 封装标准 TLS 握手和内层协议检测，继承 stealth_scheme 基类。
 * Native 是 Tier 2 方案，作为兜底处理无法匹配其他方案的 TLS 连接。
 */
#pragma once

#include <prism/stealth/scheme.hpp>


namespace psm::stealth::native
{

    class native final : public stealth_scheme
    {
    public:
        // === 基本信息 ===
        [[nodiscard]] auto name() const noexcept
            -> std::string_view override;
        [[nodiscard]] auto tier() const noexcept
            -> std::uint8_t override { return 2; }
        [[nodiscard]] auto unique() const noexcept
            -> bool override { return false; }

        // === 配置检查 ===
        [[nodiscard]] auto active(const psm::config &cfg) const noexcept
            -> bool override;

        // === Tier 2: 模糊检测 ===
        [[nodiscard]] auto guess(const psm::config &cfg) const
            -> verify_result override;

        // === 执行 ===
        [[nodiscard]] auto handshake(stealth::handshake_context ctx)
            -> net::awaitable<stealth::handshake_result> override;

    protected:
        [[nodiscard]] auto weight() const noexcept
            -> std::uint16_t override { return 50; }
    };
} // namespace psm::stealth::native