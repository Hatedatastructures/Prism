/**
 * @file scheme.hpp
 * @brief ShadowTLS v3 伪装方案
 * @details 封装 ShadowTLS 握手和协议检测逻辑，继承 stealth_scheme 基类。
 */
#pragma once

#include <prism/stealth/scheme.hpp>
#include <prism/config.hpp>

namespace psm::stealth::shadowtls
{
    class scheme final : public stealth_scheme
    {
    public:
        [[nodiscard]] auto is_enabled(const psm::config &cfg) const noexcept -> bool override;
        [[nodiscard]] auto execute(scheme_context ctx) -> net::awaitable<scheme_result> override;
        [[nodiscard]] auto name() const noexcept -> std::string_view override;
    };
} // namespace psm::stealth::shadowtls
