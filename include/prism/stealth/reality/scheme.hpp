/**
 * @file scheme.hpp
 * @brief Reality 伪装方案类
 * @details 封装 Reality TLS 握手和协议检测逻辑，继承 stealth_scheme 基类。
 */
#pragma once

#include <prism/stealth/scheme.hpp>
#include <prism/config.hpp>

namespace psm::stealth::reality
{
    class scheme final : public stealth_scheme
    {
    public:
        [[nodiscard]] auto is_enabled(const psm::config &cfg) const noexcept -> bool override;
        [[nodiscard]] auto execute(scheme_context ctx) -> net::awaitable<scheme_result> override;
        [[nodiscard]] auto name() const noexcept -> std::string_view override;
    };
} // namespace psm::stealth::reality
