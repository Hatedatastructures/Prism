/**
 * @file native.hpp
 * @brief 原生 TLS 伪装方案（兜底）
 * @details 封装标准 TLS 握手和内层协议检测，继承 stealth_scheme 基类。
 */
#pragma once

#include <prism/stealth/scheme.hpp>

namespace psm::stealth::schemes
{
    class native final : public stealth_scheme
    {
    public:
        [[nodiscard]] auto is_enabled(const psm::config &cfg) const noexcept
            -> bool override;
        [[nodiscard]] auto detect(const protocol::tls::client_hello_features &features, const psm::config &cfg) const
            -> detection_result override;
        [[nodiscard]] auto execute(scheme_context ctx)
            -> net::awaitable<scheme_result> override;
        [[nodiscard]] auto name() const noexcept
            -> std::string_view override;
    };
} // namespace psm::stealth::schemes
