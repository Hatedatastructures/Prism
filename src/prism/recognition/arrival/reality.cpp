/**
 * @file reality.cpp
 * @brief Reality 方案 feature 实现
 */

#include <prism/recognition/arrival/reality.hpp>
#include <prism/recognition/arrival/registry.hpp>
#include <prism/config.hpp>
#include <prism/trace.hpp>

namespace psm::recognition::arrival
{
    auto reality::analyze(const arrival_features &features, const config &cfg) const
        -> confidence
    {
        if (!check_sni_match(features.server_name, cfg.stealth.reality.server_names))
        {
            trace::debug("[Reality] SNI '{}' not matched", features.server_name);
            return confidence::none;
        }

        const bool has_full_session_id = features.session_id_len == 32;
        const bool has_x25519 = features.has_x25519_key_share;

        if (has_full_session_id && has_x25519)
        {
            trace::debug("[Reality] Full features: session_id=32, x25519=true");
            return confidence::high;
        }

        if (has_x25519)
        {
            trace::debug("[Reality] Partial features: x25519=true, session_id={}", features.session_id_len);
            return confidence::medium;
        }

        trace::debug("[Reality] SNI matched but no X25519 key_share");
        return confidence::low;
    }

    auto reality::is_enabled(const config &cfg) const noexcept -> bool
    {
        return cfg.stealth.reality.enabled();
    }

    auto reality::check_sni_match(const std::string_view sni, const memory::vector<memory::string> &server_names)
        -> bool
    {
        if (sni.empty() || server_names.empty())
            return false;

        for (const auto &name : server_names)
        {
            if (sni == std::string_view(name))
                return true;
        }

        return false;
    }
} // namespace psm::recognition::arrival

REGISTER_ARRIVAL(psm::recognition::arrival::reality)
