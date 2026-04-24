/**
 * @file scheme.cpp
 * @brief Reality 伪装方案实现
 */

#include <prism/stealth/reality/scheme.hpp>
#include <prism/config.hpp>
#include <prism/stealth/reality/handshake.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/trace.hpp>

namespace psm::stealth::reality
{
    auto scheme::is_enabled(const psm::config &cfg) const noexcept -> bool
    {
        return cfg.stealth.reality.enabled();
    }

    auto scheme::name() const noexcept -> std::string_view
    {
        return "reality";
    }

    auto scheme::execute(scheme_context ctx)
        -> net::awaitable<scheme_result>
    {
        scheme_result result;

        if (!ctx.session)
        {
            result.error = fault::code::not_supported;
            co_return result;
        }

        ctx.session->inbound = std::move(ctx.inbound);

        auto hs = co_await stealth::reality::handshake(*ctx.session);

        switch (hs.type)
        {
        case stealth::reality::handshake_result_type::authenticated:
            result.transport = std::move(hs.encrypted_transport); // seal
            result.detected = protocol::protocol_type::vless;
            result.preread.assign(hs.inner_preread.begin(), hs.inner_preread.end());
            trace::debug("[Reality] Authenticated, dispatching to VLESS");
            break;

        case stealth::reality::handshake_result_type::not_reality:
            result.transport = std::move(ctx.session->inbound);
            result.preread.assign(hs.raw_tls_record.begin(), hs.raw_tls_record.end());
            result.detected = protocol::protocol_type::tls;
            trace::debug("[Reality] Not Reality, pass to next scheme");
            break;

        case stealth::reality::handshake_result_type::fallback:
            trace::debug("[RealityScheme] Fallback complete");
            break;

        case stealth::reality::handshake_result_type::failed:
            result.transport = std::move(ctx.session->inbound);
            if (hs.error == fault::code::reality_tls_record_error)
            {
                result.detected = protocol::protocol_type::shadowsocks;
                trace::debug("[Reality] TLS record error, fallback to Shadowsocks");
                break;
            }
            result.error = hs.error;
            trace::warn("[Reality] Handshake failed: {}", fault::describe(hs.error));
            break;
        }

        co_return result;
    }
} // namespace psm::stealth::reality
