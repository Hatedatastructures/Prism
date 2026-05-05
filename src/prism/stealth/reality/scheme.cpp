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

    auto scheme::detect(const protocol::tls::client_hello_features &features, const psm::config &cfg) const
        -> detection_result
    {
        const auto &server_names = cfg.stealth.reality.server_names;

        // SNI 匹配检查
        bool sni_matched = false;
        if (!features.server_name.empty() && !server_names.empty())
        {
            for (const auto &name : server_names)
            {
                if (features.server_name == std::string_view(name))
                {
                    sni_matched = true;
                    break;
                }
            }
        }

        if (!sni_matched)
        {
            trace::debug("[Reality] SNI '{}' not matched", features.server_name);
            return {.confidence = recognition::confidence::none,
                    .reason = "SNI not matched"};
        }

        const bool has_full_session_id = features.session_id_len == 32;
        const bool has_x25519 = features.has_x25519;

        if (has_full_session_id && has_x25519)
        {
            trace::debug("[Reality] Full features: session_id=32, x25519=true");
            return {.confidence = recognition::confidence::high,
                    .reason = "SNI matched + session_id=32 + X25519"};
        }

        if (has_x25519)
        {
            trace::debug("[Reality] Partial features: x25519=true, session_id={}", features.session_id_len);
            return {.confidence = recognition::confidence::medium,
                    .reason = "SNI matched + X25519"};
        }

        trace::debug("[Reality] SNI matched but no X25519 key_share");
        return {.confidence = recognition::confidence::low,
                .reason = "SNI matched but no X25519"};
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
                // 不假设为 Shadowsocks，继续传递给下一个 scheme
                result.detected = protocol::protocol_type::tls;
                result.preread.assign(hs.raw_tls_record.begin(), hs.raw_tls_record.end());
                trace::debug("[Reality] TLS record error, pass to next scheme");
                break;
            }
            result.error = hs.error;
            trace::warn("[Reality] Handshake failed: {}", fault::describe(hs.error));
            break;
        }

        co_return result;
    }
} // namespace psm::stealth::reality
