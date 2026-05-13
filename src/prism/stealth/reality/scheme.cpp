/**
 * @file scheme.cpp
 * @brief Reality 伪装方案实现
 * @details Reality 是 Tier 0 方案，使用 session_id 标记作为独占特征。
 */

#include <prism/stealth/reality/scheme.hpp>
#include <prism/config.hpp>
#include <prism/stealth/reality/handshake.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/trace.hpp>

namespace psm::stealth::reality
{
    auto scheme::active(const psm::config &cfg) const noexcept -> bool
    {
        return cfg.stealth.reality.enabled();
    }

    auto scheme::snis(const psm::config &cfg) const
        -> memory::vector<memory::string>
    {
        memory::vector<memory::string> names;
        for (const auto &name : cfg.stealth.reality.server_names)
            names.push_back(memory::string(name));
        return names;
    }

    auto scheme::sniff(std::uint32_t bitmap,
                       const protocol::tls::client_hello_features &features) const
        -> sniff_result
    {
        using namespace protocol::tls;

        // Tier 0: Reality 独占标记检查（零成本字节比较）
        // session_id[0] == 0x01, session_id[1] == 0x08, session_id[2] == 0x02
        if (has_feature(bitmap, reality_marker_01_08_02))
        {
            trace::debug("[Reality] Sniff: exclusive marker [01:08:02] found");
            return {
                .hit = true,
                .solo = true,  // 独占！命中则跳过其他方案
                .hint = 950,
                .note = "Reality marker [01:08:02] detected"};
        }

        // 有 X25519 + session_id=32 → high confidence candidate
        // 不独占，可能被 ShadowTLS HMAC 验证后抢走
        if (has_all_features(bitmap, has_x25519 | has_full_session_id))
        {
            trace::debug("[Reality] Sniff: has X25519 + session_id=32, no marker");
            return {
                .hit = true,
                .solo = false,
                .hint = 450,
                .note = "Has X25519 + session_id=32"};
        }

        // 有 X25519 + session_id 非标准 → medium confidence
        // Reality 客户端可能使用非标准 session_id
        if (has_feature(bitmap, has_x25519) && has_feature(bitmap, session_id_non_standard))
        {
            trace::debug("[Reality] Sniff: has X25519 + non-standard session_id");
            return {
                .hit = true,
                .solo = false,
                .hint = 400,
                .note = "Has X25519 + non-standard session_id"};
        }

        // 有 X25519 但 session_id 标准长度（无标记）→ medium-low
        if (has_feature(bitmap, has_x25519))
        {
            trace::debug("[Reality] Sniff: has X25519 only");
            return {
                .hit = true,
                .solo = false,
                .hint = 200,
                .note = "Has X25519"};
        }

        // 无 X25519 但有 SNI + session_id=32 → low confidence
        // 需要 SNI 匹配（在 route_table 层检查）
        if (has_all_features(bitmap, has_sni | has_full_session_id))
        {
            trace::debug("[Reality] Sniff: has SNI + session_id=32, no X25519");
            return {
                .hit = true,
                .solo = false,
                .hint = 100,
                .note = "Has SNI + session_id=32"};
        }

        // 只有 SNI → low confidence (SNI 匹配已在上层检查)
        if (has_feature(bitmap, has_sni))
        {
            trace::debug("[Reality] Sniff: has SNI only");
            return {
                .hit = true,
                .solo = false,
                .hint = 100,
                .note = "Has SNI"};
        }

        return {.hit = false};
    }

    auto scheme::name() const noexcept -> std::string_view
    {
        return "reality";
    }

    auto scheme::handshake(stealth::handshake_context ctx)
        -> net::awaitable<stealth::handshake_result>
    {
        stealth::handshake_result result;

        if (!ctx.session)
        {
            result.error = fault::code::not_supported;
            co_return result;
        }

        const auto &cfg = ctx.session->server.config();

        auto hs = co_await stealth::reality::handshake(ctx.inbound, cfg, *ctx.session);

        switch (hs.type)
        {
        case stealth::reality::handshake_result_type::authenticated:
            result.transport = std::move(hs.encrypted_transport); // seal
            result.detected = protocol::protocol_type::vless;
            result.preread.assign(hs.inner_preread.begin(), hs.inner_preread.end());
            trace::debug("[Reality] Authenticated, dispatching to VLESS");
            break;

        case stealth::reality::handshake_result_type::not_reality:
            result.transport = std::move(ctx.inbound);
            result.preread.assign(hs.raw_tls_record.begin(), hs.raw_tls_record.end());
            result.detected = protocol::protocol_type::tls;
            trace::debug("[Reality] Not Reality, pass to next scheme");
            break;

        case stealth::reality::handshake_result_type::fallback:
            trace::debug("[RealityScheme] Fallback complete");
            break;

        case stealth::reality::handshake_result_type::failed:
            result.transport = std::move(ctx.inbound);
            if (hs.error == fault::code::reality_tls_record_error)
            {
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