#include <prism/stealth/reality/scheme.hpp>

#include <prism/config.hpp>
#include <prism/recognition/tls/features.hpp>
#include <prism/stealth/reality/handshake.hpp>
#include <prism/trace.hpp>

namespace psm::stealth::reality
{

    namespace rec_tls = psm::recognition::tls;
    using hello_features = protocol::tls::hello_features;

    auto scheme::active(const psm::config &cfg) const noexcept
        -> bool
    {
        return cfg.stealth.reality.enabled();
    }

    auto scheme::snis(const psm::config &cfg) const
        -> memory::vector<memory::string>
    {
        return make_sni_list(cfg.stealth.reality.server_names);
    }

    auto scheme::sniff(std::uint32_t bitmap,
                       const hello_features & /*features*/) const
        -> sniff_result
    {
        if (rec_tls::has_feature(bitmap, rec_tls::feature_bit::reality_marker))
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
        if (rec_tls::has_all(bitmap, rec_tls::feature_bit::has_x25519 | rec_tls::feature_bit::full_session))
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
        if (rec_tls::has_feature(bitmap, rec_tls::feature_bit::has_x25519) && rec_tls::has_feature(bitmap, rec_tls::feature_bit::nonstd_session))
        {
            trace::debug("[Reality] Sniff: has X25519 + non-standard session_id");
            return {
                .hit = true,
                .solo = false,
                .hint = 400,
                .note = "Has X25519 + non-standard session_id"};
        }

        // 有 X25519 但 session_id 标准长度（无标记）→ medium-low
        if (rec_tls::has_feature(bitmap, rec_tls::feature_bit::has_x25519))
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
        if (rec_tls::has_all(bitmap, rec_tls::feature_bit::has_sni | rec_tls::feature_bit::full_session))
        {
            trace::debug("[Reality] Sniff: has SNI + session_id=32, no X25519");
            return {
                .hit = true,
                .solo = false,
                .hint = 100,
                .note = "Has SNI + session_id=32"};
        }

        // 只有 SNI → low confidence (SNI 匹配已在上层检查)
        if (rec_tls::has_feature(bitmap, rec_tls::feature_bit::has_sni))
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

    auto scheme::name() const noexcept
        -> std::string_view
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

        const auto &cfg = ctx.session->server_ctx.config();

        result = co_await stealth::reality::handshake(ctx.inbound, cfg, *ctx.session);

        co_return result;
    }
} // namespace psm::stealth::reality