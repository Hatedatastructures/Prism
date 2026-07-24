#include <prism/resource/session.hpp>
#include <prism/stealth/facade/reality/scheme.hpp>

#include <prism/config/config.hpp>
#include <prism/stealth/recognition/tls/features.hpp>
#include <prism/stealth/facade/reality/handshake.hpp>
#include <prism/trace/trace.hpp>

using namespace psm::trace;

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
            trace::debug<flt::conn | flt::protocol>(prefix_, "Sniff: exclusive marker [01:08:02] found");
            return {
                .hit = true,
                .solo = true,  // 独占！命中则跳过其他方案
                .hint = 950,
                .note = "Reality marker [01:08:02] detected"};
        }

        // 有 X25519 + session_id=32 → 高置信度候选
        // 不独占，可能被 ShadowTLS HMAC 验证后抢走
        if (rec_tls::has_all(bitmap, rec_tls::feature_bit::has_x25519 | rec_tls::feature_bit::full_session))
        {
            trace::debug<flt::conn | flt::protocol>(prefix_, "Sniff: has X25519 + session_id=32, no marker");
            return {
                .hit = true,
                .solo = false,
                .hint = 450,
                .note = "Has X25519 + session_id=32"};
        }

        // 有 X25519 + session_id 非标准 → 中等置信度
        // Reality 客户端可能使用非标准 session_id
        const bool has_x25519 = rec_tls::has_feature(bitmap, rec_tls::feature_bit::has_x25519);
        const bool has_nonstd_session = rec_tls::has_feature(bitmap, rec_tls::feature_bit::nonstd_session);
        if (has_x25519 && has_nonstd_session)
        {
            trace::debug<flt::conn | flt::protocol>(prefix_, "Sniff: has X25519 + non-standard session_id");
            return {
                .hit = true,
                .solo = false,
                .hint = 400,
                .note = "Has X25519 + non-standard session_id"};
        }

        // 有 X25519 但 session_id 标准长度（无标记）→ 中低置信度
        if (rec_tls::has_feature(bitmap, rec_tls::feature_bit::has_x25519))
        {
            trace::debug<flt::conn | flt::protocol>(prefix_, "Sniff: has X25519 only");
            return {
                .hit = true,
                .solo = false,
                .hint = 200,
                .note = "Has X25519"};
        }

        // 无 X25519 但有 SNI + session_id=32 → 低置信度
        // 需要 SNI 匹配（在 route_table 层检查）
        if (rec_tls::has_all(bitmap, rec_tls::feature_bit::has_sni | rec_tls::feature_bit::full_session))
        {
            trace::debug<flt::conn | flt::protocol>(prefix_, "Sniff: has SNI + session_id=32, no X25519");
            return {
                .hit = true,
                .solo = false,
                .hint = 100,
                .note = "Has SNI + session_id=32"};
        }

        // 只有 SNI → 低置信度 (SNI 匹配已在上层检查)
        if (rec_tls::has_feature(bitmap, rec_tls::feature_bit::has_sni))
        {
            trace::debug<flt::conn | flt::protocol>(prefix_, "Sniff: has SNI only");
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

    auto scheme::handshake(stealth::stealth_opts ctx)
        -> net::awaitable<stealth::handshake_result>
    {
        stealth::handshake_result result;

        if (!ctx.session)
        {
            result.error = fault::code::not_supported;
            co_return result;
        }

        const auto &cfg = *ctx.session->worker->process->cfg;

        result = co_await stealth::reality::handshake(ctx.transport, cfg, *ctx.session, ctx.session->trace);

        co_return result;
    }


    auto scheme::challenge(stealth::stealth_opts /*ctx*/)
        -> net::awaitable<challenge_result>
    {
        // Reality 挑战的基础实现：标记 triggered=true 但 success=false
        // 后续完善：在 ServerHello 的 encrypted_extensions 中嵌入 GREASE 扩展,
        // 使用 steady_timer 等待客户端响应,verify_challenge 验证
        // 当前实现：让 executor 继续走 rewind/fallback 路径
        challenge_result res;
        res.triggered = true;
        res.success = false;
        res.error = fault::code::auth_failed;
        co_return res;
    }
} // namespace psm::stealth::reality