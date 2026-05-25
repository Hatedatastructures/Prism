#include <prism/recognition/pipeline.hpp>
#include <prism/stealth/registry.hpp>
#include <prism/trace.hpp>
#include <algorithm>

namespace psm::recognition
{
    using hello_features = protocol::tls::hello_features;

    layered_detection_pipeline::layered_detection_pipeline(
        const std::vector<stealth::shared_scheme> &schemes)
    {
        // 按层级分组方案
        for (const auto &scheme : schemes)
        {
            const auto t = scheme->tier();
            if (t == 0)
            {
                tier0_schemes_.push_back(scheme);
            }
            else if (t == 1)
            {
                tier1_schemes_.push_back(scheme);
            }
            else
            {
                tier2_schemes_.push_back(scheme);
            }

            // 记录 native 兜底方案
            if (scheme->name() == "native")
            {
                native_scheme_ = scheme;
            }
        }

        trace::debug("[LayeredPipeline] Built: Tier0={} schemes, Tier1={} schemes, Tier2={} schemes",
                     tier0_schemes_.size(), tier1_schemes_.size(), tier2_schemes_.size());
    }

    auto layered_detection_pipeline::detect(
        detect_input input,
        const std::vector<stealth::shared_scheme> &matched_schemes) const
        -> pipeline_result
    {
        trace::debug("[LayeredPipeline] Starting detection, SNI: {}", input.features.server_name);

        // === Tier 0: 零成本检测 ===
        auto tier0_result = detect_tier0(input.bitmap, input.features, input.cfg);
        if (tier0_result.deterministic_hit)
        {
            trace::debug("[LayeredPipeline] Tier 0 deterministic hit: {}",
                         tier0_result.exclusive_scheme);
            return tier0_result;
        }

        // === Tier 1: 有成本检测 ===
        auto tier1_result = detect_tier1(input.features, input.raw, input.cfg);
        if (tier1_result.deterministic_hit)
        {
            trace::debug("[LayeredPipeline] Tier 1 deterministic hit: {}",
                         tier1_result.exclusive_scheme);
            return tier1_result;
        }

        // === Tier 2: 模糊检测 ===
        auto tier2_result = detect_tier2(input.cfg, matched_schemes);
        trace::debug("[LayeredPipeline] Tier 2 fuzzy match: {} candidates",
                     tier2_result.candidates.size());

        return tier2_result;
    }

    auto layered_detection_pipeline::detect_tier0(
        std::uint32_t bitmap,
        const hello_features &features,
        const psm::config &cfg) const
        -> pipeline_result
    {
        pipeline_result result;

        for (const auto &scheme : tier0_schemes_)
        {
            if (!scheme->active(cfg))
                continue;

            auto sniff_res = scheme->sniff(bitmap, features);
            if (sniff_res.hit)
            {
                trace::debug("[LayeredPipeline] Tier 0: {} hit (solo={}, hint={})",
                             scheme->name(), sniff_res.solo, sniff_res.hint);

                // 独占命中：直接返回单一候选
                if (sniff_res.solo)
                {
                    result.deterministic_hit = true;
                    result.exclusive_scheme = memory::string(scheme->name());
                    result.reason = sniff_res.note;
                    return result;
                }

                // 非独占命中：添加到候选列表
                result.candidates.push_back({
                    .name = memory::string(scheme->name()),
                    .score = sniff_res.hint,
                    .tier = 0,
                    .is_deterministic = false});
            }
        }

        return result;
    }

    auto layered_detection_pipeline::detect_tier1(
        const hello_features &features,
        std::span<const std::byte> raw,
        const psm::config &cfg) const
        -> pipeline_result
    {
        pipeline_result result;

        for (const auto &scheme : tier1_schemes_)
        {
            if (!scheme->active(cfg))
                continue;

            auto verify_res = scheme->verify(features, raw, cfg);
            if (verify_res.score > 0)
            {
                trace::debug("[LayeredPipeline] Tier 1: {} score={} (solo={})",
                             scheme->name(), verify_res.score, verify_res.solo_flag);

                // 独占命中：直接返回单一候选
                if (verify_res.solo_flag != 0)
                {
                    result.deterministic_hit = true;
                    result.exclusive_scheme = memory::string(scheme->name());
                    result.reason = verify_res.note;
                    return result;
                }

                // 非独占命中：添加到候选列表
                result.candidates.push_back({
                    .name = memory::string(scheme->name()),
                    .score = verify_res.score,
                    .tier = 1,
                    .is_deterministic = false});
            }
        }

        return result;
    }

    auto layered_detection_pipeline::detect_tier2(
        const psm::config &cfg,
        const std::vector<stealth::shared_scheme> &matched_schemes) const
        -> pipeline_result
    {
        pipeline_result result;

        // 如果有 SNI 路由匹配的方案，只执行这些方案
        if (!matched_schemes.empty())
        {
            for (const auto &scheme : matched_schemes)
            {
                auto guess_res = scheme->guess(cfg);
                if (guess_res.score > 0)
                {
                    trace::debug("[LayeredPipeline] Tier 2 (matched): {} score={}",
                                 scheme->name(), guess_res.score);

                    result.candidates.push_back({
                        .name = memory::string(scheme->name()),
                        .score = guess_res.score,
                        .tier = 2,
                        .is_deterministic = false});
                }
            }
        }
        else
        {
            // 无 SNI 匹配：只使用 native 兜底方案
            // restls/shadowtls/anytls/trusttunnel 等方案会连接外部后端并向客户端
            // 写入 TLS 数据（pollute socket），导致后续方案无法正常工作。
            // native 是纯本地 TLS 握手，不连接外部后端，不会污染 socket。
            if (native_scheme_ && native_scheme_->active(cfg))
            {
                trace::debug("[LayeredPipeline] No SNI match, using native fallback only");
                result.candidates.push_back({
                    .name = memory::string(native_scheme_->name()),
                    .score = native_scheme_->guess(cfg).score,
                    .tier = 2,
                    .is_deterministic = false});
            }
        }

        // 按评分排序（高分在前）
        std::ranges::sort(result.candidates, [](const auto &a, const auto &b)
                          { return a.score > b.score; });

        return result;
    }
} // namespace psm::recognition
