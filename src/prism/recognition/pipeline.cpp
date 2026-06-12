#include <prism/recognition/pipeline.hpp>

#include <prism/stealth/registry.hpp>
#include <prism/trace.hpp>

#include <algorithm>

using namespace psm::trace;

namespace psm::recognition
{

    using hello_features = protocol::tls::hello_features;

    layered_detection_pipeline::layered_detection_pipeline(
        const std::vector<stealth::shared_scheme> &schemes)
    {
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

            if (scheme->name() == "native")
            {
                native_scheme_ = scheme;
            }
        }

        trace::debug("pipeline built: Tier0={}, Tier1={}, Tier2={}",
                     tier0_schemes_.size(), tier1_schemes_.size(), tier2_schemes_.size());
    }

    auto layered_detection_pipeline::detect(
        detect_input input,
        const std::vector<stealth::shared_scheme> &matched_schemes) const
        -> pipeline_result
    {
        // === 层级 0：零成本检测 ===
        auto tier0_result = detect_tier0(input.bitmap, input.features, input.cfg);
        if (tier0_result.deterministic_hit)
        {
            return tier0_result;
        }

        // === 层级 1：有成本检测 ===
        auto tier1_result = detect_tier1(input.features, input.raw, input.cfg);
        if (tier1_result.deterministic_hit)
        {
            return tier1_result;
        }

        // === 层级 2：模糊检测 ===
        return detect_tier2(input.cfg, matched_schemes);
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
                if (sniff_res.solo)
                {
                    result.deterministic_hit = true;
                    result.exclusive_scheme = memory::string(scheme->name());
                    result.reason = sniff_res.note;
                    return result;
                }

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
                if (verify_res.solo_flag != 0)
                {
                    result.deterministic_hit = true;
                    result.exclusive_scheme = memory::string(scheme->name());
                    result.reason = verify_res.note;
                    return result;
                }

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

        if (!matched_schemes.empty())
        {
            for (const auto &scheme : matched_schemes)
            {
                auto guess_res = scheme->guess(cfg);
                if (guess_res.score > 0)
                {
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
            if (native_scheme_ && native_scheme_->active(cfg))
            {
                trace::debug("no SNI match, using native fallback");
                result.candidates.push_back({
                    .name = memory::string(native_scheme_->name()),
                    .score = native_scheme_->guess(cfg).score,
                    .tier = 2,
                    .is_deterministic = false});
            }
        }

        std::ranges::sort(result.candidates, [](const auto &a, const auto &b)
                          { return a.score > b.score; });

        return result;
    }
} // namespace psm::recognition
