/**
 * @file registry.cpp
 * @brief 特征注册表实现
 * @details 注册发生于静态初始化阶段，分析发生于热路径只读遍历，无锁。
 */

#include <prism/recognition/arrival/registry.hpp>
#include <algorithm>
#include <ranges>

namespace psm::recognition::arrival
{
    auto registry::instance() -> registry &
    {
        static registry instance;
        return instance;
    }

    // 注册仅在静态初始化阶段，单线程，无需同步保护。
    auto registry::add(shared_feature f) -> void
    {
        features_.push_back(std::move(f));
    }

    // 遍历所有 feature，按置信度排序（值越小优先级越高）。
    auto registry::analyze(const arrival_features &arrival_features, const config &cfg) const
        -> analysis_result
    {
        analysis_result result;
        result.features = arrival_features;

        std::vector<std::pair<confidence, memory::string>> scored_candidates;

        for (const auto &feature_inst : features_)
        {
            if (!feature_inst->is_enabled(cfg))
                continue;

            const auto conf = feature_inst->analyze(arrival_features, cfg);
            if (conf != confidence::none)
                scored_candidates.emplace_back(conf, memory::string(feature_inst->name()));
        }

        auto compare = [](const auto &a, const auto &b)
        {
            return static_cast<std::uint8_t>(a.first) < static_cast<std::uint8_t>(b.first);
        };

        std::ranges::sort(scored_candidates, std::move(compare));

        for (const auto &val : scored_candidates | std::views::values)
            result.candidates.push_back(val);

        result.confidence = scored_candidates.empty() ? confidence::none : scored_candidates.front().first;

        return result;
    }

    auto registry::features() const -> const std::vector<shared_feature> &
    {
        return features_;
    }
} // namespace psm::recognition::arrival
