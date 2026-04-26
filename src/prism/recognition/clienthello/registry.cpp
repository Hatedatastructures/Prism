/**
 * @file registry.cpp
 * @brief ClientHello 特征分析器注册表实现
 */

#include <prism/recognition/clienthello/registry.hpp>
#include <algorithm>

namespace psm::recognition::clienthello
{
    auto analyzer_registry::instance() -> analyzer_registry &
    {
        static analyzer_registry instance;
        return instance;
    }

    auto analyzer_registry::register_analyzer(shared_analyzer analyzer) -> void
    {
        std::lock_guard<std::mutex> lock(mutex_);
        analyzers_.push_back(std::move(analyzer));
    }

    auto analyzer_registry::analyze(
        const clienthello_features &features,
        const psm::config &cfg) const -> analysis_result
    {
        analysis_result result;
        result.features = features;

        // 收集所有启用的分析器的结果
        std::vector<std::pair<confidence, memory::string>> scored_candidates;

        for (const auto &analyzer : analyzers_)
        {
            if (!analyzer->is_enabled(cfg))
                continue;

            const auto conf = analyzer->analyze(features, cfg);
            if (conf != confidence::none)
            {
                scored_candidates.emplace_back(conf, memory::string(analyzer->name()));
            }
        }

        // 按置信度排序（high > medium > low）
        std::sort(scored_candidates.begin(), scored_candidates.end(),
                  [](const auto &a, const auto &b) {
                      // confidence 是枚举：high=0, medium=1, low=2, none=3
                      // 数值越小置信度越高
                      return static_cast<std::uint8_t>(a.first) < static_cast<std::uint8_t>(b.first);
                  });

        // 提取候选列表
        for (const auto &pair : scored_candidates)
        {
            result.candidates.push_back(std::move(pair.second));
        }

        // 设置整体置信度
        if (!scored_candidates.empty())
        {
            result.confidence = scored_candidates.front().first;
        }
        else
        {
            result.confidence = confidence::none;
        }

        return result;
    }

    auto analyzer_registry::get_enabled_analyzers(const psm::config &cfg) const
        -> std::vector<shared_analyzer>
    {
        std::vector<shared_analyzer> enabled;
        for (const auto &analyzer : analyzers_)
        {
            if (analyzer->is_enabled(cfg))
                enabled.push_back(analyzer);
        }
        return enabled;
    }

    auto analyzer_registry::get_all_analyzers() const -> const std::vector<shared_analyzer> &
    {
        return analyzers_;
    }
} // namespace psm::recognition::clienthello