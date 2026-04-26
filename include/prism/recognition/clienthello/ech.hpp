/**
 * @file ech.hpp
 * @brief ECH (Encrypted Client Hello) 特征分析器（预留）
 * @details ECH 在 ClientHello 中有特征（扩展类型 0xfe0d），
 * 可零成本识别。当前为预留接口，待后续实现。
 */

#pragma once

#include <prism/recognition/clienthello/analyzer.hpp>

namespace psm::recognition::clienthello
{
    /**
     * @class ech_analyzer
     * @brief ECH 方案特征分析器（预留）
     * @details ECH (Encrypted Client Hello) 特征：
     * - ClientHello 中存在 ECH 扩展（扩展类型 0xfe0d）
     * - 扩展数据包含加密的 ClientHello 内层
     *
     * **置信度判定**：
     * - high: 存在 ECH 扩展
     * - none: 不存在 ECH 扩展
     *
     * **实现状态**：预留接口，待后续完善
     */
    class ech_analyzer final : public feature_analyzer
    {
    public:
        [[nodiscard]] auto name() const noexcept -> std::string_view override
        {
            return "ech";
        }

        [[nodiscard]] auto analyze(
            const clienthello_features &features,
            const psm::config &cfg) const -> confidence override
        {
            // ECH 特征：has_ech_extension == true
            if (features.has_ech_extension)
            {
                return confidence::high;
            }
            return confidence::none;
        }

        [[nodiscard]] auto is_enabled(const psm::config &cfg) const noexcept -> bool override
        {
            // ECH 方案当前未实现，暂不启用
            // 未来实现后检查 cfg.stealth.ech.enabled()
            return false;
        }
    };
} // namespace psm::recognition::clienthello

// ECH 分析器暂不注册，待实现后启用
// REGISTER_CLIENTHELLO_ANALYZER(ech_analyzer)