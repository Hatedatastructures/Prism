/**
 * @file analyzer.hpp
 * @brief ClientHello 特征分析器虚基类
 * @details 定义 feature_analyzer 抽象基类，每个伪装方案可注册一个分析器，
 * 声明其 ClientHello 特征。分析器仅解析字节，不做任何网络 I/O，实现零成本预识别。
 */

#pragma once

#include <memory>
#include <string_view>
#include <prism/recognition/confidence.hpp>
#include <prism/recognition/feature.hpp>

// 前置声明
namespace psm
{
    struct config;
} // namespace psm

namespace psm::recognition::arrival
{
    /**
     * @class feature_analyzer
     * @brief ClientHello 特征分析器虚基类
     * @details 每个伪装方案可注册一个分析器，声明其 ClientHello 特征。
     * 分析器仅解析 ClientHello 字节特征，不做任何网络 I/O 操作，
     * 实现零成本预识别。返回置信度指导后续方案执行顺序。
     *
     * **设计原则**：
     * - 纯解析操作，无协程、无异步 I/O
     * - 快速判断，返回置信度而非执行结果
     * - 可复用已有 ClientHello 解析结果
     *
     * **使用示例**：
     * ```cpp
     * class reality_analyzer final : public feature_analyzer
     * {
     * public:
     *     auto name() const noexcept -> std::string_view override { return "reality"; }
     *     auto analyze(const arrival_features &f, const psm::config &cfg) const
     *         -> confidence override
     *     {
     *         // Reality 特征：SNI 匹配 + 32字节 session_id + X25519
     *         if (sni_matches(f.server_name, cfg) && f.session_id_len == 32 && f.has_x25519_key_share)
     *             return confidence::high;
     *         return confidence::none;
     *     }
     * };
     *
     * REGISTER_ARRIVAL_ANALYZER(reality_analyzer)
     * ```
     */
    class feature_analyzer
    {
    public:
        virtual ~feature_analyzer() = default;

        /**
         * @brief 分析器名称（对应伪装方案名称）
         * @return 方案名称字符串，如 "reality"、"ech"、"shadowtls"
         */
        [[nodiscard]] virtual auto name() const noexcept -> std::string_view = 0;

        /**
         * @brief 分析 ClientHello 特征
         * @param features 已提取的 ClientHello 特征
         * @param cfg 全局配置（用于 SNI 匹配等配置相关的判断）
         * @return 置信度判定
         * @details 根据特征判断该 ClientHello 是否可能属于此方案。
         * 返回 confidence::high 表示特征完全匹配，应优先执行此方案；
         * 返回 confidence::medium 表示部分匹配，需要完整验证；
         * 返回 confidence::low 表示可能有匹配，但不确定；
         * 返回 confidence::none 表示不匹配。
         */
        [[nodiscard]] virtual auto analyze(const arrival_features &features,const config &cfg) const -> confidence = 0;

        /**
         * @brief 分析器是否启用（对应方案是否配置）
         * @param cfg 全局配置
         * @return 如果对应方案在配置中启用，返回 true
         * @details 例如 reality_analyzer 应检查 cfg.stealth.reality.enabled()。
         */
        [[nodiscard]] virtual auto is_enabled(const config &cfg) const noexcept -> bool = 0;
    };

    using shared_analyzer = std::shared_ptr<feature_analyzer>;
} // namespace psm::recognition::arrival