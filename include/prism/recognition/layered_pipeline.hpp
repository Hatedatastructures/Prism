/**
 * @file layered_pipeline.hpp
 * @brief 分层检测管道
 * @details 按成本和确定性分层执行检测，避免不必要的计算。
 * Tier 0: 零成本字节比较（如 Reality session_id 标记）
 * Tier 1: 有成本验证（如 ShadowTLS HMAC）
 * Tier 2: 模糊匹配（依赖 SNI 路由）
 */

#pragma once

#include <prism/memory/container.hpp>
#include <prism/protocol/tls/types.hpp>
#include <prism/recognition/tls/feature_bitmap.hpp>
#include <prism/stealth/scheme.hpp>
#include <cstdint>
#include <vector>

namespace psm
{
    struct config;
}

namespace psm::recognition
{
    using hello_features = protocol::tls::hello_features;
    // ═══════════════════════════════════════════════════════════════════════
    // 候选条目
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @struct candidate_entry
     * @brief 检测候选条目
     * @details 包含方案名称、评分、层级和确定性标记。
     */
    struct candidate_entry
    {
        /** @brief 方案名称 */
        memory::string name;

        /** @brief 评分（0-1000，越高越确定） */
        std::uint16_t score{0};

        /** @brief 检测层级 (0-2) */
        std::uint8_t tier{2};

        /** @brief 是否确定性命中（独占特征） */
        bool is_deterministic{false};
    };

    // ═══════════════════════════════════════════════════════════════════════
    // 管道检测结果
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @struct pipeline_result
     * @brief 分层检测管道结果
     * @details 包含确定性命中信息和候选列表。
     */
    struct pipeline_result
    {
        /** @brief 是否确定性命中（独占特征） */
        bool deterministic_hit{false};

        /** @brief 独占命中的方案名称 */
        memory::string exclusive_scheme;

        /** @brief 候选列表（按评分排序） */
        memory::vector<candidate_entry> candidates;

        /** @brief 检测原因（用于日志） */
        memory::string reason;
    };

    // ═══════════════════════════════════════════════════════════════════════
    // 分层检测管道
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @class layered_detection_pipeline
     * @brief 分层检测管道
     * @details 按成本分层执行检测：
     * - Tier 0: 零成本字节比较（如 Reality session_id 标记）
     * - Tier 1: 有成本验证（如 ShadowTLS HMAC）
     * - Tier 2: 模糊匹配（依赖 SNI 路由）
     *
     * **执行顺序**：
     * 1. 先执行 Tier 0，检查独占特征
     * 2. 如果独占命中，直接返回单一候选
     * 3. 否则执行 Tier 1，检查 HMAC 等有成本验证
     * 4. 如果确定性命中，返回单一候选
     * 5. 否则执行 Tier 2，返回多候选列表
     */
    class layered_detection_pipeline
    {
    public:
        /**
         * @brief 从 stealth 注册表构建管道
         * @param schemes 已注册的方案列表（std::vector 兼容 registry）
         */
        explicit layered_detection_pipeline(
            const std::vector<stealth::shared_scheme> &schemes);

        /**
         * @brief 执行分层检测
         * @param bitmap 特征位图
         * @param features ClientHello 特征结构
         * @param raw 原始 ClientHello 字节
         * @param cfg 全局配置
         * @param matched_schemes SNI 路由匹配的方案（可选）
         * @return 管道检测结果
         */
        [[nodiscard]] auto detect(
            std::uint32_t bitmap,
            const hello_features &features,
            std::span<const std::byte> raw,
            const psm::config &cfg,
            const std::vector<stealth::shared_scheme> &matched_schemes) const
            -> pipeline_result;

    private:
        /// Tier 0 方案列表（有独占特征）
        std::vector<stealth::shared_scheme> tier0_schemes_;

        /// Tier 1 方案列表（需要 HMAC/解密验证）
        std::vector<stealth::shared_scheme> tier1_schemes_;

        /// Tier 2 方案列表（模糊匹配）
        std::vector<stealth::shared_scheme> tier2_schemes_;

        /// Native 兜底方案
        stealth::shared_scheme native_scheme_;

        /**
         * @brief 执行 Tier 0 检测（零成本）
         */
        [[nodiscard]] auto detect_tier0(std::uint32_t bitmap, const hello_features &features, const psm::config &cfg) const
            -> pipeline_result;

        /**
         * @brief 执行 Tier 1 检测（有成本）
         */
        [[nodiscard]] auto detect_tier1(const hello_features &features, std::span<const std::byte> raw, const psm::config &cfg) const
            -> pipeline_result;

        /**
         * @brief 执行 Tier 2 检测（模糊）
         */
        [[nodiscard]] auto detect_tier2(const psm::config &cfg, const std::vector<stealth::shared_scheme> &matched_schemes) const
            -> pipeline_result;
    };
} // namespace psm::recognition