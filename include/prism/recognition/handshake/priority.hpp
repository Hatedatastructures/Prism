/**
 * @file priority.hpp
 * @brief 方案执行优先级配置
 * @details 定义执行优先级模式和配置结构。
 */

#pragma once

#include <prism/memory/container.hpp>

namespace psm::recognition::handshake
{
    /**
     * @enum priority_mode
     * @brief 优先级模式
     * @details 决定方案执行的顺序策略。
     */
    enum class priority_mode : std::uint8_t
    {
        /** @brief 分析驱动：按 ClientHello 分析结果的置信度顺序执行 */
        analysis_driven,

        /** @brief 配置驱动：按用户配置的固定顺序执行 */
        config_driven,

        /** @brief 混合模式：分析优先 + 配置兜底（默认） */
        hybrid
    };

    /**
     * @struct execution_priority
     * @brief 方案执行优先级配置
     * @details 定义方案执行的顺序策略和备用顺序。
     */
    struct execution_priority
    {
        /** @brief 优先级模式 */
        priority_mode mode{priority_mode::hybrid};

        /** @brief 配置驱动的方案顺序（如 ["reality", "shadowtls", "native"]） */
        memory::vector<memory::string> order;

        /** @brief 是否跳过低置信度检测 */
        bool skip_low_confidence{false};

        /**
         * @brief 获取默认优先级配置
         * @return 默认配置（hybrid 模式，Reality 优先）
         */
        static auto default_order() -> execution_priority
        {
            return execution_priority{
                .mode = priority_mode::hybrid,
                .order = {"reality", "shadowtls", "restls", "native"},
                .skip_low_confidence = false};
        }
    };
} // namespace psm::recognition::handshake