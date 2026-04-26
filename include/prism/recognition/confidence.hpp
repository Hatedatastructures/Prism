/**
 * @file confidence.hpp
 * @brief 检测置信度枚举定义
 * @details 定义 ClientHello 特征分析结果的置信度级别，用于指导方案执行顺序。
 */

#pragma once

#include <cstdint>

namespace psm::recognition
{
    /**
     * @enum confidence
     * @brief 检测置信度级别
     * @details 置信度越高，优先执行对应方案的可能性越大。
     */
    enum class confidence : std::uint8_t
    {
        /** @brief 高置信度：特征完全匹配，可直接执行对应方案 */
        high,
        /** @brief 中置信度：特征部分匹配，需完整验证 */
        medium,
        /** @brief 低置信度：特征部分匹配但不确定，需验证 */
        low,
        /** @brief 无特征：标准 TLS，执行 Native 兜底方案 */
        none
    };
} // namespace psm::recognition