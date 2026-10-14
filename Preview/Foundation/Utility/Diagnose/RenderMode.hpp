/**
 * @file RenderMode.hpp
 * @brief Diagnose 输出模式。
 */
#pragma once

#include <cstdint>

namespace Preview::Diagnose
{

    /**
     * @brief 选择日志消息和上下文的输出格式。
     */
    enum class RenderMode : std::uint8_t
    {
        CompactHuman, ///< 上下文正文只包含固定身份前缀和消息；时间等元数据由 sink pattern 添加。
        HumanWithFields, ///< 上下文正文还包含可见字段；时间等元数据由 sink pattern 添加。
        Structured, ///< 输出包含时间、级别、身份、字段和消息的 JSON 行。
    };

} // namespace Preview::Diagnose
