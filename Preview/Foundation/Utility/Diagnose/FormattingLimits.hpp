/** @file FormattingLimits.hpp
 * @brief 日志格式化的冷冻结资源政策；不缩小协议消息能力。
 */
#pragma once
#include <cstddef>
namespace Preview::Diagnose
{
    /** @brief 合法标准格式超出观察预算时明确拒绝，不静默忽略说明符。 */
    struct FormattingLimits final
    {
        std::size_t MaximumWidth{64U * 1024U}; ///< 每字段最大 width。
        std::size_t MaximumPrecision{4096U}; ///< 每字段最大 precision。
        std::size_t WorkBytes{256U * 1024U}; ///< 每记录解析、扫描、转义及输出的保守字节工作量额度。
        /** @brief 额度同时有绝对上限，保证乘法、浮点精度及格式化工作始终有界。 */
        [[nodiscard]] auto Valid() const noexcept -> bool
        {
            return MaximumWidth > 0U && MaximumWidth <= 64U * 1024U &&
                MaximumPrecision <= 4096U && WorkBytes > 0U && WorkBytes <= 1024U * 1024U;
        }
    };
}
