/**
 * @file DynamicTable.hpp
 * @brief QPACK 动态表能力声明
 * @details 当前 Preview 认证头只使用 RFC 9204 静态表。这个显式的
 *          空对象保留动态表的职责边界，避免把未支持的动态状态伪装
 *          成 Decoder/Encoder 的隐式全局状态。
 */

#pragma once

#include <cstddef>

namespace Preview::Http3::Qpack
{

    /**
     * @class DynamicTable
     * @brief 当前配置下的空动态表
     * @note 任何需要非零插入计数的块仍由 Decoder 拒绝。
     */
    class DynamicTable final
    {
    public:
        static constexpr bool Enabled = false;

        /**
         * @brief 获取插入计数
         * @return 永远为 0
         */
        [[nodiscard]] constexpr auto InsertCount() const noexcept -> std::size_t
        {
            return 0;
        }

        /**
         * @brief 清空动态表
         */
        constexpr auto Clear() noexcept -> void
        {
        }
    };

} // namespace Preview::Http3::Qpack
