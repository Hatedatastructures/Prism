/**
 * @file Qpack.hpp
 * @brief QPACK 静态表编解码与动态表能力入口。
 * @details 当前支持范围使用静态表；任何需要非零动态表插入计数的块仍由 Decoder 拒绝。
 */
#pragma once

#include <cstddef>

#include <Prism/Protocols/Http3/Decoder.hpp>
#include <Prism/Protocols/Http3/Encoder.hpp>

namespace Prism::Http3::Qpack
{
    /** @brief 当前配置下禁用的动态表能力。 */
    class DynamicTable final
    {
    public:
        static constexpr bool Enabled = false;

        [[nodiscard]] constexpr auto InsertCount() const noexcept -> std::size_t
        {
            return 0;
        }

        constexpr auto Clear() noexcept -> void
        {
        }
    };
}
