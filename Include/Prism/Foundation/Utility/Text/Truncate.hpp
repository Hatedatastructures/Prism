/** @file Truncate.hpp
 * @brief 固定输出的统一 UTF-8 截断收尾与明确 marker。
 */
#pragma once
#include <cstddef>
#include <span>

namespace Prism::Text
{
    /** @brief 调用者已经确认截断时，以完整字符边界和 marker 收尾。 */
    [[nodiscard]] auto FinishTruncatedUtf8(std::span<char> Storage) noexcept -> std::size_t;
}
