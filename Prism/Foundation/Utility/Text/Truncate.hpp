/** @file Truncate.hpp
 * @brief 固定输出的统一 UTF-8 截断收尾与明确 marker。
 */
#pragma once
#include <cstring>
#include <span>
#include <string_view>

namespace Prism::Text
{
    /** @brief 调用者已经确认截断时，以完整字符边界和 marker 收尾。 */
    [[nodiscard]] inline auto FinishTruncatedUtf8(const std::span<char> Storage) noexcept -> std::size_t
    {
        constexpr std::string_view Marker{"...[truncated]"};
        if (Storage.size() <= Marker.size())
        {
            if (!Storage.empty()) { std::memcpy(Storage.data(), Marker.data(), Storage.size()); }
            return Storage.size();
        }
        auto Prefix = Storage.size() - Marker.size();
        while (Prefix > 0U && (static_cast<unsigned char>(Storage[Prefix]) & 0xC0U) == 0x80U) { --Prefix; }
        std::memcpy(Storage.data() + Prefix, Marker.data(), Marker.size());
        return Prefix + Marker.size();
    }
}
