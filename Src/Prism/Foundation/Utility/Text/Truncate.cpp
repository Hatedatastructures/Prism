/** @file Truncate.cpp
 * @brief 固定输出缓冲区的 UTF-8 截断收尾实现。
 */
#include <Prism/Foundation/Utility/Text/Truncate.hpp>

#include <cstring>
#include <string_view>

namespace Prism::Text
{
    auto FinishTruncatedUtf8(const std::span<char> Storage) noexcept -> std::size_t
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
