/** @file QuicInitial.hpp @brief Boundary 默认 Initial 类型的长头前缀分类。 */
#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
namespace Preview::Boundary
{
    /**
     * @brief 检查长头、固定比特与默认 Initial 类型前缀。
     * @details 完整版本与 wire 合法性继续由真实 Native owner 校验。
     */
    [[nodiscard]] inline auto IsQuicInitialPacket(
        const std::span<const std::byte> Payload) noexcept -> bool
    {
        if (Payload.empty())
        {
            return false;
        }
        const auto Byte = std::to_integer<std::uint8_t>(Payload.front());
        return (Byte & 0xC0) == 0xC0 && ((Byte >> 4) & 3) == 0;
    }
}
