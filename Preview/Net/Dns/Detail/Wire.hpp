/** @file Wire.hpp @brief DNS 大端数值字段的唯一有界读取原语。 */
#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace Preview::Network::Dns::Detail
{
    /** @brief 成功才推进游标；输入只同步借用，没有分配、异常或关闭资源。 */
    [[nodiscard]] inline auto GetU16(const std::span<const std::uint8_t> Data,
                                     std::size_t &Offset) noexcept -> std::optional<std::uint16_t>
    {
        if (Offset > Data.size() || Data.size() - Offset < 2) return std::nullopt;
        const auto Value = static_cast<std::uint16_t>((Data[Offset] << 8) | Data[Offset + 1]);
        Offset += 2;
        return Value;
    }

    /** @brief 大端读取四字节字段，失败不推进，也不把真实零值误当作缺失。 */
    [[nodiscard]] inline auto GetU32(const std::span<const std::uint8_t> Data,
                                     std::size_t &Offset) noexcept -> std::optional<std::uint32_t>
    {
        if (Offset > Data.size() || Data.size() - Offset < 4) return std::nullopt;
        const auto Value = (static_cast<std::uint32_t>(Data[Offset]) << 24) |
                           (static_cast<std::uint32_t>(Data[Offset + 1]) << 16) |
                           (static_cast<std::uint32_t>(Data[Offset + 2]) << 8) |
                           static_cast<std::uint32_t>(Data[Offset + 3]);
        Offset += 4;
        return Value;
    }
}
