/**
 * @file byte_span.hpp
 * @brief 字节视图转换辅助（std::uint8_t ↔ std::byte）
 * @details transmission 接口统一使用 std::span<std::byte> 视图，
 * 而协议编解码层（codec）以 std::uint8_t 字节序为主。本头提供
 * 无开销的视图转换辅助，避免散落的 reinterpret_cast 强制转换。
 * @note 仅做指针重解释，不拷贝数据；调用方保证生命周期。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace psmtest
{

    /**
     * @brief 将 uint8_t 可写视图转换为 byte 可写视图
     * @param s uint8_t 视图
     * @return byte 视图（大小不变）
     */
    [[nodiscard]] inline auto as_bytes(std::span<std::uint8_t> s) noexcept -> std::span<std::byte>
    {
        return {reinterpret_cast<std::byte *>(s.data()), s.size()};
    }

    /**
     * @brief 将 uint8_t 只读视图转换为 byte 只读视图
     * @param s uint8_t 只读视图
     * @return byte 只读视图（大小不变）
     */
    [[nodiscard]] inline auto as_bytes(std::span<const std::uint8_t> s) noexcept
        -> std::span<const std::byte>
    {
        return {reinterpret_cast<const std::byte *>(s.data()), s.size()};
    }

    /**
     * @brief 将 byte 可写视图转换为 uint8_t 可写视图
     * @param s byte 视图
     * @return uint8_t 视图（大小不变）
     */
    [[nodiscard]] inline auto as_u8(std::span<std::byte> s) noexcept -> std::span<std::uint8_t>
    {
        return {reinterpret_cast<std::uint8_t *>(s.data()), s.size()};
    }

    /**
     * @brief 将 byte 只读视图转换为 uint8_t 只读视图
     * @param s byte 只读视图
     * @return uint8_t 只读视图（大小不变）
     */
    [[nodiscard]] inline auto as_u8(std::span<const std::byte> s) noexcept
        -> std::span<const std::uint8_t>
    {
        return {reinterpret_cast<const std::uint8_t *>(s.data()), s.size()};
    }

} // namespace psmtest
