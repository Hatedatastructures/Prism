/**
 * @file cast.hpp
 * @brief SS2022 字节类型转换工具
 * @details 提供 std::byte span 与 std::uint8_t span 之间的零开销
 * 类型转换，用于 SS2022 的 AEAD 加解密接口。所有函数均为
 * constexpr inline，编译期展开，无运行时开销。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>


namespace psm::protocol::shadowsocks::util
{

    /**
     * @brief byte 只读 span 转 uint8_t 只读 span
     * @param s 源 byte span
     * @return uint8_t span，指向相同内存区域
     * @note 零开销 reinterpret_cast，用于 AEAD 密文输入
     */
    [[nodiscard]] inline auto as_u8(const std::span<const std::byte> s) noexcept
        -> std::span<const std::uint8_t>
    {
        return {reinterpret_cast<const std::uint8_t *>(s.data()), s.size()};
    }
} // namespace psm::protocol::shadowsocks::util
