/**
 * @file transparent.hpp
 * @brief 透明哈希与相等比较器
 * @details 提供支持异构查找的哈希函数和相等比较器，允许在
 * unordered_map 中使用 string_view 和 memory::string 进行混合查找，
 * 无需构造临时键对象。采用 FNV-1a 算法实现高效哈希。
 */

#pragma once

#include <cstddef>
#include <string_view>

#include <prism/memory/container.hpp>

namespace psm::resolve
{
    /**
     * @struct transparent_hash
     * @brief 透明字符串哈希函数对象
     * @details 支持对 std::string_view 和 memory::string 进行哈希计算，
     * 无需进行类型转换。采用 FNV-1a 算法实现高效哈希，
     * 通过 is_transparent 启用异构查找特性。
     */
    struct transparent_hash
    {
        using is_transparent = void;

        [[nodiscard]] auto operator()(const std::string_view value) const noexcept -> std::size_t
        {
            return hash_view(value);
        }

        [[nodiscard]] auto operator()(const memory::string &value) const noexcept -> std::size_t
        {
            return hash_view(std::string_view(value));
        }

    private:
        static constexpr std::size_t seed = 14695981039346656037ull;
        static constexpr std::size_t prime = 1099511628211ull;

        [[nodiscard]] static auto hash_view(const std::string_view value) noexcept -> std::size_t
        {
            return append(seed, value);
        }

        [[nodiscard]] static auto append(std::size_t hash, const std::string_view value) noexcept -> std::size_t
        {
            for (const auto ch : value)
            {
                hash ^= static_cast<unsigned char>(ch);
                hash *= prime;
            }
            return hash;
        }
    };

    /**
     * @struct transparent_equal
     * @brief 透明字符串相等比较函数对象
     * @details 支持对 std::string_view 和 memory::string 进行混合比较，
     * 无需进行类型转换。通过 is_transparent 启用异构查找特性，
     * 允许在 unordered_map 中使用不同类型的键查找。
     */
    struct transparent_equal
    {
        using is_transparent = void;

        [[nodiscard]] auto operator()(const std::string_view left, const std::string_view right) const noexcept -> bool
        {
            return left == right;
        }

        [[nodiscard]] auto operator()(const memory::string &left, const std::string_view right) const noexcept -> bool
        {
            return std::string_view(left) == right;
        }

        [[nodiscard]] auto operator()(const std::string_view left, const memory::string &right) const noexcept -> bool
        {
            return left == std::string_view(right);
        }

        [[nodiscard]] auto operator()(const memory::string &left, const memory::string &right) const noexcept -> bool
        {
            return left == right;
        }
    };
} // namespace psm::resolve
