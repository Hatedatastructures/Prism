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
     * 通过 is_transparent 启用异构查找特性。FNV-1a 使用 64 位种子
     * 和质数常数进行逐字节哈希运算。
     */
    struct transparent_hash
    {
        using is_transparent = void; // 启用异构查找标记

        /**
         * @brief 计算 string_view 的哈希值
         * @details 委托给内部 hash_view 函数进行 FNV-1a 哈希计算。
         * @param value 待哈希的字符串视图
         * @return 哈希值
         */
        [[nodiscard]] auto operator()(const std::string_view value) const noexcept -> std::size_t
        {
            return hash_view(value);
        }

        /**
         * @brief 计算 memory::string 的哈希值
         * @details 将 memory::string 转换为 string_view 后委托给 hash_view。
         * @param value 待哈希的 PMR 字符串
         * @return 哈希值
         */
        [[nodiscard]] auto operator()(const memory::string &value) const noexcept -> std::size_t
        {
            return hash_view(std::string_view(value));
        }

    private:
        static constexpr std::size_t seed = 14695981039346656037ull;
        static constexpr std::size_t prime = 1099511628211ull;

        /**
         * @brief 使用 FNV-1a 算法计算字符串视图的哈希值
         * @param value 待哈希的字符串视图
         * @return 哈希值
         */
        [[nodiscard]] static auto hash_view(const std::string_view value) noexcept -> std::size_t
        {
            return append(seed, value);
        }

        /**
         * @brief FNV-1a 哈希追加
         * @details 将字符串的每个字节逐个混入哈希值。
         * @param hash 初始哈希值
         * @param value 待追加的字符串视图
         * @return 更新后的哈希值
         */
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
     * 提供四种 operator() 重载覆盖所有类型组合。
     */
    struct transparent_equal
    {
        using is_transparent = void; // 启用异构查找标记

        /**
         * @brief 比较两个 string_view 是否相等
         * @param left 左操作数
         * @param right 右操作数
         * @return 相等返回 true，否则返回 false
         */
        [[nodiscard]] auto operator()(const std::string_view left, const std::string_view right) const noexcept -> bool
        {
            return left == right;
        }

        /**
         * @brief 比较 memory::string 和 string_view 是否相等
         * @param left PMR 字符串
         * @param right 字符串视图
         * @return 相等返回 true，否则返回 false
         */
        [[nodiscard]] auto operator()(const memory::string &left, const std::string_view right) const noexcept -> bool
        {
            return std::string_view(left) == right;
        }

        /**
         * @brief 比较 string_view 和 memory::string 是否相等
         * @param left 字符串视图
         * @param right PMR 字符串
         * @return 相等返回 true，否则返回 false
         */
        [[nodiscard]] auto operator()(const std::string_view left, const memory::string &right) const noexcept -> bool
        {
            return left == std::string_view(right);
        }

        /**
         * @brief 比较两个 memory::string 是否相等
         * @param left PMR 字符串
         * @param right PMR 字符串
         * @return 相等返回 true，否则返回 false
         */
        [[nodiscard]] auto operator()(const memory::string &left, const memory::string &right) const noexcept -> bool
        {
            return left == right;
        }
    };
} // namespace psm::resolve
