/**
 * @file transparent.hpp
 * @brief 透明哈希与相等比较器
 * @details 提供支持异构查找的哈希函数和相等比较器，允许在
 * unordered_map 中使用 string_view、memory::string 和 lookup_key
 * 进行混合查找，无需构造临时键对象。采用 FNV-1a 算法实现高效哈希。
 */

#pragma once

#include <cstddef>
#include <string_view>

#include <forward-engine/memory/container.hpp>

namespace ngx::agent::distribution
{
    /**
     * @struct lookup_key
     * @brief 通用查找键结构体
     * @details 用于在哈希表中进行异构查找，避免构造完整的键字符串。
     * 包含主机名和端口的字符串视图，适用于 DNS 缓存和连接缓存场景。
     */
    struct lookup_key
    {
        std::string_view host;  // 主机名
        std::string_view port;  // 服务端口
    };

    /**
     * @struct transparent_hash
     * @brief 透明字符串哈希函数对象
     * @details 支持对 std::string_view、memory::string 和 lookup_key
     * 进行哈希计算，无需进行类型转换。采用 FNV-1a 算法实现高效哈希，
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

        [[nodiscard]] auto operator()(const lookup_key &value) const noexcept -> std::size_t
        {
            auto hash = seed;
            hash = append(hash, value.host);
            hash = append(hash, std::string_view{":", 1});
            return append(hash, value.port);
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
     * @details 支持对 std::string_view、memory::string 和 lookup_key
     * 进行混合比较，无需进行类型转换。通过 is_transparent 启用
     * 异构查找特性，允许在 unordered_map 中使用不同类型的键查找。
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

        [[nodiscard]] auto operator()(const memory::string &stored, const lookup_key &lookup) const noexcept -> bool
        {
            return matches(stored, lookup);
        }

        [[nodiscard]] auto operator()(const std::string_view stored, const lookup_key &lookup) const noexcept -> bool
        {
            return matches(stored, lookup);
        }

        [[nodiscard]] auto operator()(const lookup_key &lookup, const memory::string &stored) const noexcept -> bool
        {
            return matches(stored, lookup);
        }

        [[nodiscard]] auto operator()(const lookup_key &lookup, const std::string_view stored) const noexcept -> bool
        {
            return matches(stored, lookup);
        }

    private:
        /**
         * @brief 匹配存储键与查找键
         * @param stored 存储的键，格式为 "host:port"
         * @param lookup 查找键
         * @return 相等返回 true
         * @details 检查存储键是否符合 "host:port" 格式且与查找键匹配。
         */
        [[nodiscard]] static auto matches(const std::string_view stored, const lookup_key &lookup) noexcept -> bool
        {
            if (stored.size() != lookup.host.size() + lookup.port.size() + 1)
            {
                return false;
            }
            if (!stored.starts_with(lookup.host))
            {
                return false;
            }
            if (stored[lookup.host.size()] != ':')
            {
                return false;
            }
            return stored.substr(lookup.host.size() + 1) == lookup.port;
        }
    };
} // namespace ngx::agent::distribution
