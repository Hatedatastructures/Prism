/**
 * @file StaticTable.hpp
 * @brief HPACK 静态表实现的私有访问声明。
 */
#pragma once

#include <cstddef>
#include <string_view>
#include <utility>
#include <vector>

namespace Prism::Http2::Detail
{
    /** @brief 返回 RFC 7541 附录 A 的静态表。 */
    [[nodiscard]] auto StaticTable()
        -> const std::vector<std::pair<std::string_view, std::string_view>> &;

    /**
     * @brief 查静态表索引（Name 和 Value 完全匹配）。
     * @return 索引（1-61）；未命中返回 0。
     */
    [[nodiscard]] auto LookupStatic(std::string_view Name, std::string_view Value)
        -> std::size_t;

    /** @brief 查静态表中最小的同名索引；未命中返回 0。 */
    [[nodiscard]] auto LookupStaticName(std::string_view Name) -> std::size_t;
} // namespace Prism::Http2::Detail
