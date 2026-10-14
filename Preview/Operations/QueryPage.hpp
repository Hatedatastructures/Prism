/**
 * @file QueryPage.hpp
 * @brief 管理面列表查询的统一有界游标值。
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace Preview::Operations
{

    struct PageRequest final
    {
        static constexpr std::size_t MaxLimit = 256;

        std::uint64_t Cursor{0};
        std::size_t Limit{50};

        [[nodiscard]] auto BoundedLimit() const noexcept -> std::size_t
        {
            return Limit > MaxLimit ? MaxLimit : Limit;
        }
    };

    template <typename Value>
    struct Page final
    {
        std::vector<Value> Items;
        std::uint64_t NextCursor{0};
        bool HasMore{false};
    };

} // namespace Preview::Operations
