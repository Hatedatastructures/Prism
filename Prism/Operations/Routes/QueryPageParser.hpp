/** @file QueryPageParser.hpp @brief 有界 Operations cursor/limit 的 typed 查询解析。 */
#pragma once

#include <Prism/Operations/Routes/RouteTarget.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>

namespace Prism::Operations::RouteDispatch
{
    [[nodiscard]] inline auto MakePage(const TargetParts &Parts, PageRequest &Page) -> bool
    {
        std::uint64_t Cursor{};
        std::uint64_t Limit{};
        if (!TargetParameterReader(Parts).Unsigned("cursor", std::uint64_t{0}, Cursor) ||
            !TargetParameterReader(Parts).Unsigned("limit", std::uint64_t{50}, Limit) ||
            Limit > std::numeric_limits<std::size_t>::max())
        {
            return false;
        }
        Page.Cursor = Cursor;
        Page.Limit = static_cast<std::size_t>(Limit);
        return true;
    }


} // namespace Prism::Operations::RouteDispatch