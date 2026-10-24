/** @file RouteTarget.cpp @brief 管理 HTTP target 路由解析实现。 */
#include <Prism/Operations/Routes/RouteTarget.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string_view>

namespace Prism::Operations::RouteDispatch
{

    /** @brief 在固定 query 容量内查找首个同名参数；返回值借用 Parts。 */
    [[nodiscard]] auto FindParameter(
        const TargetParts &Parts,
        const std::string_view Name)
        -> std::optional<std::string_view>
    {
        for (std::size_t Index = 0; Index < Parts.ParameterCount; ++Index)
        {
            if (Parts.Parameters[Index].Name == Name)
            {
                return Parts.Parameters[Index].Value;
            }
        }
        return std::nullopt;
    }

    /** @brief 解析完整 path/query；重复、空或超容量部分均返回 false。 */
    [[nodiscard]] auto ParseTarget(
        const std::string_view Target,
        TargetParts &Parts) -> bool
    {
        Parts = {};
        const auto QueryStart = Target.find('?');
        const auto Path = Target.substr(0, QueryStart);
        if (Path.empty() || Path.front() != '/')
        {
            return false;
        }

        std::size_t SegmentStart = 1;
        while (SegmentStart <= Path.size())
        {
            const auto SegmentEnd = Path.find('/', SegmentStart);
            auto End = Path.size();
            if (SegmentEnd != std::string_view::npos)
            {
                End = SegmentEnd;
            }
            if (End == SegmentStart || Parts.SegmentCount >= Parts.Segments.size())
            {
                return false;
            }
            Parts.Segments[Parts.SegmentCount++] = Path.substr(SegmentStart, End - SegmentStart);
            if (SegmentEnd == std::string_view::npos)
            {
                break;
            }
            SegmentStart = SegmentEnd + 1U;
        }

        if (QueryStart == std::string_view::npos)
        {
            return true;
        }
        const auto Query = Target.substr(QueryStart + 1U);
        if (Query.empty())
        {
            return false;
        }
        std::size_t ParameterStart = 0;
        while (ParameterStart <= Query.size())
        {
            const auto ParameterEnd = Query.find('&', ParameterStart);
            auto End = Query.size();
            if (ParameterEnd != std::string_view::npos)
            {
                End = ParameterEnd;
            }
            const auto Parameter = Query.substr(ParameterStart, End - ParameterStart);
            const auto Equal = Parameter.find('=');
            if (Equal == std::string_view::npos || Equal == 0U ||
                Parts.ParameterCount >= Parts.Parameters.size())
            {
                return false;
            }
            const auto Name = Parameter.substr(0, Equal);
            const auto Value = Parameter.substr(Equal + 1U);
            if (Value.empty() || FindParameter(Parts, Name))
            {
                return false;
            }
            Parts.Parameters[Parts.ParameterCount++] = QueryParameter{Name, Value};
            if (ParameterEnd == std::string_view::npos)
            {
                break;
            }
            ParameterStart = ParameterEnd + 1U;
        }
        return true;
    }

    /** @brief 解析 query boolean 的公开 wire 取值。 */
    [[nodiscard]] auto ParseBoolean(
        const std::string_view Text,
        bool &Result) -> bool
    {
        if (Text == "true" || Text == "1")
        {
            Result = true;
            return true;
        }
        if (Text == "false" || Text == "0")
        {
            Result = false;
            return true;
        }
        return false;
    }

    TargetParameterReader::TargetParameterReader(const TargetParts &Parts)
        : Parts_(Parts)
    {
    }

    auto TargetParameterReader::Boolean(
        const std::string_view Name,
        const bool Default,
        bool &Result) const -> bool
    {
        const auto Parameter = FindParameter(Parts_, Name);
        if (!Parameter)
        {
            Result = Default;
            return true;
        }
        return ParseBoolean(*Parameter, Result);
    }

    /** @brief 有界 cursor/limit 的 typed 查询解析；缺省值沿用 API 契约。 */
    [[nodiscard]] auto MakePage(const TargetParts &Parts, PageRequest &Page) -> bool
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
