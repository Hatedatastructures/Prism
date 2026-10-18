/**
 * @file RouteTarget.hpp
 * @brief 管理 HTTP target 的借用解析视图和 typed route 值。
 * @details 解析期间借用 HttpRequest.Target；调用者必须在返回 BuildRoute 前完成值构造。
 */

#pragma once

#include <Prism/Operations/Models.hpp>
#include <Prism/Operations/Routes/RequestParser.hpp>

#include <array>
#include <cstddef>
#include <optional>
#include <string_view>
#include <variant>

namespace Prism::Operations::RouteDispatch
{

    struct QueryParameter final
    {
        std::string_view Name{};
        std::string_view Value{};
    };

    /** @brief 固定容量 target 视图；所有 string_view 借用同一请求缓冲区。 */
    struct TargetParts final
    {
        std::array<std::string_view, 10> Segments{};
        std::size_t SegmentCount{0};
        std::array<QueryParameter, 16> Parameters{};
        std::size_t ParameterCount{0};
    };

    struct RouteFailure final
    {
        int Status{400};
        std::string_view Message{"bad_request"};
    };

    struct OperationStatusRoute final
    {
        OperationId Operation{};
        Prism::RequestId Correlation{};
    };

    using RouteValue = std::variant<Query, Command, OperationStatusRoute>;

    /** @brief 在固定 query 容量内查找首个同名参数；返回值借用 Parts。 */
    [[nodiscard]] inline auto FindParameter(const TargetParts &Parts,
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
    [[nodiscard]] inline auto ParseTarget(const std::string_view Target,
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
    [[nodiscard]] inline auto ParseBoolean(const std::string_view Text, bool &Result) -> bool
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

    /** @brief 同一 target 的无分配数值读取器；引用只在同步 route 构造期间有效。 */
    class TargetParameterReader final
    {
    public:
        explicit TargetParameterReader(const TargetParts &Parts) : Parts_(Parts) {}

        template <typename Value>
        [[nodiscard]] auto Unsigned(const std::string_view Name,
                                    const Value Default,
                                    Value &Result) const -> bool
        {
            const auto Parameter = FindParameter(Parts_, Name);
            if (!Parameter)
            {
                Result = Default;
                return true;
            }
            return RequestParserDetail::ParseUnsigned(*Parameter, Result);
        }

        [[nodiscard]] auto Boolean(const std::string_view Name,
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

    private:
        const TargetParts &Parts_;
    };

} // namespace Prism::Operations::RouteDispatch
