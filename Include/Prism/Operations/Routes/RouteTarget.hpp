/**
 * @file RouteTarget.hpp
 * @brief 管理 HTTP target 的借用解析视图和 typed route 值。
 * @details 解析期间借用 HttpRequest.Target；调用者必须在返回 BuildRoute 前完成值构造。
 */
#pragma once

#include <Prism/Operations/Models.hpp>
#include <Prism/Operations/QueryPage.hpp>
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
    [[nodiscard]] auto FindParameter(
        const TargetParts &Parts,
        const std::string_view Name) -> std::optional<std::string_view>;

    /** @brief 解析完整 path/query；重复、空或超容量部分均返回 false。 */
    [[nodiscard]] auto ParseTarget(
        const std::string_view Target,
        TargetParts &Parts) -> bool;

    /** @brief 解析 query boolean 的公开 wire 取值。 */
    [[nodiscard]] auto ParseBoolean(
        const std::string_view Text,
        bool &Result) -> bool;

    /** @brief 同一 target 的无分配数值读取器；引用只在同步 route 构造期间有效。 */
    class TargetParameterReader final
    {
    public:
        explicit TargetParameterReader(const TargetParts &Parts);

        template <typename Value>
        [[nodiscard]] auto Unsigned(
            const std::string_view Name,
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

        [[nodiscard]] auto Boolean(
            const std::string_view Name,
            const bool Default,
            bool &Result) const -> bool;

    private:
        const TargetParts &Parts_;
    };

    /** @brief 有界 cursor/limit 的 typed 查询解析；缺省值沿用 API 契约。 */
    [[nodiscard]] auto MakePage(
        const TargetParts &Parts,
        PageRequest &Page) -> bool;
} // namespace Prism::Operations::RouteDispatch
