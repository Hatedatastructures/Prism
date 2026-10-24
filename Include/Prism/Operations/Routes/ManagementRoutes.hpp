/** @file ManagementRoutes.hpp @brief 新增管理查询的 typed HTTP target 解析。 */
#pragma once

#include <Prism/Operations/ManagementModels.hpp>
#include <Prism/Operations/Routes/RouteTarget.hpp>
#include <Prism/Statistics/Types.hpp>

#include <expected>
#include <optional>
#include <string_view>
#include <vector>

namespace Prism::Operations::RouteDispatch
{
    [[nodiscard]] auto IsAllowedManagementParameter(
        const TargetParts &Parts, const std::string_view Name) -> bool;

    [[nodiscard]] auto MakeManagementLimit(const TargetParts &Parts, PageRequest &Page) -> bool;

    /** @brief 普通集合消费位置游标；Trace 的多 worker 游标由专属解析器消费。 */
    [[nodiscard]] auto MakeManagementPage(const TargetParts &Parts, PageRequest &Page) -> bool;

    [[nodiscard]] auto ReadTraceCursors(
        const TargetParts &Parts, std::vector<TraceCursorSnapshot> &Cursors) -> bool;

    [[nodiscard]] auto ParseEventSeverity(const std::string_view Text)
        -> std::optional<Prism::Statistics::EventSeverity>;

    [[nodiscard]] auto MakeEventsRead(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>;

    [[nodiscard]] auto MakeTraceRead(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>;

    [[nodiscard]] auto MakeManagementCollectionRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>;

    [[nodiscard]] auto MakeManagementGetRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::optional<std::expected<RouteValue, RouteFailure>>;
}
