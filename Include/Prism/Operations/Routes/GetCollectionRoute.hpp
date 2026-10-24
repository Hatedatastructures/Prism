/** @file GetCollectionRoute.hpp @brief Operations 顶层 GET 集合的 typed 路由解析。 */
#pragma once

#include <Prism/Operations/Routes/RouteTarget.hpp>

#include <expected>

namespace Prism::Operations::RouteDispatch
{
    [[nodiscard]] auto MakeGetCollectionRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>;


} // namespace Prism::Operations::RouteDispatch
