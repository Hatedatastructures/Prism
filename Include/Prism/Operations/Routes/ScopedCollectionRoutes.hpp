/** @file ScopedCollectionRoutes.hpp @brief Streams/Tasks 完整父作用域 collection route。 */
#pragma once

#include <Prism/Operations/QueryPage.hpp>
#include <Prism/Operations/Routes/RouteTarget.hpp>

#include <cstdint>
#include <expected>
#include <optional>
#include <string_view>
#include <utility>

namespace Prism::Operations::ScopedCollectionRoutes
{
    namespace Route = Prism::Operations::RouteDispatch;
    namespace Operations = Prism::Operations;

    struct ProcessSessionScope final
    {
        Prism::ProcessId Process{};
        Prism::SessionId Session{};
    };

    struct ProcessWorkerSessionScope final
    {
        Prism::ProcessId Process{};
        Prism::WorkerId Worker{};
        Prism::SessionId Session{};
    };

    [[nodiscard]] auto ReadRequired(
        const Route::TargetParts &Parts,
        const std::string_view Name,
        std::uint64_t &Value) -> bool;

    [[nodiscard]] auto ParseProcessSession(const Route::TargetParts &Parts)
        -> std::optional<ProcessSessionScope>;

    [[nodiscard]] auto ParseProcessWorkerSession(const Route::TargetParts &Parts)
        -> std::optional<ProcessWorkerSessionScope>;

    [[nodiscard]] auto MakeStreamQueryRoute(
        const Route::TargetParts &Parts,
        const Prism::RequestId Correlation,
        const Operations::PageRequest Page) -> std::expected<Route::RouteValue, Route::RouteFailure>;

    [[nodiscard]] auto MakeStreamListQueryRoute(
        const Route::TargetParts &Parts,
        const Prism::RequestId Correlation,
        const Operations::PageRequest Page) -> std::expected<Route::RouteValue, Route::RouteFailure>;

    [[nodiscard]] auto MakeTaskQueryRoute(
        const Route::TargetParts &Parts,
        const Prism::RequestId Correlation,
        const Operations::PageRequest Page) -> std::expected<Route::RouteValue, Route::RouteFailure>;

    [[nodiscard]] auto MakeTaskListQueryRoute(
        const Route::TargetParts &Parts,
        const Prism::RequestId Correlation,
        const Operations::PageRequest Page) -> std::expected<Route::RouteValue, Route::RouteFailure>;
}
