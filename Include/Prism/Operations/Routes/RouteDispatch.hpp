/**
 * @file RouteDispatch.hpp
 * @brief Operations HTTP 请求的 typed 路由构造契约。
 * @details 此公共头只声明输入请求到路由值的映射；连接响应分派由 Operations 内部 owner 执行。
 */

#pragma once

#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Operations/HttpRequest.hpp>
#include <Prism/Operations/Models.hpp>
#include <Prism/Operations/Routes/RouteTarget.hpp>

#include <atomic>
#include <cstdint>
#include <expected>
#include <optional>
#include <string_view>

namespace Prism::Operations::RouteDispatch
{

    [[nodiscard]] auto ReadRequiredUnsigned(
        const TargetParts &Parts,
        const std::string_view Name,
        std::uint64_t &Result) -> bool;

    [[nodiscard]] auto ReadCorrelation(const HttpRequest &Request,
                                              const TargetParts &Parts,
                                              std::atomic<std::uint64_t> &NextCorrelation) -> std::optional<Prism::RequestId>;

    [[nodiscard]] auto MakeProcessGenerationRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>;

    [[nodiscard]] auto MakeStreamQueryRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>;

    [[nodiscard]] auto MakeStreamListQueryRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>;

    [[nodiscard]] auto MakeTaskQueryRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>;

    [[nodiscard]] auto MakeTaskListQueryRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>;

    [[nodiscard]] auto MakeOperationStatusRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>;

    [[nodiscard]] auto MakeGetRoute(const TargetParts &Parts,
                                           const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>;

    [[nodiscard]] auto MakeDrainRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>;

    [[nodiscard]] auto MakeReloadRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation,
        const std::string_view Body)
        -> std::expected<RouteValue, RouteFailure>;

    [[nodiscard]] auto MakeRevokeRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>;

    [[nodiscard]] auto MakeSessionCancelRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>;

    [[nodiscard]] auto MakeStreamResetRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>;

    [[nodiscard]] auto MakeTaskCancelRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>;

    [[nodiscard]] auto MakePostRoute(const TargetParts &Parts,
                                            const Prism::RequestId Correlation,
                                            const std::string_view Body)
        -> std::expected<RouteValue, RouteFailure>;

    [[nodiscard]] auto BuildRoute(const HttpRequest &Request,
                                         std::atomic<std::uint64_t> &NextCorrelation)
        -> std::expected<RouteValue, RouteFailure>;

} // namespace Prism::Operations::RouteDispatch
