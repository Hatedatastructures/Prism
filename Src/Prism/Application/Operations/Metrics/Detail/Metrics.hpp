/** @file Metrics.hpp @brief Application 进程统计查询的内部接口。 */
#pragma once

#include <Prism/Application/Startup/Detail/RuntimeState.hpp>
#include <Prism/Operations/Metrics.hpp>
#include <Prism/Operations/Models.hpp>

#include <cstdint>
#include <memory>
#include <optional>

namespace Prism::Application::OperationsMetrics
{

    struct MetricsSupport final
    {
        std::uint64_t SampleIntervalMilliseconds{0};
    };

    [[nodiscard]] auto IsSupported(
        const std::shared_ptr<Application::RuntimeState> &State,
        const SharedRuntimeGenerationSnapshot &Snapshot) -> std::optional<MetricsSupport>;

    [[nodiscard]] auto Query(
        const std::shared_ptr<Application::RuntimeState> &State,
        const Prism::Operations::MetricsQuery &Request) -> Prism::Operations::QueryResult;

} // namespace Prism::Application::OperationsMetrics
