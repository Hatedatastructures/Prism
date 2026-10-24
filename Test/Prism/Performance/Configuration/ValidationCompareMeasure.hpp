/**
 * @file ValidationCompareMeasure.hpp
 * @brief 配置校验对照工具的逐轮构图、解析和校验测量。
 */
#pragma once

#include "ValidationCompare.hpp"
#include "ValidationCompareAlloc.hpp"
#include "ValidationCompareCase.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace Prism::Application::Configuration::Perf::Measure
{

    struct RoundMeasurement final
    {
        std::size_t Round{0};
        std::size_t Nodes{0};
        std::uint64_t TraceHash{Scenario::FnvOffset};
        ScenarioKind Kind{ScenarioKind::Valid};
        Scenario::ExpectedError Expected{};
        std::uint64_t ConstructionNanoseconds{0};
        std::uint64_t ParserNanoseconds{0};
        std::uint64_t ValidatorNanoseconds{0};
        Allocation::Stats ConstructionAllocations{};
        Allocation::Stats ParserAllocations{};
        Allocation::Stats ValidatorAllocations{};
        std::optional<std::uint64_t> RssBefore;
        std::optional<std::uint64_t> RssAfter;
        Scenario::ErrorView ParserError{};
        Scenario::ErrorView ValidatorError{};
        bool CorrectnessInvalid{false};
        std::string InvalidReason{"none"};
    };

    struct RunPlan final
    {
        const Options &Settings;
        const Scenario::SnapshotPointer &Builtins;
        ScenarioKind Kind{ScenarioKind::Valid};
        const Scenario::Scenario *Input{nullptr};
    };

    struct RoundRequest final
    {
        const RunPlan &Plan;
        std::size_t Round{0};
    };

} // namespace Prism::Application::Configuration::Perf::Measure
