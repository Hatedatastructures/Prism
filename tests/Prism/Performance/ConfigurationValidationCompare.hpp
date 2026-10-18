/**
 * @file ConfigurationValidationCompare.hpp
 * @brief Preview 配置 Parser/Validator 基线对照入口。
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>

namespace Prism::Application::Configuration::Perf
{

    enum class ScenarioKind
    {
        Valid,
        CarrierRouteConflict,
        All
    };

    enum class VariantKind
    {
        A,
        B
    };

    struct Options final
    {
        std::size_t Nodes{64};
        std::size_t Rounds{5};
        std::uint64_t Seed{0xC11A5EEDULL};
        ScenarioKind Scenario{ScenarioKind::All};
        VariantKind Variant{VariantKind::A};
        std::filesystem::path InputPath{};
        std::filesystem::path EmitInputPath{};
        bool ValidateOnly{false};
    };

} // namespace Prism::Application::Configuration::Perf
