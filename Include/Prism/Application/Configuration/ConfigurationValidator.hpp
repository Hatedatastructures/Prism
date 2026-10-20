/**
 * @file ConfigurationValidator.hpp
 * @brief Prism 配置校验的稳定公共接口。
 */
#pragma once

#include <Prism/Application/Configuration/Validation/ValidationTypes.hpp>

#include <optional>
#include <string_view>

namespace Prism::Application::Configuration
{

    class ConfigurationValidator final
    {
    public:
        using Result = ValidationResult;

        [[nodiscard]] static auto Validate(
            const PrismConfiguration &Configuration) -> Result;

        [[nodiscard]] static auto Validate(ValidationRequest Request) -> Result;

        [[nodiscard]] static auto CapabilityFromName(std::string_view Name)
            -> std::optional<Prism::Composition::Builtin::Capability>;
    };

} // namespace Prism::Application::Configuration
