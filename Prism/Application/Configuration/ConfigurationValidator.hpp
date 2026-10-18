/**
 * @file ConfigurationValidator.hpp
 * @brief Prism 配置校验的稳定公共 facade。
 */
#pragma once

#include <Prism/Application/Configuration/Validation/CapabilityValidation.hpp>
#include <Prism/Application/Configuration/Validation/ConfigurationValidation.hpp>
#include <Prism/Application/Configuration/Validation/ValidationTypes.hpp>

#include <optional>
#include <string_view>

namespace Prism::Application::Configuration
{

    class ConfigurationValidator final
    {
    public:
        using Result = ValidationResult;

        [[nodiscard]] static auto Validate(const PrismConfiguration &Configuration) -> Result
        {
            return Validate(ValidationRequest{
                Configuration,
                ValidationOptions{.CheckSecrets = true, .CheckCapabilities = true}});
        }

        [[nodiscard]] static auto Validate(ValidationRequest Request) -> Result
        {
            return Validation::ValidateConfiguration(Request);
        }

        [[nodiscard]] static auto CapabilityFromName(const std::string_view Name)
            -> std::optional<Prism::Composition::Builtin::Capability>
        {
            return Validation::CapabilityFromName(Name);
        }
    };

} // namespace Prism::Application::Configuration
