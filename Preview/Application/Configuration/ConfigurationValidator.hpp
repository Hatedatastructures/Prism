/**
 * @file ConfigurationValidator.hpp
 * @brief Preview 配置校验的稳定公共 facade。
 */
#pragma once

#include <Preview/Application/Configuration/Validation/CapabilityValidation.hpp>
#include <Preview/Application/Configuration/Validation/ConfigurationValidation.hpp>
#include <Preview/Application/Configuration/Validation/ValidationTypes.hpp>

#include <optional>
#include <string_view>

namespace Preview::Application::Configuration
{

    class ConfigurationValidator final
    {
    public:
        using Result = ValidationResult;

        [[nodiscard]] static auto Validate(const PreviewConfiguration &Configuration) -> Result
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
            -> std::optional<Preview::Composition::Builtin::Capability>
        {
            return Validation::CapabilityFromName(Name);
        }
    };

} // namespace Preview::Application::Configuration
