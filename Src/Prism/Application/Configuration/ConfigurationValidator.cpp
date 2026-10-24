/** @file ConfigurationValidator.cpp @brief 调度内部校验流水线并返回 typed 结果。 */

#include <Prism/Application/Configuration/ConfigurationValidator.hpp>
#include <Prism/Application/Configuration/Validation/CapabilityValidation.hpp>
#include <Prism/Application/Configuration/Validation/ConfigurationValidation.hpp>

namespace Prism::Application::Configuration
{

    auto ConfigurationValidator::Validate(
        const PrismConfiguration &Configuration) -> Result
    {
        return Validate(ValidationRequest{
            Configuration,
            ValidationOptions{.CheckSecrets = true, .CheckCapabilities = true}});
    }

    auto ConfigurationValidator::Validate(ValidationRequest Request) -> Result
    {
        return Validation::ValidateConfiguration(Request);
    }

    auto ConfigurationValidator::CapabilityFromName(const std::string_view Name)
        -> std::optional<Prism::Composition::Builtin::Capability>
    {
        return Validation::CapabilityFromName(Name);
    }

} // namespace Prism::Application::Configuration
