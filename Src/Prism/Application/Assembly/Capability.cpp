/** @file Capability.cpp @brief 将应用运行与配置能力声明映射为 typed 集合。 */

#include <Prism/Application/Assembly/Capability.hpp>
#include <Prism/Application/Configuration/ConfigurationValidator.hpp>
#include <Prism/Application/Startup/Detail/Errors.hpp>
#include <Prism/Composition/Builtin/ProtocolBuiltins.hpp>

#include <expected>
#include <string>

namespace Prism::Application::Assembly
{

    auto ApplicationCapabilities() -> Prism::Composition::Builtin::CapabilitySet
    {
        auto Result = Prism::Composition::Builtin::ProtocolBuiltinCapabilities();
        Result.Add(Prism::Composition::Builtin::Capability::Observability);
        return Result;
    }

    auto RequiredCapabilities(
        const Prism::Application::Configuration::PrismConfiguration &ConfigurationValue)
        -> std::expected<Prism::Composition::Builtin::CapabilitySet,
            Prism::Application::StartupError>
    {
        Prism::Composition::Builtin::CapabilitySet Result;
        for (const auto &Name : ConfigurationValue.Runtime.RequiredCapabilities)
        {
            const auto CapabilityValue =
                Prism::Application::Configuration::ConfigurationValidator::CapabilityFromName(Name);
            if (!CapabilityValue)
            {
                return std::unexpected(Prism::Application::Startup::MakeStartupError(
                    Prism::Application::StartupErrorCode::InvalidConfiguration,
                    "Runtime.RequiredCapabilities",
                    "unknown Prism capability: " + Name));
            }
            Result.Add(*CapabilityValue);
        }
        return Result;
    }

} // namespace Prism::Application::Assembly
