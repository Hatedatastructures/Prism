/**
 * @file CapabilityAssembly.hpp
 * @brief Prism 应用能力声明与配置要求装配。
 */
#pragma once

#include <Prism/Application/Application.hpp>
#include <Prism/Application/Configuration/Configuration.hpp>
#include <Prism/Application/Startup/StartupErrors.hpp>
#include <Prism/Composition/Builtin/ProtocolBuiltins.hpp>

#include <expected>

namespace Prism::Application::Assembly
{

    [[nodiscard]] inline auto ApplicationCapabilities()
        -> Prism::Composition::Builtin::CapabilitySet
    {
        auto Result = Prism::Composition::Builtin::ProtocolBuiltinCapabilities();
        Result.Add(Prism::Composition::Builtin::Capability::Observability);
        return Result;
    }

    [[nodiscard]] inline auto RequiredCapabilities(
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
