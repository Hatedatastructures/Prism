/**
 * @file CapabilityAssembly.hpp
 * @brief Preview 应用能力声明与配置要求装配。
 */
#pragma once

#include <Preview/Application/Application.hpp>
#include <Preview/Application/Configuration/Configuration.hpp>
#include <Preview/Application/Startup/StartupErrors.hpp>
#include <Preview/Composition/Builtin/ProtocolBuiltins.hpp>

#include <expected>

namespace Preview::Application::Assembly
{

    [[nodiscard]] inline auto ApplicationCapabilities()
        -> Preview::Composition::Builtin::CapabilitySet
    {
        auto Result = Preview::Composition::Builtin::ProtocolBuiltinCapabilities();
        Result.Add(Preview::Composition::Builtin::Capability::Observability);
        return Result;
    }

    [[nodiscard]] inline auto RequiredCapabilities(
        const Preview::Application::Configuration::PreviewConfiguration &ConfigurationValue)
        -> std::expected<Preview::Composition::Builtin::CapabilitySet,
                         Preview::Application::StartupError>
    {
        Preview::Composition::Builtin::CapabilitySet Result;
        for (const auto &Name : ConfigurationValue.Runtime.RequiredCapabilities)
        {
            const auto CapabilityValue =
                Preview::Application::Configuration::ConfigurationValidator::CapabilityFromName(Name);
            if (!CapabilityValue)
            {
                return std::unexpected(Preview::Application::Startup::MakeStartupError(
                    Preview::Application::StartupErrorCode::InvalidConfiguration,
                    "Runtime.RequiredCapabilities",
                    "unknown Preview capability: " + Name));
            }
            Result.Add(*CapabilityValue);
        }
        return Result;
    }

} // namespace Preview::Application::Assembly
