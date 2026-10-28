/** @file Capability.hpp @brief Prism 应用能力声明与配置要求装配接口。 */
#pragma once

#include <Prism/Application/Configuration/Configuration.hpp>
#include <Prism/Application/Definition.hpp>
#include <Prism/Composition/Builtin/Capability.hpp>

#include <expected>

namespace Prism::Application::Assembly
{

    [[nodiscard]] auto ApplicationCapabilities()
        -> Prism::Composition::Builtin::CapabilitySet;

    [[nodiscard]] auto RequiredCapabilities(
        const Prism::Application::Configuration::PrismConfiguration &ConfigurationValue)
        -> std::expected<Prism::Composition::Builtin::CapabilitySet,
            Prism::Application::StartupError>;

} // namespace Prism::Application::Assembly
