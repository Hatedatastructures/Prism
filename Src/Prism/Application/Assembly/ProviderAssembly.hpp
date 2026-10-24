/** @file ProviderAssembly.hpp @brief Application 到 Composition 的 provider 装配接口。 */
#pragma once

#include <Prism/Application/Startup/GenerationPhase.hpp>
#include <Prism/Application/Startup/StartupErrors.hpp>
#include <Prism/Composition/Provider/ProviderCatalog.hpp>

#include <expected>

namespace Prism::Application::Assembly
{

    [[nodiscard]] auto BuildProviderCatalog(
        Prism::Composition::Provider::ConfigurationInput Input,
        Prism::Composition::Provider::BindingServices Services)
        -> std::expected<Prism::Composition::Provider::BoundCatalog, StartupError>;

} // namespace Prism::Application::Assembly
