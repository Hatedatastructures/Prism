/** @file Runtime.hpp @brief Application 内部 runtime startup 事务接口。 */
#pragma once

#include <Prism/Application/Startup/Detail/RuntimeState.hpp>
#include <Prism/Application/Startup/Detail/Generation.hpp>
#include <Prism/Application/Startup/Detail/Errors.hpp>

#include <expected>
#include <filesystem>
#include <memory>

namespace Prism::Application::Startup
{

    [[nodiscard]] auto RunStartup(
        const std::shared_ptr<Application::RuntimeState> &Runtime,
        const GenerationPhase::Result &Phase,
        const std::filesystem::path &ConfigurationPath)
        -> std::expected<void, StartupError>;

} // namespace Prism::Application::Startup
