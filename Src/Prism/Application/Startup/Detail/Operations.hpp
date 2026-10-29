/**
 * @file Operations.hpp
 * @brief Prism 应用内部管理服务启动阶段接口。
 */
#pragma once

#include <Prism/Application/Startup/Detail/RuntimeState.hpp>
#include <Prism/Application/Startup/Detail/Generation.hpp>
#include <Prism/Application/Startup/Detail/Errors.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Operations/Models.hpp>

#include <expected>
#include <memory>

namespace Prism::Application::Startup::OperationsPhase
{

    [[nodiscard]] auto CreateIdentity(const Prism::ProcessId Process)
        -> std::expected<std::shared_ptr<const Prism::Operations::BootstrapIdentity>,
            Prism::Fault::Failure>;

    [[nodiscard]] auto Start(const std::shared_ptr<Application::RuntimeState> &Runtime,
        const GenerationPhase::Result &Phase) -> std::expected<void, StartupError>;

} // namespace Prism::Application::Startup::OperationsPhase
