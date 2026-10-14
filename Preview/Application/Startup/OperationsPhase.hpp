/**
 * @file OperationsPhase.hpp
 * @brief Preview 启动阶段的独立管理控制器装配责任。
 */
#pragma once
#include <Preview/Application/Application.hpp>
#include <Preview/Application/OperationsBootstrap.hpp>
#include <Preview/Application/OperationsStartup.hpp>
#include <Preview/Application/RuntimeState.hpp>
#include <Preview/Application/Startup/GenerationPhase.hpp>
#include <Preview/Operations/Controller.hpp>
#include <Preview/Operations/Web/Loader.hpp>

#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <system_error>
#include <utility>

namespace Preview::Application::Startup::OperationsPhase
{

    /** @brief 在应用冷启动路径装配独立管理 io/thread，再注册进程信号。 */
    inline auto Start(const std::shared_ptr<Application::RuntimeState> &Runtime,
                      const GenerationPhase::Result &Phase)
        -> std::expected<void, StartupError>
    {
        if (Phase.OperationsEndpoint)
        {
            if (!Runtime->Process)
            {
                return std::unexpected(Startup::MakeStartupError(
                    StartupErrorCode::Runtime, "Operations.Bootstrap",
                    "Operations process identity is unavailable"));
            }
            const auto Bootstrap = OperationsBootstrap::CreateIdentity(Runtime->Process->Id());
            if (!Bootstrap)
            {
                auto Message = "Operations command credential generation failed with code " +
                    std::to_string(static_cast<unsigned>(Bootstrap.error().Code));
                if (Bootstrap.error().Native)
                {
                    Message.append(": ").append(Bootstrap.error().Native.message());
                }
                return std::unexpected(Startup::MakeStartupError(
                    StartupErrorCode::Runtime, "Operations.Bootstrap", std::move(Message)));
            }
            Preview::Operations::Controller::Options Options;
            Options.BindEndpoint = *Phase.OperationsEndpoint;
            Options.Handlers = OperationsStartup::MakeOperationsHandlers(Runtime);
            Options.Bootstrap = *Bootstrap;
            // 前端 bundle 可选；未生成 catalog 时仍启动管理 API。
            std::error_code WebCatalogError;
            if (!Runtime->OperationsWebDirectory.empty() &&
                std::filesystem::is_regular_file(
                    Runtime->OperationsWebDirectory / "catalog.json", WebCatalogError))
            {
                const auto Resources = Preview::Operations::Web::LoadCatalog(Runtime->OperationsWebDirectory);
                if (!Resources)
                    return std::unexpected(Startup::MakeStartupError(
                        StartupErrorCode::Runtime, "Operations.Web", "管理资源清单加载或完整性检查失败"));
                Options.WebResources = *Resources;
            }
            Options.ReadDeadline = std::chrono::milliseconds(
                Runtime->Generation->Configuration().Operations.Timeout);
            Options.DrainTimeout = std::chrono::milliseconds(
                Runtime->Generation->Configuration().Shutdown.Timeout);
            auto ControllerOwner =
                std::make_shared<Preview::Operations::Controller>(std::move(Options));
            if (const auto Started = OperationsStartup::StartOperations(*ControllerOwner); !Started)
            {
                return std::unexpected(Started.error());
            }
            Runtime->ManagementController = std::move(ControllerOwner);
        }
        return OperationsStartup::ArmSignals(Runtime);
    }

} // namespace Preview::Application::Startup::OperationsPhase
