/** @file OperationsPhase.cpp @brief 管理服务身份生成与启动实现。 */

#include <Prism/Application/OperationsStartup.hpp>
#include <Prism/Application/RuntimeState.hpp>
#include <Prism/Application/Startup/GenerationPhase.hpp>
#include <Prism/Application/Startup/StartupErrors.hpp>
#include <Prism/Operations/Controller.hpp>
#include <Prism/Operations/Web/Loader.hpp>
#include <Prism/Foundation/Utility/Crypto/Random.hpp>
#include <openssl/crypto.h>

#include <chrono>
#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <system_error>
#include <utility>

namespace Prism::Application::Startup::OperationsPhase
{

    [[nodiscard]] auto CreateIdentity(const Prism::ProcessId Process)
        -> std::expected<std::shared_ptr<const Prism::Operations::BootstrapIdentity>,
            Prism::Fault::Failure>
    {
        if (!Process)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        Prism::Operations::BootstrapIdentity::Incarnation Incarnation{};
        Prism::Operations::BootstrapIdentity::CommandToken Token{};
        if (const auto Randomized = Prism::Crypto::FillRandom(Incarnation); !Randomized)
        {
            return std::unexpected(Randomized.error());
        }
        if (const auto Randomized = Prism::Crypto::FillRandom(Token); !Randomized)
        {
            OPENSSL_cleanse(Incarnation.data(), Incarnation.size());
            return std::unexpected(Randomized.error());
        }
        Prism::Operations::BootstrapIdentity::Options Options;
        Options.Process = Process;
        Options.ProcessIncarnation = std::move(Incarnation);
        Options.Token = std::move(Token);
        return std::make_shared<const Prism::Operations::BootstrapIdentity>(
            std::move(Options));
    }

    /** @brief 在应用冷启动路径装配独立管理 io/thread，再注册进程信号。 */
    auto Start(const std::shared_ptr<Application::RuntimeState> &Runtime,
        const GenerationPhase::Result &Phase) -> std::expected<void, StartupError>
    {
        if (Phase.OperationsEndpoint)
        {
            if (!Runtime->Process)
            {
                return std::unexpected(Startup::MakeStartupError(
                    StartupErrorCode::Runtime, "Operations.Bootstrap",
                    "Operations process identity is unavailable"));
            }
            const auto Bootstrap = CreateIdentity(Runtime->Process->Id());
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
            Prism::Operations::Controller::Options Options;
            Options.BindEndpoint = *Phase.OperationsEndpoint;
            Options.Handlers = OperationsStartup::MakeOperationsHandlers(Runtime);
            Options.Bootstrap = *Bootstrap;
            std::error_code WebCatalogError;
            if (!Runtime->OperationsWebDirectory.empty() &&
                std::filesystem::is_regular_file(
                    Runtime->OperationsWebDirectory / "catalog.json", WebCatalogError))
            {
                const auto Resources = Prism::Operations::Web::LoadCatalog(
                    Runtime->OperationsWebDirectory);
                if (!Resources)
                {
                    return std::unexpected(Startup::MakeStartupError(
                        StartupErrorCode::Runtime, "Operations.Web",
                        "管理资源清单加载或完整性检查失败"));
                }
                Options.WebResources = *Resources;
            }
            Options.ReadDeadline = std::chrono::milliseconds(
                Runtime->Generation->Configuration().Operations.Timeout);
            Options.DrainTimeout = std::chrono::milliseconds(
                Runtime->Generation->Configuration().Shutdown.Timeout);
            auto ControllerOwner =
                std::make_shared<Prism::Operations::Controller>(std::move(Options));
            if (const auto Started = OperationsStartup::StartOperations(*ControllerOwner); !Started)
            {
                return std::unexpected(Started.error());
            }
            Runtime->ManagementController = std::move(ControllerOwner);
        }
        return OperationsStartup::ArmSignals(Runtime);
    }

} // namespace Prism::Application::Startup::OperationsPhase
