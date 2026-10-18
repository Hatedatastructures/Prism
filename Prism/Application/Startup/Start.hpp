/**
 * @file Start.hpp
 * @brief Prism 应用启动事务的阶段编排。
 */

#pragma once

#include <Prism/Application/Application.hpp>
#include <Prism/Application/BoundaryStartup.hpp>
#include <Prism/Application/ClosingFailure.hpp>
#include <Prism/Application/Account/PublishedPolicySource.hpp>
#include <Prism/Application/Startup/BoundaryPhase.hpp>
#include <Prism/Application/Startup/DatagramServices.hpp>
#include <Prism/Application/Startup/OperationsPhase.hpp>
#include <Prism/Application/Startup/ProcessServices.hpp>
#include <Prism/Application/Startup/ProtocolServices.hpp>
#include <Prism/Application/Startup/PublishPhase.hpp>
#include <Prism/Application/Startup/QuicServices.hpp>
#include <Prism/Application/Startup/StartupTransaction.hpp>

namespace Prism::Application
{
    namespace Assembly = Prism::Application::Assembly;

    /** @brief 在控制线程借用未发布 owner、generation 和配置来源，装配入口或返回 typed 错误。
     * @details 此复杂边界允许三个参数；回滚的最终关闭者仅为 StartupTransaction。
     */
    [[nodiscard]] auto StartupRuntime(const std::shared_ptr<Application::RuntimeState>& Runtime,
        const Startup::GenerationPhase::Result& Phase, const std::filesystem::path& ConfigurationPath)
        -> std::expected<void, StartupError>
    {
        Runtime->ConfigurationPath = ConfigurationPath;
        if (auto Result = Startup::ProcessServices::Build(Runtime, Phase); !Result)
            return Result;
        if (auto Result = Startup::ProtocolServices::Prepare(Runtime, ConfigurationPath); !Result)
            return Result;
        if (Phase.UdpEndpoint)
            Startup::DatagramServices::Build(Runtime, Phase);
        if (auto Result = Startup::ProtocolServices::Bind(Runtime, Phase); !Result)
            return Result;
        if (auto Result = Startup::BoundaryPhase::Start(Runtime, Phase); !Result)
            return Result;
        return Startup::OperationsPhase::Start(Runtime, Phase);
    }

    auto Application::Start() -> std::expected<Readiness, StartupError>
    {
        if (State_ && State_->Phase.load(std::memory_order_acquire) != RuntimePhase::Ready)
        {
            if (!LastError_)
                LastError_ = Startup::MakeStartupError(StartupErrorCode::Runtime, {},
                    "Prism application cannot restart after stop");
            return std::unexpected(*LastError_);
        }
        if (Readiness_)
            return *Readiness_;
        if (LastError_)
            return std::unexpected(*LastError_);
        try
        {
            const auto Phase = Startup::GenerationPhase::Build(Startup::GenerationPhase::Request{
                Options_.ConfigurationPath, std::move(Options_.SecretResolver)});
            if (!Phase)
            {
                LastError_ = Phase.error();
                return std::unexpected(*LastError_);
            }
            const auto& Config = Phase->Generation->Configuration();
            auto Runtime = std::make_shared<RuntimeState>(Config.Runtime.WorkerCount, Phase->Generation->Id(),
                Assembly::MakeDnsConfig(Config.Dns));
            const auto AdmissionAuthority = Phase->Accounts.Identities
                ? Phase->Accounts.Identities->RuntimeRegistry()->AttachAdmissionAuthority(
                    Runtime->GenerationPublisher)
                : std::expected<void, Prism::Fault::Failure>{
                    std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked})};
            if (!AdmissionAuthority)
            {
                LastError_ = Startup::MakeStartupError(StartupErrorCode::Runtime, "Accounts",
                    "账户准入authority未能绑定运行时publication");
                return std::unexpected(*LastError_);
            }
            ObserveClosingFailures(Runtime);
            Startup::StartupTransaction Transaction(Runtime);
            Runtime->Generation = Phase->Generation;
            Runtime->Accounts = Phase->Accounts;
            if (Runtime->Accounts.Identities)
                Runtime->Accounts.Identities->RuntimeRegistry()->AttachPolicySource(
                    std::make_shared<Prism::Application::PublishedPolicySource>(
                        Runtime->GenerationPublisher));
            Runtime->OperationsWebDirectory = Options_.OperationsWebDirectory;
            if (Config.Operations.WebDirectory)
            {
                const auto& ConfiguredDirectory = *Config.Operations.WebDirectory;
                Runtime->OperationsWebDirectory = ConfiguredDirectory.empty()
                    ? std::filesystem::path{}
                    : BoundaryStartup::ResolveConfigurationPath(
                        Options_.ConfigurationPath, ConfiguredDirectory);
            }
            const auto Started = StartupRuntime(Runtime, *Phase, Options_.ConfigurationPath);
            if (!Started)
            {
                LastError_ = Started.error();
                return std::unexpected(*LastError_);
            }
            auto& Output = Options_.Output ? *Options_.Output : std::cout;
            const auto Ready = Startup::PublishPhase::Publish(Runtime, Output);
            State_ = Transaction.Commit();
            Readiness_ = Ready;
            return *Readiness_;
        }
        catch (const std::exception& Error)
        {
            LastError_ = Startup::MakeStartupError(StartupErrorCode::Runtime, {},
                "Prism runtime construction failed: " + std::string(Error.what()));
        }
        catch (...)
        {
            LastError_ = Startup::MakeStartupError(StartupErrorCode::Runtime, {},
                "Prism runtime construction failed with an unknown exception");
        }
        return std::unexpected(*LastError_);
    }
} // namespace Prism::Application
