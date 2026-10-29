/** @file Start.cpp @brief Prism 应用启动事务与就绪发布实现。 */

#include <Prism/Application/Application.hpp>
#include <Prism/Application/Startup/Detail/BoundaryServices.hpp>
#include <Prism/Application/Shutdown/Detail/ClosingFailure.hpp>
#include <Prism/Application/Account/Detail/PublishedPolicySource.hpp>
#include <Prism/Application/Startup/Detail/RuntimeState.hpp>
#include <Prism/Application/Startup/Detail/Boundary.hpp>
#include <Prism/Application/Startup/Detail/Datagram.hpp>
#include <Prism/Application/Startup/Detail/Generation.hpp>
#include <Prism/Application/Startup/Detail/Operations.hpp>
#include <Prism/Application/Startup/Detail/Process.hpp>
#include <Prism/Application/Startup/Detail/Protocol.hpp>
#include <Prism/Application/Startup/Detail/Quic.hpp>
#include <Prism/Application/Startup/Detail/Errors.hpp>
#include <Prism/Application/Storage/Detail/Lifecycle.hpp>
#include <Prism/Application/Startup/Detail/Runtime.hpp>
#include <Prism/Application/Startup/Detail/Transaction.hpp>
#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>

#include <chrono>
#include <exception>
#include <iostream>
#include <memory>
#include <string>
#include <utility>

namespace Prism::Application
{

    namespace
    {

        namespace Assembly = Prism::Application::Assembly;

        /** @brief 在控制线程发布唯一启动结果并写入 READY 诊断。 */
        [[nodiscard]] auto PublishReadyState(
            const std::shared_ptr<Application::RuntimeState> &Runtime,
            std::ostream &Output) -> Readiness
        {
            const auto UdpHealth = Runtime->DatagramListener
                ? Runtime->DatagramListener->Health()
                : Prism::Boundary::DatagramListenerHealth{};
            const auto QuicHealth = Runtime->QuicPacketGateway
                ? Runtime->QuicPacketGateway->Health()
                : Prism::Boundary::QuicPacketGatewayHealth{};
            std::uint16_t OperationsPort = 0;
            if (Runtime->ManagementController)
            {
                OperationsPort = static_cast<std::uint16_t>(
                    Runtime->ManagementController->LocalEndpoint().port());
            }
            std::uint16_t UdpPort = 0;
            if (UdpHealth.Bound)
            {
                UdpPort = static_cast<std::uint16_t>(
                    Runtime->DatagramListener->LocalEndpoint().port());
            }
            Runtime->Ready = Readiness{Runtime->Listener->LocalEndpoint().port(),
                OperationsPort,
                Runtime->Generation->Id(),
                UdpPort,
                UdpHealth.Healthy(),
                !Runtime->Generation->Configuration().Listeners.Quic.empty() && QuicHealth.Healthy(),
                UdpHealth.Bound, QuicHealth.SocketReady, QuicHealth.HandshakeReady,
                QuicHealth.ProtocolReady};
            Runtime->Phase.store(RuntimePhase::Ready, std::memory_order_release);
            if (Runtime->Events)
            {
                Prism::Statistics::DetailedEvent Event;
                Event.Timestamp = static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count());
                Event.Generation = Runtime->Generation->Id();
                Event.Process = Runtime->Process->Id();
                Event.Kind = Prism::Statistics::EventKind::GenerationReloaded;
                Event.Severity = Prism::Statistics::EventSeverity::Info;
                Event.Detail = "application ready";
                (void)Runtime->Events->Append(std::move(Event));
            }
            (void)Prism::Diagnose::Debug(Runtime->RootContext, "RuntimeReady");
            Output << std::boolalpha
                   << "Prism READY tcp_port=" << Runtime->Ready.Port
                   << " udp_port=" << Runtime->Ready.UdpPort
                   << " udp_ready=" << Runtime->Ready.UdpReady
                   << " quic_ready=" << Runtime->Ready.QuicReady
                   << " generation=" << Runtime->Ready.Generation.Value()
                   << " quic_socket_ready=" << Runtime->Ready.QuicSocketReady
                   << " quic_handshake_ready=" << Runtime->Ready.QuicHandshakeReady
                   << " quic_protocol_ready=" << Runtime->Ready.QuicProtocolReady
                   << std::noboolalpha << '\n' << std::flush;
            return Runtime->Ready;
        }

    } // namespace

    namespace Startup
    {

        /** @brief 在控制线程装配未发布运行时；失败由启动事务排空并回收。 */
        auto RunStartup(const std::shared_ptr<Application::RuntimeState> &Runtime,
            const GenerationPhase::Result &Phase,
            const std::filesystem::path &ConfigurationPath)
            -> std::expected<void, StartupError>
        {
            Runtime->ConfigurationPath = ConfigurationPath;
            if (auto Result = ProcessServices::Build(Runtime, Phase); !Result)
            {
                return Result;
            }
            if (auto Result = ProtocolServices::Prepare(Runtime, ConfigurationPath); !Result)
            {
                return Result;
            }
            if (Phase.UdpEndpoint)
            {
                DatagramServices::Build(Runtime, Phase);
            }
            if (auto Result = ProtocolServices::Bind(Runtime, Phase); !Result)
            {
                return Result;
            }
            if (auto Result = BoundaryPhase::Start(Runtime, Phase); !Result)
            {
                return Result;
            }
            return OperationsPhase::Start(Runtime, Phase);
        }

    } // namespace Startup

    auto Application::Start() -> std::expected<Readiness, StartupError>
    {
        if (State_ && State_->Phase.load(std::memory_order_acquire) != RuntimePhase::Ready)
        {
            if (!LastError_)
            {
                LastError_ = Startup::MakeStartupError(StartupErrorCode::Runtime, {},
                    "Prism application cannot restart after stop");
            }
            return std::unexpected(*LastError_);
        }
        if (Readiness_)
        {
            return *Readiness_;
        }
        if (LastError_)
        {
            return std::unexpected(*LastError_);
        }
        try
        {
            const auto Phase = Startup::GenerationPhase::Build(Startup::GenerationPhase::Request{
                Options_.ConfigurationPath, std::move(Options_.SecretResolver)});
            if (!Phase)
            {
                LastError_ = Phase.error();
                return std::unexpected(*LastError_);
            }
            const auto &Config = Phase->Generation->Configuration();
            auto Runtime = std::make_shared<RuntimeState>(Config.Runtime.WorkerCount,
                Phase->Generation->Id(), Assembly::MakeDnsConfig(Config.Dns));
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
            {
                const auto Policies = Runtime->Accounts.Identities->RuntimeRegistry()->AttachPolicySource(
                    std::make_shared<Prism::Application::PublishedPolicySource>(
                        Runtime->GenerationPublisher));
                if (!Policies)
                {
                    LastError_ = Startup::MakeStartupError(
                        StartupErrorCode::Runtime, "Accounts", "account policy source could not be attached");
                    return std::unexpected(*LastError_);
                }
            }
            if (const auto Storage = StorageLifecycle::Open(Runtime, Options_.ConfigurationPath); !Storage)
            {
                LastError_ = Storage.error();
                return std::unexpected(*LastError_);
            }
            Runtime->OperationsWebDirectory = Options_.OperationsWebDirectory;
            if (Config.Operations.WebDirectory)
            {
                const auto &ConfiguredDirectory = *Config.Operations.WebDirectory;
                Runtime->OperationsWebDirectory = ConfiguredDirectory.empty()
                    ? std::filesystem::path{}
                    : BoundaryStartup::ResolveConfigurationPath(
                        Options_.ConfigurationPath, ConfiguredDirectory);
            }
            const auto Started = Startup::RunStartup(Runtime, *Phase, Options_.ConfigurationPath);
            if (!Started)
            {
                LastError_ = Started.error();
                return std::unexpected(*LastError_);
            }
            auto &Output = Options_.Output ? *Options_.Output : std::cout;
            const auto Ready = PublishReadyState(Runtime, Output);
            State_ = Transaction.Commit();
            Readiness_ = Ready;
            return *Readiness_;
        }
        catch (const std::exception &Error)
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
