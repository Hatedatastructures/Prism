/**
 * @file BoundaryPhase.hpp
 * @brief Preview 启动阶段的独立资源装配责任。
 */
#pragma once
#include <Preview/Application/Application.hpp>
#include <Preview/Application/BoundaryStartup.hpp>
#include <Preview/Application/RuntimeState.hpp>
#include <Preview/Application/Shutdown.hpp>
#include <Preview/Application/Startup/GenerationPhase.hpp>
#include <Preview/Application/Startup/DatagramServices.hpp>
#include <Preview/Application/WorkerSessionServices.hpp>
#include <vector>
namespace Preview::Application::Startup::BoundaryPhase
{
    namespace Net = boost::asio;
    inline auto OnListenerFailure(const std::weak_ptr<Application::RuntimeState>& Owner) noexcept -> void
    {
        if (const auto State = Owner.lock())
        {
            Shutdown::MarkShutdownFailed(State);
            if (!State->StopRequested.exchange(true, std::memory_order_acq_rel))
                Shutdown::ScheduleShutdown(State);
        }
    }
    /** @brief 把启动已编译的配置、账户、协议和worker dial services冻结为唯一活动snapshot。 */
    [[nodiscard]] inline auto PublishInitialSnapshot(
        const std::shared_ptr<Application::RuntimeState>& Runtime,
        const GenerationPhase::Result& Phase)
        -> std::expected<void, StartupError>
    {
        if (Runtime->GenerationPublisher->Current())
        {
            return {};
        }
        if (!Runtime->Generation || !Runtime->Services)
        {
            return std::unexpected(Startup::MakeStartupError(
                StartupErrorCode::Runtime, "Generation", "initial runtime generation is incomplete"));
        }
        std::vector<std::shared_ptr<Preview::Network::Services::WorkerDialService>> WorkerDials;
        WorkerDials.reserve(Runtime->Process->Workers().Size());
        for (std::size_t Index = 0; Index < Runtime->Process->Workers().Size(); ++Index)
        {
            const auto WorkerId = Preview::WorkerId{static_cast<std::uint64_t>(Index + 1U)};
            const auto* Worker = Runtime->Process->Workers().Find(WorkerId);
            if (!Worker || !Worker->Resources().DialService)
            {
                return std::unexpected(Startup::MakeStartupError(
                    StartupErrorCode::Runtime, "Workers", "initial worker dial service is unavailable"));
            }
            WorkerDials.push_back(Worker->Resources().DialService);
        }
        auto Services = std::make_shared<Preview::Runtime::SessionServices>(*Runtime->Services);
        Services->Generation = Runtime->Generation;
        Services->GenerationUseState = Phase.UseState;
        const auto WorkerSessions = MakeWorkerSessionServices(
            WorkerSessionServicesPreparation{
                Services, &Runtime->Process->Workers(), WorkerDials});
        if (!WorkerSessions)
        {
            return std::unexpected(Startup::MakeStartupError(
                StartupErrorCode::Runtime, "Workers", "initial worker session services are incomplete"));
        }
        if (!Phase.UseState)
        {
            return std::unexpected(Startup::MakeStartupError(
                StartupErrorCode::Runtime, "Generation", "initial generation use state is unavailable"));
        }
        const auto DatagramSelection = DatagramServices::MakeIngressSelection(
            DatagramServices::IngressSelectionPreparation{
                Runtime->ProviderBindings, Runtime->Generation, Phase.UseState, {}});
        if (!DatagramSelection)
        {
            return std::unexpected(Startup::MakeStartupError(
                StartupErrorCode::Generation, DatagramSelection.error().Path,
                "initial raw/QUIC ingress binding is invalid"));
        }
        PreparedRuntimeGenerationServices PreparedServices;
        auto &ServiceGraph = PreparedServices.Graph();
        ServiceGraph.Session = std::move(Services);
        ServiceGraph.Providers = Runtime->ProviderBindings;
        ServiceGraph.Resolver = Runtime->DnsResolver;
        ServiceGraph.WorkerDials = std::move(WorkerDials);
        ServiceGraph.WorkerSessions = std::move(*WorkerSessions);
        ServiceGraph.UseState = Phase.UseState;
        ServiceGraph.DatagramSelection = *DatagramSelection;
        auto FrozenServices = std::move(PreparedServices).Freeze();
        if (!FrozenServices)
        {
            return std::unexpected(Startup::MakeStartupError(
                StartupErrorCode::Runtime, "Generation", "initial runtime services are incomplete"));
        }
        auto Candidate = std::make_shared<const RuntimeGenerationSnapshot>(
            Runtime->Generation, Runtime->Accounts, std::move(*FrozenServices));
        if (!Candidate->Accounts.Store || !Candidate->Accounts.IdentityPreparation)
        {
            return std::unexpected(Startup::MakeStartupError(
                StartupErrorCode::Runtime, "Accounts", "initial account identity preparation is missing"));
        }
        const auto IdentityStaged = Candidate->Accounts.IdentityPreparation->StageCommit();
        if (!IdentityStaged)
        {
            return std::unexpected(Startup::MakeStartupError(
                StartupErrorCode::Runtime, "Accounts", "initial account identities could not be staged"));
        }
        auto Prepared = Runtime->GenerationPublisher->Prepare(
            {}, Candidate, Candidate->Accounts.Store->AccountIds());
        if (!Prepared)
        {
            return std::unexpected(Startup::MakeStartupError(
                StartupErrorCode::Runtime, "Generation", "initial runtime snapshot publication failed"));
        }
        const auto Published = Runtime->GenerationPublisher->Publish(*Prepared);
        if (!Published)
        {
            return std::unexpected(Startup::MakeStartupError(
                StartupErrorCode::Runtime, "Generation", "initial runtime snapshot publication failed"));
        }
        const auto IdentityCommitted = Candidate->Accounts.IdentityPreparation->Commit();
        if (!IdentityCommitted)
        {
            return std::unexpected(Startup::MakeStartupError(
                StartupErrorCode::Runtime, "Accounts", "initial account identities did not commit"));
        }
        return {};
    }
    /** @brief 在 runtime/worker executor 启动监听；typed 失败交给事务，取消和最终关闭由 Shutdown 驱动。 */
    inline auto Start(const std::shared_ptr<Application::RuntimeState>& Runtime,
        const GenerationPhase::Result& Phase) -> std::expected<void, StartupError>
    {
        if (const auto Published = PublishInitialSnapshot(Runtime, Phase); !Published)
        {
            return std::unexpected(Published.error());
        }
        const auto WeakState = std::weak_ptr<Application::RuntimeState>(Runtime);
        Preview::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = Runtime->Io.get_executor();
        ListenerOptions.Factory = BoundaryStartup::MakeSessionFactory();
        ListenerOptions.WorkerCount = Runtime->Generation->Configuration().Runtime.WorkerCount;
        ListenerOptions.Workers = &Runtime->Process->Workers();
        ListenerOptions.Publication = Runtime->GenerationPublisher;
        ListenerOptions.OnFailure = [WeakState](const Preview::Fault::Code) noexcept
        { OnListenerFailure(WeakState); };
        Runtime->Listener = std::make_unique<Preview::Runtime::TcpListener>(std::move(ListenerOptions));
        Runtime->StartWorkers(Runtime->Generation->Configuration().Runtime.WorkerCount);

        if (const auto Started = BoundaryStartup::StartListener(Runtime, Phase.Endpoint); !Started)
        {
            return std::unexpected(Started.error());
        }
        if (Phase.UdpEndpoint)
        {
            if (const auto Started = BoundaryStartup::StartDatagramListener(Runtime, *Phase.UdpEndpoint);
                !Started)
            {
                return std::unexpected(Started.error());
            }
            Runtime->QuicPacketGateway->MarkSocketReady();
            Runtime->QuicPacketGateway->MarkReceiveLoopReady();
            const auto Active = Runtime->ActiveGenerationSnapshot();
            const auto Selection = Active ? Active->Services.DatagramSelection
                : std::shared_ptr<const Preview::Contract::DatagramIngressSelection>{};
            const auto Quic = Selection ? Selection->Quic()
                : std::shared_ptr<const Preview::Contract::QuicIngressBindingSnapshot>{};
            if (Quic && Quic->HasListener())
            {
                Runtime->QuicPacketGateway->MarkHandshakeReady();
                Runtime->QuicPacketGateway->MarkProtocolReady();
            }
        }
        return {};
    }
} // namespace Preview::Application::Startup::BoundaryPhase
