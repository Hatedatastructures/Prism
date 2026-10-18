/**
 * @file ReloadGenerationPreparation.hpp
 * @brief Reload 候选账户与完整 generation 服务图的 prepare owner。
 */
#pragma once

#include <Prism/Account/Store.hpp>
#include <Prism/Application/Assembly/AccountAssembly.hpp>
#include <Prism/Application/Assembly/DnsAssembly.hpp>
#include <Prism/Application/Assembly/NetworkAssembly.hpp>
#include <Prism/Application/Assembly/ProviderAssembly.hpp>
#include <Prism/Application/BoundaryStartup.hpp>
#include <Prism/Application/Configuration/ConfigurationParser.hpp>
#include <Prism/Application/ConfigurationStartup.hpp>
#include <Prism/Application/ProtocolAcceptors.hpp>
#include <Prism/Application/RuntimeGenerationSnapshot.hpp>
#include <Prism/Application/RuntimeState.hpp>
#include <Prism/Application/Startup/DatagramServices.hpp>
#include <Prism/Application/WorkerSessionServices.hpp>
#include <Prism/Boundary/Datagram/DatagramSender.hpp>
#include <Prism/Protocols/Http3/ServerFactory.hpp>
#include <Prism/Net/Datagram/Egress.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Net/Services/StreamEgress.hpp>
#include <Prism/Net/Services/StreamRelay.hpp>
#include <Prism/Net/Services/WorkerDialService.hpp>
#include <Prism/Operations/Models.hpp>

#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Prism::Application::ReloadGenerationPreparation
{

    namespace Net = boost::asio;
    namespace Assembly = Prism::Application::Assembly;
    namespace Configuration = Prism::Application::Configuration;
    namespace Provider = Prism::Composition::Provider;
    using RuntimeState = Prism::Application::Application::RuntimeState;
    using RuntimeSnapshot = Prism::Application::RuntimeGenerationSnapshot;
    using SharedRuntimeSnapshot = Prism::Application::SharedRuntimeGenerationSnapshot;
    using Failure = Prism::Fault::Failure;

    [[nodiscard]] inline auto FailureForStartup(const StartupError &) noexcept -> Failure
    {
        return Failure{Prism::Fault::Code::ConfigErr};
    }
    [[nodiscard]] inline auto FailureForDiagnose(const DiagnoseRuntimeError &Error) noexcept -> Failure
    {
        using ErrorCode = DiagnoseRuntimeErrorCode;
        switch (Error.Code)
        {
        case ErrorCode::InvalidOptions: return Failure{Prism::Fault::Code::ConfigErr};
        case ErrorCode::Directory:
        case ErrorCode::FileOpen:
        case ErrorCode::LegacyArchive: return Failure{Prism::Fault::Code::FileOpenfail};
        case ErrorCode::ConfigurationConflict:
        case ErrorCode::OwnerConflict: return Failure{Prism::Fault::Code::Blocked};
        case ErrorCode::WorkerStart:
        case ErrorCode::ResourceUnavailable: return Failure{Prism::Fault::Code::ResourceUnavailable};
        }
        return Failure{Prism::Fault::Code::Blocked};
    }
    [[nodiscard]] inline auto MakeDiagnoseConfiguration(
        const Configuration::PrismConfiguration &ConfigurationValue,
        const std::uint64_t GenerationId)
        -> std::expected<DiagnoseRuntimeConfiguration, Failure>
    {
        const auto Level = ConfigurationStartup::ParseDiagnoseLogLevel(ConfigurationValue.Logging.Level);
        const auto Mode = ConfigurationStartup::ParseDiagnoseRenderMode(ConfigurationValue.Logging.RenderMode);
        if (!Level || !Mode)
        {
            return std::unexpected(Failure{Prism::Fault::Code::ConfigErr});
        }
        DiagnoseRuntimeConfiguration Result;
        Result.Logging.Level = *Level;
        Result.Logging.Directory = ConfigurationValue.Logging.Directory;
        Result.Logging.FileName = ConfigurationValue.Logging.FileName;
        Result.Logging.Console = ConfigurationValue.Logging.Console;
        Result.Logging.RotateBytes = ConfigurationValue.Logging.RotateBytes;
        Result.Logging.RotateFiles = ConfigurationValue.Logging.RotateFiles;
        Result.Mode = *Mode;
        Result.TraceSelection = Prism::Text::TraceSelection{
            ConfigurationValue.Trace.IncludeCorrelation,
            ConfigurationValue.Trace.IncludeWorker,
            ConfigurationValue.Trace.IncludeSession,
            ConfigurationValue.Trace.IncludeStream};
        Result.FlushIntervalMs = ConfigurationValue.Logging.FlushIntervalMs;
        Result.GenerationId = GenerationId;
        return Result;
    }
    [[nodiscard]] inline auto MakeCandidateAccounts(
        const Configuration::SharedConfigurationGeneration &Generation,
        const AccountCatalog &CurrentAccounts)
        -> std::expected<AccountCatalog, Failure>
    {
        if (!Generation || !CurrentAccounts.Store || !CurrentAccounts.Identities ||
            !CurrentAccounts.Identities->RuntimeRegistry())
        {
            return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
        auto IdentityPreparation = CurrentAccounts.Identities->BeginPreparation();
        if (!IdentityPreparation)
        {
            return std::unexpected(IdentityPreparation.error());
        }
        auto Store = std::make_shared<Prism::Account::AccountStore>(
            Prism::Account::StoreOptions{
                .WorkerCount = Generation->Configuration().Runtime.WorkerCount,
                .RuntimeRegistry = CurrentAccounts.Identities->RuntimeRegistry(),
                .RevokeRuntimesOnSeal = false});
        auto Prepared = Assembly::PrepareAccountCatalog(
            {Generation, Store, *IdentityPreparation});
        if (!Prepared)
        {
            return std::unexpected(FailureForStartup(Prepared.error()));
        }
        const auto Committed = Store->Commit(Prepared->Update);
        if (!Committed)
        {
            return std::unexpected(Committed.error());
        }
        return std::move(Prepared->Catalog);
    }

    [[nodiscard]] inline auto MakeDialFunction(
        const Net::any_io_executor Executor,
        const std::shared_ptr<Prism::Network::Dns::Resolver> &Resolver,
        const std::chrono::milliseconds Timeout)
        -> Prism::Middleware::Builtin::DialMiddleware::DialFn
    {
        auto Dialer = std::make_shared<Prism::Network::Dialer::Dialer>(
            Executor, Prism::Network::Dialer::DialOptions{Timeout, true, Resolver});
        return [Dialer](const Prism::Network::Target &Target)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Failure>>
        {
            co_return co_await Dialer->Connect(Target);
        };
    }

    struct PreparedCandidateNetworkServices final
    {
        std::shared_ptr<Prism::Network::Dns::Resolver> Resolver;
        Prism::Runtime::SharedSessionServices Session;
        std::vector<std::shared_ptr<Prism::Network::Services::WorkerDialService>> WorkerDials;
        std::chrono::milliseconds HandshakeTimeout{};
        std::chrono::milliseconds RelayIdleTimeout{};
    };

    [[nodiscard]] inline auto PrepareCandidateNetworkServices(
        const std::shared_ptr<RuntimeState> &State,
        const SharedRuntimeSnapshot &Current,
        const Configuration::SharedConfigurationGeneration &Generation)
        -> std::expected<PreparedCandidateNetworkServices, Failure>
    {
        if (!State || !State->Process || !Current || !Generation || !Current->Services.Session)
        {
            return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
        const auto &ConfigurationValue = Generation->Configuration();
        PreparedCandidateNetworkServices Prepared;
        Prepared.Resolver = std::make_shared<Prism::Network::Dns::Resolver>(
            State->Io.get_executor(), Assembly::MakeDnsConfig(ConfigurationValue.Dns));
        Prepared.HandshakeTimeout = std::chrono::milliseconds(
            ConfigurationValue.Listeners.Tcp.front().Timeout);
        Prepared.RelayIdleTimeout = std::chrono::milliseconds(
            ConfigurationValue.Runtime.SessionTimeout);
        const auto NativeTls = BoundaryStartup::MakeNativeTlsContext(
            ConfigurationValue, State->ConfigurationPath);
        if (!NativeTls)
        {
            return std::unexpected(FailureForStartup(NativeTls.error()));
        }

        Prepared.WorkerDials.reserve(State->Process->Workers().Size());
        for (std::size_t Index = 0; Index < State->Process->Workers().Size(); ++Index)
        {
            const auto WorkerId = Prism::WorkerId{static_cast<std::uint64_t>(Index + 1U)};
            auto *Worker = State->Process->Workers().Find(WorkerId);
            if (!Worker)
            {
                return std::unexpected(Failure{Prism::Fault::Code::Blocked});
            }
            auto Dial = std::make_shared<Prism::Network::Services::WorkerDialService>(
                Prism::Network::Services::WorkerDialOptions{
                    Worker->Executor(), Assembly::MakeDnsConfig(ConfigurationValue.Dns),
                    Prepared.HandshakeTimeout, true});
            Prepared.WorkerDials.push_back(std::move(Dial));
        }

        const auto DiagnoseConfiguration = MakeDiagnoseConfiguration(
            Generation->Configuration(), Generation->Id().Value());
        if (!DiagnoseConfiguration)
        {
            return std::unexpected(DiagnoseConfiguration.error());
        }
        if (!State->Diagnose || !Current->Services.Session)
        {
            return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
        const auto DiagnoseEpoch = State->Diagnose->PrepareEpoch(*DiagnoseConfiguration);
        if (!DiagnoseEpoch)
        {
            return std::unexpected(FailureForDiagnose(DiagnoseEpoch.error()));
        }
        auto Session = std::make_shared<Prism::Runtime::SessionServices>(
            *Current->Services.Session);
        Session->Generation = Generation;
        Session->ProcessContext = Current->Services.Session->ProcessContext
            .WithRenderEpoch(*DiagnoseEpoch)
            .With(Prism::Diagnose::Fields::Generation, Generation->Id());
        Session->NativeTls = *NativeTls;
        Session->HandshakeTimeout = Prepared.HandshakeTimeout;
        Session->RelayIdleTimeout = Prepared.RelayIdleTimeout;
        Session->Dial = MakeDialFunction(
            State->Io.get_executor(), Prepared.Resolver, Prepared.HandshakeTimeout);
        Prepared.Session = std::move(Session);
        return Prepared;
    }

    struct CandidateProviderAssemblyRequest final
    {
        std::shared_ptr<RuntimeState> State;
        SharedRuntimeSnapshot Current;
        Configuration::SharedConfigurationGeneration Generation;
        AccountCatalog Accounts;
        PreparedCandidateNetworkServices Network;
    };

    struct PreparedCandidateProviderServices final
    {
        std::shared_ptr<Provider::BoundCatalog> Bindings;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
        std::shared_ptr<const Prism::Contract::DatagramIngressSelection> DatagramSelection;
        std::vector<Prism::Runtime::SessionServices> WorkerSessions;
        PreparedCandidateNetworkServices Network;
    };

    [[nodiscard]] inline auto PrepareCandidateProviderServices(
        CandidateProviderAssemblyRequest Request)
        -> std::expected<PreparedCandidateProviderServices, Failure>
    {
        const auto &ConfigurationValue = Request.Generation->Configuration();
        PreparedCandidateProviderServices Prepared;
        Prepared.UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        Request.Network.Session->GenerationUseState = Prepared.UseState;
        Prism::Contract::DatagramServices UdpOptions;
        UdpOptions.Resolve = [Resolver = Request.Network.Resolver](Prism::Network::Target Target)
            -> Net::awaitable<std::expected<Net::ip::udp::endpoint, Failure>>
        {
            return Assembly::ResolveUdpTarget(Resolver, std::move(Target));
        };
        UdpOptions.IdleTimeout = Request.Network.RelayIdleTimeout;
        UdpOptions.Traffic = Request.Network.Session->Traffic;

        Provider::ConfigurationInput Inputs{
            Request.Generation, Prepared.UseState, ConfigurationValue.Protocols,
            ConfigurationValue.ProtocolBindings, {}};
        for (const auto &Protocol : Inputs.Protocols)
        {
            const auto *Authentication = Request.Accounts.Find(Protocol.Id);
            if (!Authentication)
            {
                return std::unexpected(Failure{Prism::Fault::Code::ConfigErr});
            }
            Inputs.Authentication.emplace(Protocol.Id, *Authentication);
        }

        Provider::BindingServices BindingServices{
            Request.State->Io.get_executor(), UdpOptions,
            std::make_shared<Prism::Network::DatagramEgress>(Request.Network.Resolver), {}, {}};
        if (Request.State->DatagramListener)
        {
            BindingServices.Sender = std::make_shared<Prism::Boundary::DatagramSender>(
                Request.State->DatagramListener->SharedSocket());
            BindingServices.Quic.Listener = {
                Request.State->Io.get_executor(), Request.State->DatagramListener->SharedSocket(),
                Request.Network.Session->NativeTls, Request.State->DatagramListener->SharedSender()};
        }
        auto StreamEgress = std::make_shared<Prism::Network::StreamEgress>(
            Prism::Network::StreamEgressOptions{
                Request.State->Io.get_executor(), Request.Network.Resolver,
                Request.Network.HandshakeTimeout});
        Prism::Contract::StreamServices StreamServices{
            StreamEgress, Request.Network.Session->Traffic, Request.Network.RelayIdleTimeout,
            16U * 1024U, Request.State->Process->Resources().Bytes};
        BindingServices.Quic.Streams = StreamEgress;
        BindingServices.Quic.Datagrams = BindingServices.Egress;
        BindingServices.Quic.Traffic = Request.Network.Session->Traffic;
        BindingServices.Quic.Trace = Request.Network.Session->ProcessContext;
        BindingServices.Http3 = std::make_shared<Prism::Http3::ServerFactory>();
        BindingServices.Quic.Relay = std::make_shared<Prism::Network::StreamRelayService>(
            Prism::Network::StreamRelayOptions{
                .Traffic = StreamServices.Traffic,
                .BufferSize = StreamServices.BufferSize,
                .IdleTimeout = StreamServices.IdleTimeout,
                .Bytes = StreamServices.Bytes});
        BindingServices.Streams = StreamServices;

        auto Providers = Assembly::BuildProviderCatalog(std::move(Inputs), std::move(BindingServices));
        if (!Providers)
        {
            return std::unexpected(FailureForStartup(Providers.error()));
        }
        Prepared.Bindings = std::make_shared<Provider::BoundCatalog>(std::move(*Providers));
        const auto DatagramSelection = Startup::DatagramServices::MakeIngressSelection(
            Startup::DatagramServices::IngressSelectionPreparation{
                Prepared.Bindings, Request.Generation, Prepared.UseState,
                Request.Current->Services.DatagramSelection});
        if (!DatagramSelection)
        {
            return std::unexpected(Failure{Prism::Fault::Code::ConfigErr});
        }
        Prepared.DatagramSelection = *DatagramSelection;
        const ProtocolProfile::ProtocolFactoryContext Context{
            ConfigurationValue, *Request.Generation, Request.Accounts,
            Request.Network.Session->NativeTls, Request.Network.Session->Dial,
            Prepared.Bindings.get(), UdpOptions, StreamServices};
        const auto Profile = ProtocolProfile::MakeTcpProfile(Context);
        if (!Profile)
        {
            return std::unexpected(FailureForStartup(Profile.error()));
        }
        Request.Network.Session->Profile = Profile->Profile;
        Request.Network.Session->ResolveCandidate = Profile->Resolver;
        const auto WorkerSessions = MakeWorkerSessionServices(
            WorkerSessionServicesPreparation{
                Request.Network.Session, &Request.State->Process->Workers(),
                Request.Network.WorkerDials});
        if (!WorkerSessions)
        {
            return std::unexpected(WorkerSessions.error());
        }
        Prepared.WorkerSessions = std::move(*WorkerSessions);
        Prepared.Network = std::move(Request.Network);
        return Prepared;
    }

    [[nodiscard]] inline auto MakeCandidateSnapshot(
        const std::shared_ptr<RuntimeState> &State,
        const SharedRuntimeSnapshot &Current,
        Configuration::SharedConfigurationGeneration Generation)
        -> std::expected<SharedRuntimeSnapshot, Failure>
    {
        if (!State || !Current || !Generation)
        {
            return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
        auto Accounts = MakeCandidateAccounts(Generation, Current->Accounts);
        if (!Accounts)
        {
            return std::unexpected(Accounts.error());
        }
        auto Network = PrepareCandidateNetworkServices(State, Current, Generation);
        if (!Network)
        {
            return std::unexpected(Network.error());
        }
        auto Providers = PrepareCandidateProviderServices(CandidateProviderAssemblyRequest{
            State, Current, Generation, *Accounts, std::move(*Network)});
        if (!Providers)
        {
            return std::unexpected(Providers.error());
        }

        PreparedRuntimeGenerationServices PreparedServices;
        auto &ServiceGraph = PreparedServices.Graph();
        ServiceGraph.Session = std::move(Providers->Network.Session);
        ServiceGraph.Providers = std::move(Providers->Bindings);
        ServiceGraph.Resolver = std::move(Providers->Network.Resolver);
        ServiceGraph.WorkerDials = std::move(Providers->Network.WorkerDials);
        ServiceGraph.WorkerSessions = std::move(Providers->WorkerSessions);
        ServiceGraph.UseState = std::move(Providers->UseState);
        ServiceGraph.DatagramSelection = std::move(Providers->DatagramSelection);
        ServiceGraph.OwnResolver = true;
        ServiceGraph.OwnWorkerDials = true;
        auto FrozenServices = std::move(PreparedServices).Freeze();
        if (!FrozenServices)
        {
            return std::unexpected(FrozenServices.error());
        }
        return SharedRuntimeSnapshot{std::make_shared<const RuntimeSnapshot>(
            std::move(Generation), std::move(*Accounts), std::move(*FrozenServices))};
    }

} // namespace Prism::Application::ReloadGenerationPreparation
