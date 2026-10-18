/**
 * @file ProtocolServices.hpp
 * @brief Prism 启动阶段的独立资源装配责任。
 */
#pragma once
#include <Prism/Application/Application.hpp>
#include <Prism/Application/Assembly/NetworkAssembly.hpp>
#include <Prism/Application/BoundaryStartup.hpp>
#include <Prism/Application/ProtocolAcceptors.hpp>
#include <Prism/Application/RuntimeState.hpp>
#include <Prism/Application/Startup/GenerationPhase.hpp>
#include <Prism/Contract/Services/Datagram.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Datagram/Egress.hpp>
#include <Prism/Application/Assembly/ProviderAssembly.hpp>
#include <Prism/Application/Startup/DatagramServices.hpp>
#include <Prism/Application/Startup/QuicServices.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Net/Services/StreamEgress.hpp>
#include <Prism/Net/Services/StreamRelay.hpp>
namespace Prism::Application::Startup::ProtocolServices
{
    namespace Net = boost::asio;
    namespace Assembly = Prism::Application::Assembly;
    namespace Provider = Prism::Composition::Provider;
    /** @brief 控制线程借用配置路径加载 TLS、设置超时和拨号 owner；返回 typed 错误，事务最终关闭。 */
    inline auto Prepare(const std::shared_ptr<Application::RuntimeState>& Runtime,
        const std::filesystem::path& ConfigurationPath) -> std::expected<void, StartupError>
    {
        const auto NativeTls =
            BoundaryStartup::MakeNativeTlsContext(Runtime->Generation->Configuration(), ConfigurationPath);
        if (!NativeTls)
        {
            return std::unexpected(NativeTls.error());
        }
        Runtime->Services->NativeTls = *NativeTls;
        Runtime->ShutdownTimeout =
            std::chrono::milliseconds(Runtime->Generation->Configuration().Shutdown.Timeout);
        Runtime->Services->HandshakeTimeout =
            std::chrono::milliseconds(Runtime->Generation->Configuration().Listeners.Tcp.front().Timeout);
        Runtime->Services->RelayIdleTimeout =
            std::chrono::milliseconds(Runtime->Generation->Configuration().Runtime.SessionTimeout);
        const auto DialTimeout =
            std::chrono::milliseconds(Runtime->Generation->Configuration().Listeners.Tcp.front().Timeout);
        Runtime->Services->Dial = [Dialer = std::make_shared<Prism::Network::Dialer::Dialer>(
            Runtime->Io.get_executor(),
            Prism::Network::Dialer::DialOptions{DialTimeout, true, Runtime->DnsResolver})](
                                      const Prism::Network::Target &Target)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
        {
            co_return co_await Dialer->Connect(Target);
        };
        return {};
    }
    /** @brief 从 generation 冻结协议 profile 和 Mux 快照；runtime 拥有结果，异步 child 独立保活共享依赖。 */
    inline auto Bind(const std::shared_ptr<Application::RuntimeState>& Runtime,
        const GenerationPhase::Result& Phase) -> std::expected<void, StartupError>
    {
        Prism::Contract::DatagramServices UdpOptions;
        UdpOptions.Resolve = [Resolver = Runtime->DnsResolver](
                                  Prism::Network::Target Request)
            -> Net::awaitable<std::expected<Net::ip::udp::endpoint, Prism::Fault::Failure>>
        { return Assembly::ResolveUdpTarget(Resolver, std::move(Request)); };
        UdpOptions.IdleTimeout = Runtime->Services->RelayIdleTimeout;
        UdpOptions.Traffic = Runtime->Services->Traffic;
        if (!Phase.UseState)
        {
            return std::unexpected(Startup::MakeStartupError(
                StartupErrorCode::Runtime, "Generation", "initial generation use state is unavailable"));
        }
        Provider::ConfigurationInput Inputs{Runtime->Generation, Phase.UseState,
            Runtime->Generation->Configuration().Protocols,
            Runtime->Generation->Configuration().ProtocolBindings, {}};
        for (const auto& Protocol : Inputs.Protocols)
        {
            const auto* Authentication = Runtime->Accounts.Find(Protocol.Id);
            if (!Authentication) return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Runtime,
                "Protocols." + Protocol.Id, "协议实例没有已编译凭据域"));
            Inputs.Authentication.emplace(Protocol.Id, *Authentication);
        }
        Provider::BindingServices Services{Runtime->Io.get_executor(),UdpOptions,
            std::make_shared<Prism::Network::DatagramEgress>(Runtime->DnsResolver),{}};
        if(Runtime->DatagramListener)Services.Sender=std::make_shared<Prism::Boundary::DatagramSender>(
            Runtime->DatagramListener->SharedSocket());
        if(Runtime->DatagramListener)Services.Quic.Listener={Runtime->Io.get_executor(),
            Runtime->DatagramListener->SharedSocket(),Runtime->Services->NativeTls,Runtime->DatagramListener->SharedSender()};
        Services.Quic.Streams=std::make_shared<Prism::Network::StreamEgress>(Prism::Network::StreamEgressOptions{
            Runtime->Io.get_executor(),Runtime->DnsResolver,Runtime->Services->HandshakeTimeout});
        Services.Quic.Datagrams=Services.Egress;Services.Quic.Traffic=Runtime->Services->Traffic;Services.Quic.Trace=Runtime->RootContext;
        Services.Http3=std::make_shared<Prism::Http3::ServerFactory>();
        const Prism::Contract::StreamServices Streams{Services.Quic.Streams, Runtime->Services->Traffic,
            Runtime->Services->RelayIdleTimeout, 16 * 1024, Runtime->Process->Resources().Bytes};
        Services.Quic.Relay=std::make_shared<Prism::Network::StreamRelayService>(
            Prism::Network::StreamRelayOptions{
                .Traffic = Streams.Traffic,
                .BufferSize = Streams.BufferSize,
                .IdleTimeout = Streams.IdleTimeout,
                .Bytes = Streams.Bytes});
        Services.Streams = Streams;
        auto Providers=Assembly::BuildProviderCatalog(std::move(Inputs),std::move(Services));
        if(!Providers)return std::unexpected(Providers.error());
        Runtime->ProviderBindings=std::make_shared<Provider::BoundCatalog>(std::move(*Providers));
        QuicServices::Build(Runtime);
        DatagramServices::Bind(Runtime);
        const ProtocolProfile::ProtocolFactoryContext ProtocolContext{Runtime->Generation->Configuration(),
            *Runtime->Generation, Runtime->Accounts,
            Runtime->Services->NativeTls, Runtime->Services->Dial, &*Runtime->ProviderBindings, std::move(UdpOptions),
            Streams};
        const auto Profile = ProtocolProfile::MakeTcpProfile(ProtocolContext);
        if (!Profile)
        {
            return std::unexpected(Profile.error());
        }
        Runtime->Services->Profile = Profile->Profile;
        Runtime->Services->ResolveCandidate = std::move(Profile->Resolver);

        return {};
    }
} // namespace Prism::Application::Startup::ProtocolServices
