/**
 * @file ProtocolServices.hpp
 * @brief Preview 启动阶段的独立资源装配责任。
 */
#pragma once
#include <Preview/Application/Application.hpp>
#include <Preview/Application/Assembly/NetworkAssembly.hpp>
#include <Preview/Application/BoundaryStartup.hpp>
#include <Preview/Application/ProtocolAcceptors.hpp>
#include <Preview/Application/RuntimeState.hpp>
#include <Preview/Application/Startup/GenerationPhase.hpp>
#include <Preview/Contract/Services/Datagram.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Net/Datagram/Egress.hpp>
#include <Preview/Application/Assembly/ProviderAssembly.hpp>
#include <Preview/Application/Startup/DatagramServices.hpp>
#include <Preview/Application/Startup/QuicServices.hpp>
#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Net/Services/StreamEgress.hpp>
#include <Preview/Net/Services/StreamRelay.hpp>
namespace Preview::Application::Startup::ProtocolServices
{
    namespace Net = boost::asio;
    namespace Assembly = Preview::Application::Assembly;
    namespace Provider = Preview::Composition::Provider;
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
        Runtime->Services->Dial = [Dialer = std::make_shared<Preview::Network::Dialer::Dialer>(
            Runtime->Io.get_executor(),
            Preview::Network::Dialer::DialOptions{DialTimeout, true, Runtime->DnsResolver})](
                                      const Preview::Network::Target &Target)
            -> Net::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>
        {
            co_return co_await Dialer->Connect(Target);
        };
        return {};
    }
    /** @brief 从 generation 冻结协议 profile 和 Mux 快照；runtime 拥有结果，异步 child 独立保活共享依赖。 */
    inline auto Bind(const std::shared_ptr<Application::RuntimeState>& Runtime,
        const GenerationPhase::Result& Phase) -> std::expected<void, StartupError>
    {
        Preview::Contract::DatagramServices UdpOptions;
        UdpOptions.Resolve = [Resolver = Runtime->DnsResolver](
                                  Preview::Network::Target Request)
            -> Net::awaitable<std::expected<Net::ip::udp::endpoint, Preview::Fault::Failure>>
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
            std::make_shared<Preview::Network::DatagramEgress>(Runtime->DnsResolver),{}};
        if(Runtime->DatagramListener)Services.Sender=std::make_shared<Preview::Boundary::DatagramSender>(
            Runtime->DatagramListener->SharedSocket());
        if(Runtime->DatagramListener)Services.Quic.Listener={Runtime->Io.get_executor(),
            Runtime->DatagramListener->SharedSocket(),Runtime->Services->NativeTls,Runtime->DatagramListener->SharedSender()};
        Services.Quic.Streams=std::make_shared<Preview::Network::StreamEgress>(Preview::Network::StreamEgressOptions{
            Runtime->Io.get_executor(),Runtime->DnsResolver,Runtime->Services->HandshakeTimeout});
        Services.Quic.Datagrams=Services.Egress;Services.Quic.Traffic=Runtime->Services->Traffic;Services.Quic.Trace=Runtime->RootContext;
        Services.Http3=std::make_shared<Preview::Http3::ServerFactory>();
        const Preview::Contract::StreamServices Streams{Services.Quic.Streams, Runtime->Services->Traffic,
            Runtime->Services->RelayIdleTimeout, 16 * 1024, Runtime->Process->Resources().Bytes};
        Services.Quic.Relay=std::make_shared<Preview::Network::StreamRelayService>(
            Preview::Network::StreamRelayOptions{
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
} // namespace Preview::Application::Startup::ProtocolServices
