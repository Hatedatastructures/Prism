/**
 * @file Acceptors.hpp
 * @brief Application 把已编译的 typed protocol bindings 接入冷候选 registry。
 */
#pragma once

#include <Prism/Application/Protocol/Detail/Profile.hpp>
#include <Prism/Composition/Provider/ProviderCatalog.hpp>
#include <Prism/Composition/Provider/TlsCarrierProvider.hpp>
#include <Prism/Composition/Protocol/ProtocolCatalog.hpp>
#include <Prism/Composition/Recognition/CandidateRegistry.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <stop_token>

namespace Prism::Application::ProtocolProfile
{
    [[nodiscard]] inline auto MakeCarrierStartupError(
        const Prism::Contract::ProviderFailure& Failure) -> StartupError
    {
        auto Code = StartupErrorCode::InvalidConfiguration;
        if (Failure.Code == Prism::Contract::ProviderError::MissingTls ||
            Failure.Code == Prism::Contract::ProviderError::MissingResolver ||
            Failure.Code == Prism::Contract::ProviderError::MissingAuthentication)
        {
            Code = StartupErrorCode::UnsupportedService;
        }
        else if (Failure.Code == Prism::Contract::ProviderError::DuplicateInstance ||
                 Failure.Code == Prism::Contract::ProviderError::AlreadyBound)
        {
            Code = StartupErrorCode::Runtime;
        }
        return Startup::MakeStartupError(Code,
            "Carriers." + Failure.Instance + "." + Failure.Path,
            "typed TLS carrier preparation or binding failed");
    }

    [[nodiscard]] inline auto RegisterTlsCarriers(
        Recognition::CandidateRegistry& Registry,
        const ProtocolFactoryContext& Context) -> std::expected<void, StartupError>
    {
        const auto ResolveSecret = [&Context](const std::string_view Reference)
            -> std::optional<std::string>
        {
            const auto Secret = Context.Generation.LookupSecret(Reference);
            if (Secret.empty())
            {
                return std::nullopt;
            }
            return std::string(reinterpret_cast<const char*>(Secret.data()), Secret.size());
        };
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
        if (Context.ProviderBindings) UseState = Context.ProviderBindings->UseState();
        Prism::Composition::Provider::TlsCarrierPreparationServices Services{
            Context.NativeTls, Context.Dial, ResolveSecret,
            std::move(UseState)};
        auto Prepared = Prism::Composition::Provider::TlsCarrierProviderCatalog::Prepare(
            Context.ConfigurationValue.Carriers, std::move(Services));
        if (!Prepared)
        {
            return std::unexpected(MakeCarrierStartupError(Prepared.error()));
        }
        auto Frozen = Prepared->Freeze();
        if (!Frozen)
        {
            return std::unexpected(MakeCarrierStartupError(Frozen.error()));
        }
        auto Bound = Frozen->Bind(std::stop_token{});
        if (!Bound)
        {
            return std::unexpected(MakeCarrierStartupError(Bound.error()));
        }
        auto Registered = (*Bound)->Register(Registry);
        if (!Registered)
        {
            return std::unexpected(MakeCarrierStartupError(Registered.error()));
        }
        if (Context.ProviderBindings)
        {
            auto Adopted = Context.ProviderBindings->AdoptCarrierOwner("Tls",
                std::static_pointer_cast<Prism::Contract::CarrierCatalogOwner>(*Bound));
            if (!Adopted)
            {
                return std::unexpected(MakeCarrierStartupError(Adopted.error()));
            }
        }
        return {};
    }

    [[nodiscard]] inline auto RegisterProviderCandidate(
        Recognition::CandidateRegistry& Registry,
        const Prism::Contract::ProtocolConfiguration& Configured,
        const ProtocolFactoryContext& Context) -> std::expected<void, StartupError>
    {
        const Prism::Composition::Provider::BoundInstance* Entry = nullptr;
        if (Context.ProviderBindings)
        {
            Entry = Context.ProviderBindings->Find(Configured.Id);
        }
        if(!Entry)return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Bind,
            "Protocols."+Configured.Id,"prepared protocol instance is not bound"));
        const auto Muxes = Context.ProviderBindings->MuxesForProtocol(Configured.Id);
        const Recognition::ProviderCandidateInputs Inputs{*Entry, Muxes};
        if(!Registry.RegisterConfiguredProvider(Configured.Id,Inputs))
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Runtime,
                "Protocols."+Configured.Id,"protocol instance candidate registration failed"));
        return {};
    }

    [[nodiscard]] inline auto RegisterTcpCandidate(
        Recognition::CandidateRegistry& Registry,
        const Prism::Contract::ProtocolConfiguration& Configured,
        const ProtocolFactoryContext& Context) -> std::expected<void,StartupError>
    {
        const auto Descriptor=Prism::Composition::Protocol::ProtocolCatalog::Find(Configured.Builtin);
        if(!Descriptor || Descriptor->Kind!=Prism::Composition::Protocol::DescriptorKind::Protocol ||
            !Descriptor->SupportsTcp || !Provider::ProviderCatalog::Handles(Configured.Builtin))
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::UnsupportedService,
                "Protocols."+Configured.Id,"configured TCP protocol has no prepared provider binding"));
        }
        return RegisterProviderCandidate(Registry,Configured,Context);
    }

    [[nodiscard]] inline auto MakeTcpCandidateRegistry(const ProtocolFactoryContext& Context)
        ->std::expected<Recognition::CandidateRegistry,StartupError>
    {
        Recognition::CandidateRegistry Registry;
        const auto RegisteredCarriers = RegisterTlsCarriers(Registry, Context);
        if(!RegisteredCarriers)return std::unexpected(RegisteredCarriers.error());
        for(const auto& Configured:Context.ConfigurationValue.Protocols)
        {
            const auto Descriptor=Prism::Composition::Protocol::ProtocolCatalog::Find(Configured.Builtin);
            if(!Descriptor)return std::unexpected(Startup::MakeStartupError(
                StartupErrorCode::UnsupportedService,"Protocols."+Configured.Id,
                "configured protocol has no static descriptor"));
            if(Descriptor->SupportsQuic)continue;
            const auto Registered=RegisterTcpCandidate(Registry,Configured,Context);
            if(!Registered)return std::unexpected(Registered.error());
        }
        return Registry;
    }

    [[nodiscard]] inline auto MakeProfileBuildError(const Core::ProfileError Error) -> StartupError
    {
        auto Code=StartupErrorCode::Generation;
        if(Error==Core::ProfileError::QuicCandidateRequiresGateway)Code=StartupErrorCode::UnsupportedService;
        return Startup::MakeStartupError(Code,"Protocols",
            "Prism TCP recognition profile build failed: "+std::string(Core::ToStringView(Error)));
    }

    [[nodiscard]] inline auto MakeTcpProfile(const ProtocolFactoryContext& Context)
        ->std::expected<Recognition::ProfileBuildResult,StartupError>
    {
        auto Registry=MakeTcpCandidateRegistry(Context);
        if(!Registry)return std::unexpected(Registry.error());
        auto RecognitionConfig=MakeTcpRecognitionConfig(Context.ConfigurationValue);
        auto Factory=Registry->MakeFactory();
        auto Built=Recognition::ProfileBuilder::Build(RecognitionConfig,std::move(Factory));
        if(!Built)return std::unexpected(MakeProfileBuildError(Built.error()));
        return std::move(*Built);
    }
} // namespace Prism::Application::ProtocolProfile
