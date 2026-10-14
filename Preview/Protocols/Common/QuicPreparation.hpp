/** @file QuicPreparation.hpp @brief 共享的实际 QUIC listener 与 owning token 材料校验。 */
#pragma once
#include <Preview/Protocols/Common/Authentication/ScopedMaterial.hpp>
#include <Preview/Contract/Services/Quic.hpp>
#include <Preview/Contract/Services/Authentication.hpp>
#include <Preview/Contract/Ingress/ProtocolConfiguration.hpp>
#include <Preview/Contract/Ingress/ProviderFailure.hpp>
#include <Preview/Foundation/Executor/ContextOwner.hpp>
#include <expected>
namespace Preview::Protocols
{
    struct QuicPreparation final
    {
        std::string Instance;
        Preview::Foundation::GenerationPin Generation;
        Preview::Contract::ProtocolConfiguration::QuicOptions Config;
    };
    /** @brief 校验真实服务与原 generation 控制块，零 lease；非敏感错误路径可直接定位配置。 */
    [[nodiscard]] inline auto ValidateQuic(const QuicPreparation& Input,
        const Preview::Contract::QuicBindingServices& Services)
        -> std::expected<void,Preview::Contract::ProviderFailure>
    {
        using E=Preview::Contract::ProviderError;
        auto Fail=[&Input](E Code,std::string Path)
        {return std::unexpected(Preview::Contract::ProviderFailure{Code,Input.Instance,std::move(Path)});};
        if(!Services.Listener.Tls)return Fail(E::MissingTls,"Quic.Tls");
        if(!Services.Listener.Executor || !Services.Listener.Socket ||
            Services.Listener.Socket->get_executor()!=Services.Listener.Executor)
            return Fail(E::InvalidConfiguration,"Quic.Listener");
        if(auto Context=Preview::Executor::ContextOwner::Find(Services.Listener.Executor);Context && !Context->CanDispatch())
            return Fail(E::DispatchUnavailable,"Quic.Executor");
        if(Preview::Executor::ContextOwner::Storage(Services.Listener.Executor)->IsSealed())
            return Fail(E::DispatchUnavailable,"Quic.Executor");
        if(!Services.Streams || !Services.Relay)return Fail(E::MissingEgress,"Quic.Streams");
        if(!Services.Datagrams)return Fail(E::MissingEgress,"Quic.Datagrams");
        if(Input.Instance.empty())return Fail(E::InvalidConfiguration,"Id");
        if(Input.Config.Alpn.empty())return Fail(E::InvalidConfiguration,"Quic.Alpn");
        if(Input.Config.MaxStreams==0)return Fail(E::InvalidConfiguration,"Quic.MaxStreams");
        if(Input.Config.MaxDatagrams==0)return Fail(E::InvalidConfiguration,"Quic.MaxDatagrams");
        return {};
    }
    [[nodiscard]] inline auto ValidateQuicAuthentication(const QuicPreparation& Input,
        const Preview::Contract::AuthenticationServices& Authentication)
        -> std::expected<ScopedMaterial, Preview::Contract::ProviderFailure>
    {
        using E=Preview::Contract::ProviderError;
        auto Fail=[&Input](E Code,std::string Path)
        {return std::unexpected(Preview::Contract::ProviderFailure{Code,Input.Instance,std::move(Path)});};
        if(!Authentication.Matches(Input.Generation))return Fail(E::GenerationMismatch,"Generation");
        if (!Authentication.Credentials || !Authentication.Authenticator)
            return Fail(E::MissingAuthentication, "Authentication");
        ScopedMaterial Credential;
        bool Invalid = false;
        const auto Enumerated = Authentication.Credentials.ForEachCredential(Preview::Account::CredentialKind::Token,
            [&](const auto& Binding, const auto& Material)
            {
                auto Pinned = ScopedMaterial::Pin(Binding, Material);
                if (!Pinned || Credential) Invalid = true;
                else Credential = std::move(*Pinned);
            });
        if (!Enumerated || Invalid || !Credential) return Fail(E::InvalidCredential, "Quic.CredentialSecretRef");
        return Credential;
    }
}
