/** @file QuicPreparation.cpp @brief QUIC provider 准备输入验证实现。 */

#include <Prism/Protocols/Common/QuicPreparation.hpp>

#include <Prism/Account/Materials.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>

#include <string>
#include <utility>

namespace Prism::Protocols
{
    [[nodiscard]] auto ValidateQuic(
        const QuicPreparation& Input,
        const Prism::Contract::QuicBindingServices& Services)
        -> std::expected<void, Prism::Contract::ProviderFailure>
    {
        using E = Prism::Contract::ProviderError;
        auto Fail = [&Input](const E Code, std::string Path)
        {
            return std::unexpected(
                Prism::Contract::ProviderFailure{Code, Input.Instance, std::move(Path)});
        };
        if (!Services.Listener.Tls) return Fail(E::MissingTls, "Quic.Tls");
        if (!Services.Listener.Executor || !Services.Listener.Socket ||
            Services.Listener.Socket->get_executor() != Services.Listener.Executor)
        {
            return Fail(E::InvalidConfiguration, "Quic.Listener");
        }
        if (auto Context = Prism::Executor::ContextOwner::Find(Services.Listener.Executor);
            Context && !Context->CanDispatch())
        {
            return Fail(E::DispatchUnavailable, "Quic.Executor");
        }
        if (Prism::Executor::ContextOwner::Storage(Services.Listener.Executor)->IsSealed())
        {
            return Fail(E::DispatchUnavailable, "Quic.Executor");
        }
        if (!Services.Streams || !Services.Relay)
            return Fail(E::MissingEgress, "Quic.Streams");
        if (!Services.Datagrams) return Fail(E::MissingEgress, "Quic.Datagrams");
        if (Input.Instance.empty()) return Fail(E::InvalidConfiguration, "Id");
        if (Input.Config.Alpn.empty()) return Fail(E::InvalidConfiguration, "Quic.Alpn");
        if (Input.Config.MaxStreams == 0)
            return Fail(E::InvalidConfiguration, "Quic.MaxStreams");
        if (Input.Config.MaxDatagrams == 0)
            return Fail(E::InvalidConfiguration, "Quic.MaxDatagrams");
        return {};
    }

    [[nodiscard]] auto ValidateQuicAuthentication(
        const QuicPreparation& Input,
        const Prism::Contract::AuthenticationServices& Authentication)
        -> std::expected<ScopedMaterial, Prism::Contract::ProviderFailure>
    {
        using E = Prism::Contract::ProviderError;
        auto Fail = [&Input](const E Code, std::string Path)
        {
            return std::unexpected(
                Prism::Contract::ProviderFailure{Code, Input.Instance, std::move(Path)});
        };
        if (!Authentication.Matches(Input.Generation))
            return Fail(E::GenerationMismatch, "Generation");
        if (!Authentication.Credentials || !Authentication.Authenticator)
            return Fail(E::MissingAuthentication, "Authentication");
        ScopedMaterial Credential;
        bool Invalid = false;
        const auto Enumerated = Authentication.Credentials.ForEachCredential(
            Prism::Account::CredentialKind::Token,
            [&Credential, &Invalid](const auto& Binding, const auto& Material)
            {
                auto Pinned = ScopedMaterial::Pin(Binding, Material);
                if (!Pinned || Credential) Invalid = true;
                else Credential = std::move(*Pinned);
            });
        if (!Enumerated || Invalid || !Credential)
            return Fail(E::InvalidCredential, "Quic.CredentialSecretRef");
        return Credential;
    }
} // namespace Prism::Protocols
