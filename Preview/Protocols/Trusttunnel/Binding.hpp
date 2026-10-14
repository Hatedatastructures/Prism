/** @file Binding.hpp @brief TrustTunnel wire proof 与账户认证的冷绑定材料。 */
#pragma once
#include <Preview/Protocols/Trusttunnel/IngressFactory.hpp>
#include <Preview/Contract/Services/Authentication.hpp>
#include <Preview/Contract/Ingress/ProviderFailure.hpp>

namespace Preview::Trusttunnel
{
    [[nodiscard]] inline auto PrepareAccountCredential(std::string_view Value)
        ->Preview::Account::Credential
    {
        return Preview::Account::Credential::Password(Value);
    }

    struct PreparedBinding final
    {
        std::string Instance;
        std::shared_ptr<boost::asio::ssl::context> NativeTls;
        SharedWireAuthBinding Wire;
    };

    struct Binding final
    {
        std::string Instance;
        std::shared_ptr<boost::asio::ssl::context> NativeTls;
        SharedWireAuthBinding Wire;
    };

    [[nodiscard]] inline auto ParseServerCredential(std::string_view Credential)
        -> std::expected<ServerConfig, Preview::Contract::ProviderFailure>
    {
        const auto Separator = Credential.find(':');
        if (Separator == std::string_view::npos || Separator == 0U || Separator + 1U >= Credential.size())
        {
            return std::unexpected(Preview::Contract::ProviderFailure{
                Preview::Contract::ProviderError::InvalidCredential, {}, "Authentication.Credential"});
        }
        return ServerConfig{std::string(Credential.substr(0, Separator)),
            std::string(Credential.substr(Separator + 1U))};
    }

    [[nodiscard]] inline auto PrepareProviderBinding(
        std::string Instance,
        Preview::Contract::AuthenticationServices Authentication,
        std::shared_ptr<boost::asio::ssl::context> NativeTls)
        -> std::expected<PreparedBinding, Preview::Contract::ProviderFailure>
    {
        if (!NativeTls)
        {
            return std::unexpected(Preview::Contract::ProviderFailure{
                Preview::Contract::ProviderError::MissingTls, {}, "NativeTls"});
        }
        if (!Authentication.Generation || !Authentication.Authenticator || !Authentication.Credentials)
        {
            return std::unexpected(Preview::Contract::ProviderFailure{
                Preview::Contract::ProviderError::MissingAuthentication, {}, "Authentication"});
        }
        std::string Credential;
        const auto Enumerated = Authentication.Credentials.ForEachCredential(
            Preview::Account::CredentialKind::Password,
            [&Credential](const std::shared_ptr<const Preview::Account::AccountBinding>&,
                          const Preview::Account::CredentialMaterial& Material)
            {
                if (!Credential.empty()) return;
                const auto Bytes = Material.Credential.View().Bytes();
                Credential.assign(reinterpret_cast<const char*>(Bytes.data()), Bytes.size());
            });
        if (!Enumerated || Credential.empty())
        {
            return std::unexpected(Preview::Contract::ProviderFailure{
                Preview::Contract::ProviderError::InvalidCredential, {}, "Authentication.Credential"});
        }
        auto Configuration = ParseServerCredential(Credential);
        if (!Configuration) return std::unexpected(Configuration.error());
        auto Wire = MakeWireAuthBinding(std::move(*Configuration), std::move(Authentication.Authenticator));
        return PreparedBinding{std::move(Instance), std::move(NativeTls), std::move(Wire)};
    }

    [[nodiscard]] inline auto BindProvider(PreparedBinding Prepared)
        -> std::shared_ptr<const Binding>
    {
        return std::make_shared<const Binding>(Binding{
            std::move(Prepared.Instance), std::move(Prepared.NativeTls), std::move(Prepared.Wire)});
    }
}
