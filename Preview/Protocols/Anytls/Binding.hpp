/** @file Binding.hpp @brief AnyTLS 的冷密码 wire 配置与 ingress 服务绑定。 */
#pragma once
#include <Preview/Protocols/Anytls/IngressFactory.hpp>
#include <Preview/Contract/Services/Authentication.hpp>
#include <Preview/Contract/Ingress/ProviderFailure.hpp>

namespace Preview::Anytls
{
    [[nodiscard]] inline auto PrepareAccountCredential(std::string_view Value)
        ->Preview::Account::Credential
    {
        return Preview::Account::Credential::Password(Value);
    }

    struct PreparedBinding final
    {
        std::string Instance;
        IngressOptions Options;
    };

    struct Binding final
    {
        IngressOptions Options;
    };

    [[nodiscard]] inline auto PrepareProviderBinding(
        std::string Instance,
        Preview::Contract::AuthenticationServices Authentication,
        Preview::Contract::StreamServices Streams)
        -> std::expected<PreparedBinding, Preview::Contract::ProviderFailure>
    {
        if (!Authentication.Generation || !Authentication.Authenticator || !Authentication.Credentials)
        {
            return std::unexpected(Preview::Contract::ProviderFailure{
                Preview::Contract::ProviderError::MissingAuthentication, {}, "Authentication"});
        }
        if (!Streams.Egress)
        {
            return std::unexpected(Preview::Contract::ProviderFailure{
                Preview::Contract::ProviderError::MissingEgress, {}, "Streams.Egress"});
        }
        std::string Password;
        const auto Enumerated = Authentication.Credentials.ForEachCredential(
            Preview::Account::CredentialKind::Password,
            [&Password](const std::shared_ptr<const Preview::Account::AccountBinding>&,
                        const Preview::Account::CredentialMaterial& Material)
            {
                if (!Password.empty()) return;
                const auto Bytes = Material.Credential.View().Bytes();
                Password.assign(reinterpret_cast<const char*>(Bytes.data()), Bytes.size());
            });
        if (!Enumerated || Password.empty())
        {
            return std::unexpected(Preview::Contract::ProviderFailure{
                Preview::Contract::ProviderError::InvalidCredential, {}, "Authentication.Password"});
        }
        IngressOptions Options;
        Options.Configuration.Password = std::move(Password);
        Options.Authenticator = std::move(Authentication.Authenticator);
        Options.Streams = std::move(Streams);
        return PreparedBinding{std::move(Instance), std::move(Options)};
    }

    [[nodiscard]] inline auto BindProvider(PreparedBinding Prepared)
        -> std::shared_ptr<const Binding>
    {
        return std::make_shared<const Binding>(Binding{std::move(Prepared.Options)});
    }
}
