/** @file Binding.cpp @brief Trojan provider 准备与共享绑定生命周期实现。 */
#include <Prism/Protocols/Trojan/Binding.hpp>
#include <Prism/Protocols/Trojan/CredentialCodec.hpp>

#include <memory>
#include <utility>

namespace Prism::Trojan
{
    [[nodiscard]] auto PrepareAccountCredential(std::string_view Value)
        -> Prism::Account::Credential
    {
        return Prism::Account::Credential::Token(Prism::Trojan::Credential(Value));
    }

    Binding::~Binding()
    { Close(); }

    [[nodiscard]] auto Binding::Begin(Prism::SharedTransmission Inbound) const
        -> std::expected<Binding::AcceptAttempt, Prism::Fault::Failure>
    {
        return Lifetime_->Begin(std::move(Inbound));
    }

    auto Binding::Close() const noexcept -> void
    { Lifetime_->Close(); }

    [[nodiscard]] auto Binding::Drain() const -> boost::asio::awaitable<
        std::expected<void, Prism::Fault::Failure>>
    {
        return Lifetime_->Drain();
    }

    Binding::Binding(PreparedBinding Value) : Lifetime_(MakeLifetime(std::move(Value)))
    {}

    [[nodiscard]] auto Binding::MakeLifetime(PreparedBinding Value) -> std::shared_ptr<Binding::Lifetime>
    {
        auto Material = std::make_shared<const PreparedBinding>(std::move(Value));
        return std::make_shared<Lifetime>(std::move(Material));
    }

    [[nodiscard]] auto BindProvider(PreparedBinding Prepared)
        -> std::shared_ptr<const Binding>
    {
        return std::shared_ptr<const Binding>(new Binding(std::move(Prepared)));
    }

    [[nodiscard]] auto PrepareProviderBinding(ProviderRequest Request)
        -> std::expected<PreparedBinding, Prism::Contract::ProviderFailure>
    {
        if (!Request.Authentication.Generation || !Request.Authentication.Authenticator ||
            !Request.Authentication.Credentials)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::MissingAuthentication, {}, "Authentication"});
        }
        if (!Request.GenerationUseState || !Request.Executor)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::GenerationMismatch, Request.Instance,
                "Generation.UseState"});
        }
        ServerConfig Configuration;
        Configuration.EnableTcp = Request.EnableTcp;
        Configuration.EnableUdp = Request.EnableUdp;
        Configuration.EnableMux = Request.EnableMux;
        Configuration.AuthenticatorOwner = Request.Authentication.Authenticator;
        return PreparedBinding{std::move(Request.Instance), std::move(Configuration),
            std::move(Request.Datagrams), Request.Authentication.Generation,
            std::move(Request.GenerationUseState), std::move(Request.Executor)};
    }
}
