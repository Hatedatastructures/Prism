/** @file Binding.cpp @brief VMess account credential 与 provider binding 实现。 */
#include <Prism/Protocols/Vmess/Binding.hpp>
#include <Prism/Protocols/Common/UuidCredentialSelection.hpp>
#include <Prism/Protocols/Vmess/AuthId.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

namespace Prism::Vmess
{
    [[nodiscard]] auto PrepareAccountCredential(const std::string_view Value)
        -> std::expected<Prism::Account::Credential, Prism::Contract::ProviderFailure>
    {
        std::array<std::uint8_t, 16> Parsed{};
        if (!Prism::Vmess::ParseUuid(Value, Parsed))
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::InvalidCredential, {}, "Credential.Uuid"});
        }
        Prism::Account::UuidBytes Bytes{};
        for (std::size_t Index = 0; Index < Bytes.size(); ++Index)
        {
            Bytes[Index] = static_cast<std::byte>(Parsed[Index]);
        }
        return Prism::Account::Credential::Uuid(Bytes);
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
        const auto Uuid = Prism::Protocols::Common::FirstUuidCredential(
            Request.Authentication.Credentials);
        if (!Uuid)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::InvalidCredential, Request.Instance,
                "Authentication.Uuid"});
        }
        ServerConfig Configuration;
        Configuration.uuid = *Uuid;
        Configuration.EnableUdp = Request.EnableUdp;
        Configuration.EnableMux = Request.EnableMux;
        Configuration.AuthenticatorOwner = Request.Authentication.Authenticator;
        return PreparedBinding{std::move(Request.Instance), std::move(Configuration),
            Request.Authentication.Authenticator, Request.Authentication.Credentials,
            std::move(Request.Datagrams), Request.Authentication.Generation,
            std::move(Request.GenerationUseState), std::move(Request.Executor)};
    }
}
