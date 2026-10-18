/** @file Binding.hpp @brief VMess 冷认证、credential scope 与 session 退休 owner。 */
#pragma once

#include <Prism/Protocols/Vmess/Vmess.hpp>
#include <Prism/Protocols/Vmess/AuthId.hpp>
#include <Prism/Protocols/Common/ProviderBindingLifecycle.hpp>
#include <Prism/Protocols/Common/ProviderCredentials.hpp>
#include <Prism/Contract/Services/Authentication.hpp>
#include <Prism/Contract/Ingress/ProviderFailure.hpp>
#include <Prism/Account/Credential.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <stop_token>
#include <string_view>

namespace Prism::Vmess
{
    class IngressFactory;
    struct IngressRoute final
    {
        std::shared_ptr<Prism::Mux::RootBinding> Mux;
    };

    /** @brief 将标准 VMess UUID 文本转换为账户凭据，不把输入材料写入错误。 */
    [[nodiscard]] inline auto PrepareAccountCredential(const std::string_view Value)
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

    struct ProviderRequest final
    {
        std::string Instance;
        Prism::Contract::AuthenticationServices Authentication;
        Prism::Contract::DatagramServices Datagrams;
        std::shared_ptr<Prism::Foundation::GenerationUseState> GenerationUseState;
        boost::asio::any_io_executor Executor;
        bool EnableUdp;
        bool EnableMux;
    };

    struct PreparedBinding final
    {
        std::string Instance;
        ServerConfig Configuration;
        Prism::SharedAuthenticator Authenticator;
        Prism::Account::CredentialIndexView Credentials;
        Prism::Contract::DatagramServices Datagrams;
        Prism::Foundation::GenerationPin Generation;
        std::shared_ptr<Prism::Foundation::GenerationUseState> GenerationUseState;
        boost::asio::any_io_executor Executor;
    };

    class Binding final : public std::enable_shared_from_this<Binding>
    {
        using Lifetime = Prism::Protocols::ProviderBindingLifecycle<PreparedBinding>;

    public:
        using AcceptAttempt = Lifetime::AcceptAttempt;

        ~Binding() { Close(); }
        Binding(const Binding&) = delete;
        auto operator=(const Binding&) -> Binding& = delete;

        /** @brief 派生同一 credential owner 的 mux route view。 */
        [[nodiscard]] auto WithIngress(IngressRoute Route) const
            -> std::shared_ptr<IngressFactory>;

        [[nodiscard]] auto Begin(Prism::SharedTransmission Inbound) const
            -> std::expected<AcceptAttempt, Prism::Fault::Failure>
        {
            return Lifetime_->Begin(std::move(Inbound));
        }

        [[nodiscard]] auto Material() const noexcept -> std::shared_ptr<const PreparedBinding>
        {
            return Lifetime_->Material();
        }

        [[nodiscard]] auto GenerationUseState() const noexcept
            -> std::shared_ptr<Prism::Foundation::GenerationUseState>
        {
            return Lifetime_->UseState();
        }

        auto Close() const noexcept -> void { Lifetime_->Close(); }
        [[nodiscard]] auto Drain() const -> boost::asio::awaitable<
            std::expected<void, Prism::Fault::Failure>>
        {
            return Lifetime_->Drain();
        }
        [[nodiscard]] auto IsRetired() const noexcept -> bool { return Lifetime_->IsRetired(); }
        [[nodiscard]] auto DrainFailure() const noexcept -> Prism::Fault::Failure
        { return Lifetime_->DrainFailure(); }

    private:
        friend auto BindProvider(PreparedBinding) -> std::shared_ptr<const Binding>;
        friend class IngressFactory;

        explicit Binding(PreparedBinding Value) : Lifetime_(MakeLifetime(std::move(Value))) {}

        [[nodiscard]] static auto MakeLifetime(PreparedBinding Value) -> std::shared_ptr<Lifetime>
        {
            auto Material = std::make_shared<const PreparedBinding>(std::move(Value));
            return std::make_shared<Lifetime>(std::move(Material));
        }

        std::shared_ptr<Lifetime> Lifetime_;
    };

    [[nodiscard]] inline auto BindProvider(PreparedBinding Prepared)
        -> std::shared_ptr<const Binding>
    {
        return std::shared_ptr<const Binding>(new Binding(std::move(Prepared)));
    }

    [[nodiscard]] inline auto PrepareProviderBinding(ProviderRequest Request)
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
