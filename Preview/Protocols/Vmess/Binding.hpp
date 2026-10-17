/** @file Binding.hpp @brief VMess 冷认证、credential scope 与 session 退休 owner。 */
#pragma once

#include <Preview/Protocols/Vmess/Vmess.hpp>
#include <Preview/Protocols/Vmess/AuthId.hpp>
#include <Preview/Protocols/Common/ProviderBindingLifecycle.hpp>
#include <Preview/Protocols/Common/ProviderCredentials.hpp>
#include <Preview/Contract/Services/Authentication.hpp>
#include <Preview/Contract/Ingress/ProviderFailure.hpp>
#include <Preview/Account/Credential.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <stop_token>
#include <string_view>

namespace Preview::Vmess
{
    class IngressFactory;
    struct IngressRoute final
    {
        std::shared_ptr<Preview::Mux::RootBinding> Mux;
    };

    /** @brief 将标准 VMess UUID 文本转换为账户凭据，不把输入材料写入错误。 */
    [[nodiscard]] inline auto PrepareAccountCredential(const std::string_view Value)
        -> std::expected<Preview::Account::Credential, Preview::Contract::ProviderFailure>
    {
        std::array<std::uint8_t, 16> Parsed{};
        if (!Preview::Vmess::ParseUuid(Value, Parsed))
        {
            return std::unexpected(Preview::Contract::ProviderFailure{
                Preview::Contract::ProviderError::InvalidCredential, {}, "Credential.Uuid"});
        }
        Preview::Account::UuidBytes Bytes{};
        for (std::size_t Index = 0; Index < Bytes.size(); ++Index)
        {
            Bytes[Index] = static_cast<std::byte>(Parsed[Index]);
        }
        return Preview::Account::Credential::Uuid(Bytes);
    }

    struct ProviderRequest final
    {
        std::string Instance;
        Preview::Contract::AuthenticationServices Authentication;
        Preview::Contract::DatagramServices Datagrams;
        std::shared_ptr<Preview::Foundation::GenerationUseState> GenerationUseState;
        boost::asio::any_io_executor Executor;
        bool EnableUdp;
        bool EnableMux;
    };

    struct PreparedBinding final
    {
        std::string Instance;
        ServerConfig Configuration;
        Preview::SharedAuthenticator Authenticator;
        Preview::Account::CredentialIndexView Credentials;
        Preview::Contract::DatagramServices Datagrams;
        Preview::Foundation::GenerationPin Generation;
        std::shared_ptr<Preview::Foundation::GenerationUseState> GenerationUseState;
        boost::asio::any_io_executor Executor;
    };

    class Binding final : public std::enable_shared_from_this<Binding>
    {
        using Lifetime = Preview::Protocols::ProviderBindingLifecycle<PreparedBinding>;

    public:
        using AcceptAttempt = Lifetime::AcceptAttempt;

        ~Binding() { Close(); }
        Binding(const Binding&) = delete;
        auto operator=(const Binding&) -> Binding& = delete;

        /** @brief 派生同一 credential owner 的 mux route view。 */
        [[nodiscard]] auto WithIngress(IngressRoute Route) const
            -> std::shared_ptr<IngressFactory>;

        [[nodiscard]] auto Begin(Preview::SharedTransmission Inbound) const
            -> std::expected<AcceptAttempt, Preview::Fault::Failure>
        {
            return Lifetime_->Begin(std::move(Inbound));
        }

        [[nodiscard]] auto Material() const noexcept -> std::shared_ptr<const PreparedBinding>
        {
            return Lifetime_->Material();
        }

        [[nodiscard]] auto GenerationUseState() const noexcept
            -> std::shared_ptr<Preview::Foundation::GenerationUseState>
        {
            return Lifetime_->UseState();
        }

        auto Close() const noexcept -> void { Lifetime_->Close(); }
        [[nodiscard]] auto Drain() const -> boost::asio::awaitable<
            std::expected<void, Preview::Fault::Failure>>
        {
            return Lifetime_->Drain();
        }
        [[nodiscard]] auto IsRetired() const noexcept -> bool { return Lifetime_->IsRetired(); }
        [[nodiscard]] auto DrainFailure() const noexcept -> Preview::Fault::Failure
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
        -> std::expected<PreparedBinding, Preview::Contract::ProviderFailure>
    {
        if (!Request.Authentication.Generation || !Request.Authentication.Authenticator ||
            !Request.Authentication.Credentials)
        {
            return std::unexpected(Preview::Contract::ProviderFailure{
                Preview::Contract::ProviderError::MissingAuthentication, {}, "Authentication"});
        }
        if (!Request.GenerationUseState || !Request.Executor)
        {
            return std::unexpected(Preview::Contract::ProviderFailure{
                Preview::Contract::ProviderError::GenerationMismatch, Request.Instance,
                "Generation.UseState"});
        }
        const auto Uuid = Preview::Protocols::Common::FirstUuidCredential(
            Request.Authentication.Credentials);
        if (!Uuid)
        {
            return std::unexpected(Preview::Contract::ProviderFailure{
                Preview::Contract::ProviderError::InvalidCredential, Request.Instance,
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
