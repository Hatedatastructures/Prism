/** @file Binding.hpp @brief VLESS 冷 UUID、认证、generation 与接入退休 owner。 */
#pragma once

#include <Prism/Protocols/Vless/Vless.hpp>
#include <Prism/Protocols/Common/ProviderBindingLifecycle.hpp>
#include <Prism/Protocols/Common/ProviderCredentials.hpp>
#include <Prism/Contract/Services/Authentication.hpp>
#include <Prism/Contract/Ingress/ProviderFailure.hpp>
#include <Prism/Account/Credential.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <optional>
#include <stop_token>

namespace Prism::Vless
{
    class IngressFactory;
    struct IngressRoute final
    {
        std::shared_ptr<Prism::Mux::RootBinding> Mux;
        bool EnableUdp{true};
    };

    [[nodiscard]] inline auto ParseAccountUuid(std::string_view Value)
        -> std::optional<std::array<std::uint8_t, 16>>
    {
        std::array<std::uint8_t, 16> Result{};
        std::size_t Output = 0;
        int High = -1;
        for (const auto Character : Value)
        {
            if (Character == '-') continue;
            int Digit = -1;
            if (Character >= '0' && Character <= '9') Digit = Character - '0';
            if (Character >= 'a' && Character <= 'f') Digit = Character - 'a' + 10;
            if (Character >= 'A' && Character <= 'F') Digit = Character - 'A' + 10;
            if (Digit < 0 || Output >= Result.size()) return std::nullopt;
            if (High < 0) High = Digit;
            else
            {
                Result[Output++] = static_cast<std::uint8_t>((High << 4) | Digit);
                High = -1;
            }
        }
        if (Output != Result.size() || High >= 0) return std::nullopt;
        return Result;
    }

    [[nodiscard]] inline auto PrepareAccountCredential(std::string_view Value)
        -> std::expected<Prism::Account::Credential, Prism::Contract::ProviderFailure>
    {
        const auto Parsed = ParseAccountUuid(Value);
        if (!Parsed)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::InvalidCredential, {}, "Credential.Uuid"});
        }
        Prism::Account::UuidBytes Bytes{};
        for (std::size_t Index = 0; Index < Bytes.size(); ++Index)
        {
            Bytes[Index] = static_cast<std::byte>((*Parsed)[Index]);
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
    };

    struct PreparedBinding final
    {
        std::string Instance;
        ServerConfig Configuration;
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

        /** @brief 派生同一 prepared owner 的 route view；不会复制凭据或 generation state。 */
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

        explicit Binding(PreparedBinding Value)
            : Lifetime_(MakeLifetime(std::move(Value)))
        {
        }

        [[nodiscard]] static auto MakeLifetime(PreparedBinding Value)
            -> std::shared_ptr<Lifetime>
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
                Prism::Contract::ProviderError::InvalidCredential, {}, "Authentication.Uuid"});
        }
        ServerConfig Configuration;
        Configuration.uuid = *Uuid;
        Configuration.EnableUdp = Request.EnableUdp;
        Configuration.AuthenticatorOwner = Request.Authentication.Authenticator;
        return PreparedBinding{std::move(Request.Instance), std::move(Configuration),
            std::move(Request.Datagrams), Request.Authentication.Generation,
            std::move(Request.GenerationUseState), std::move(Request.Executor)};
    }
}
