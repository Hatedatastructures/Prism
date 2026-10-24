/** @file Binding.cpp @brief AnyTLS provider credential、投影 lease 与关闭实现。 */
#include <Prism/Protocols/Anytls/Binding.hpp>
#include <Prism/Account/Authenticator.hpp>

#include <memory>
#include <string>
#include <utility>

namespace Prism::Anytls
{
    [[nodiscard]] auto PrepareAccountCredential(std::string_view Value)
        ->Prism::Account::Credential
    {
        return Prism::Account::Credential::Password(Value);
    }

    auto Binding::Close() const noexcept -> void
    {
        State_->ProjectionGate.fetch_or(ClosedBit, std::memory_order_acq_rel);
    }

    [[nodiscard]] auto Binding::IsRetired() const noexcept -> bool
    {
        const auto Gate = State_->ProjectionGate.load(std::memory_order_acquire);
        return (Gate & ClosedBit) != 0U && (Gate & ProjectionMask) == 0U &&
            State_->Retired.load(std::memory_order_acquire);
    }

    Binding::Projection::Projection(Binding::Projection&& Other) noexcept : State_(std::move(Other.State_))
    {}

    auto Binding::Projection::operator=(Binding::Projection&& Other) noexcept -> Binding::Projection&
    {
        if (this != &Other)
        {
            Release();
            State_ = std::move(Other.State_);
        }
        return *this;
    }

    Binding::Projection::~Projection()
    { Release(); }

    auto Binding::Projection::Release() noexcept -> void
    {
        if (State_)
        {
            State_->ProjectionGate.fetch_sub(1U, std::memory_order_release);
            State_.reset();
        }
    }

    [[nodiscard]] auto Binding::BeginProjection() const noexcept -> std::optional<Binding::Projection>
    {
        auto Gate = State_->ProjectionGate.load(std::memory_order_acquire);
        while ((Gate & ClosedBit) == 0U)
        {
            if ((Gate & ProjectionMask) == ProjectionMask)
            {
                return std::nullopt;
            }
            if (State_->ProjectionGate.compare_exchange_weak(
                    Gate, Gate + 1U, std::memory_order_acq_rel, std::memory_order_acquire))
            {
                return Projection(State_);
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] auto Binding::Drain() const
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        Close();
        if (State_->Retired.load(std::memory_order_acquire))
        {
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        bool Expected = false;
        if (!State_->DrainInProgress.compare_exchange_strong(
                Expected, true, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
        }
        struct DrainRelease final
        {
            std::atomic<bool>& InProgress;
            ~DrainRelease() { InProgress.store(false, std::memory_order_release); }
        } Release{State_->DrainInProgress};
        if ((State_->ProjectionGate.load(std::memory_order_acquire) & ProjectionMask) != 0U)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        State_->Options.reset();
        State_->Retired.store(true, std::memory_order_release);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    Binding::Binding(IngressOptions Value)
        : State_(std::make_shared<State>(std::move(Value)))
    {
    }

    [[nodiscard]] auto PrepareProviderBinding(
        std::string Instance,
        Prism::Contract::AuthenticationServices Authentication,
        Prism::Contract::StreamServices Streams)
        -> std::expected<PreparedBinding, Prism::Contract::ProviderFailure>
    {
        if (!Authentication.Generation || !Authentication.Authenticator || !Authentication.Credentials)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::MissingAuthentication, {}, "Authentication"});
        }
        if (!Streams.Egress)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::MissingEgress, {}, "Streams.Egress"});
        }
        std::string Password;
        const auto Enumerated = Authentication.Credentials.ForEachCredential(
            Prism::Account::CredentialKind::Password,
            [&Password](const std::shared_ptr<const Prism::Account::AccountBinding>&,
                        const Prism::Account::CredentialMaterial& Material)
            {
                if (!Password.empty()) return;
                const auto Bytes = Material.Credential.View().Bytes();
                Password.assign(reinterpret_cast<const char*>(Bytes.data()), Bytes.size());
            });
        if (!Enumerated || Password.empty())
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::InvalidCredential, {}, "Authentication.Password"});
        }
        IngressOptions Options;
        Options.Configuration.Password = std::move(Password);
        Options.Authenticator = std::move(Authentication.Authenticator);
        Options.Streams = std::move(Streams);
        return PreparedBinding{std::move(Instance), std::move(Options)};
    }

    [[nodiscard]] auto BindProvider(PreparedBinding Prepared)
        -> std::shared_ptr<const Binding>
    {
        return std::make_shared<const Binding>(std::move(Prepared.Options));
    }
}
