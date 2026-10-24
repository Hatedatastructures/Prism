/** @file Binding.hpp @brief VMess 冷认证、credential scope 与 session 退休 owner。 */
#pragma once

#include <Prism/Account/Credential.hpp>
#include <Prism/Contract/Ingress/ProviderFailure.hpp>
#include <Prism/Contract/Services/Authentication.hpp>
#include <Prism/Contract/Services/Datagram.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Protocols/Mux/RootBinding.hpp>
#include <Prism/Protocols/ProviderLifecycle/ProviderBindingLifecycle.hpp>
#include <Prism/Protocols/Vmess/Vmess.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <expected>
#include <memory>
#include <string>
#include <string_view>

namespace Prism::Vmess
{
    class IngressFactory;
    struct IngressRoute final
    {
        std::shared_ptr<Prism::Mux::RootBinding> Mux;
    };

    /** @brief 将标准 VMess UUID 文本封装为正式 UUID 凭据。 */
    [[nodiscard]] auto PrepareAccountCredential(const std::string_view Value)
        -> std::expected<Prism::Account::Credential, Prism::Contract::ProviderFailure>;

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

        ~Binding();
        Binding(const Binding&) = delete;
        auto operator=(const Binding&) -> Binding& = delete;

        /** @brief 派生同一 credential owner 的 mux route view。 */
        [[nodiscard]] auto WithIngress(IngressRoute Route) const
            -> std::shared_ptr<IngressFactory>;

        [[nodiscard]] auto Begin(Prism::SharedTransmission Inbound) const
            -> std::expected<AcceptAttempt, Prism::Fault::Failure>;

        [[nodiscard]] auto Material() const noexcept -> std::shared_ptr<const PreparedBinding>
        {
            return Lifetime_->Material();
        }

        [[nodiscard]] auto GenerationUseState() const noexcept
            -> std::shared_ptr<Prism::Foundation::GenerationUseState>
        {
            return Lifetime_->UseState();
        }

        auto Close() const noexcept -> void;
        [[nodiscard]] auto Drain() const -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;
        [[nodiscard]] auto IsRetired() const noexcept -> bool { return Lifetime_->IsRetired(); }
        [[nodiscard]] auto DrainFailure() const noexcept -> Prism::Fault::Failure
        { return Lifetime_->DrainFailure(); }

    private:
        friend auto BindProvider(PreparedBinding) -> std::shared_ptr<const Binding>;
        friend class IngressFactory;

        explicit Binding(PreparedBinding Value);

        [[nodiscard]] static auto MakeLifetime(PreparedBinding Value)
            -> std::shared_ptr<Lifetime>;

        std::shared_ptr<Lifetime> Lifetime_;
    };

    /** @brief 为已校验 provider 材料创建唯一共享 binding owner。 */
    [[nodiscard]] auto BindProvider(PreparedBinding Prepared) -> std::shared_ptr<const Binding>;

    /** @brief 校验认证/generation 服务并选择唯一 UUID 凭据。 */
    [[nodiscard]] auto PrepareProviderBinding(ProviderRequest Request)
        -> std::expected<PreparedBinding, Prism::Contract::ProviderFailure>;
}
