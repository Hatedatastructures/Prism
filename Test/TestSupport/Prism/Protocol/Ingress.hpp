/** @file Ingress.hpp @brief TCP 协议测试按正式 Prepared/Binding 边界构造工厂。 */
#pragma once

#include <Prism/Protocols/Trojan/Binding.hpp>
#include <Prism/Protocols/Vless/Binding.hpp>
#include <Prism/Protocols/Vmess/Binding.hpp>
#include <Prism/Account/Account.hpp>
#include <Prism/Composition/Recognition/CandidateFactory.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>

#include <boost/asio/system_executor.hpp>
#include <boost/asio/any_io_executor.hpp>

#include <array>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace Prism::Testing
{
    class ProtocolIngressGeneration final : public Prism::Foundation::GenerationLifetime
    {
    public:
        explicit ProtocolIngressGeneration(Prism::GenerationId Value) : Value_(Value) {}

        auto Id() const noexcept -> Prism::GenerationId override
        {
            return Value_;
        }

    private:
        Prism::GenerationId Value_;
    };

    class ProtocolIngressAuthenticator final : public Prism::Authenticator
    {
    public:
        ProtocolIngressAuthenticator(std::shared_ptr<Prism::Account::AccountStore> Store,
            Prism::SharedAuthenticator Delegate,
            std::shared_ptr<Prism::Runtime::GenerationPublication> Publication)
            : Store_(std::move(Store)), Delegate_(std::move(Delegate)),
              Publication_(std::move(Publication)) {}

        [[nodiscard]] auto InspectCredential(const Prism::Account::CredentialView& Credential) const noexcept
            -> std::expected<bool, Prism::Fault::Failure> override
        {
            return Delegate_->InspectCredential(Credential);
        }

        [[nodiscard]] auto Authenticate(const Prism::AuthenticationRequest& Request) const noexcept
            -> Prism::AuthenticationResult override
        {
            return Delegate_->Authenticate(Request);
        }

    private:
        std::shared_ptr<Prism::Account::AccountStore> Store_;
        Prism::SharedAuthenticator Delegate_;
        std::shared_ptr<Prism::Runtime::GenerationPublication> Publication_;
    };

    struct ProtocolIngressAccounts final
    {
        std::shared_ptr<Prism::Account::AccountStore> Store;
        Prism::Account::CredentialIndexView Credentials;
        Prism::SharedAuthenticator Authenticator;
        Prism::Foundation::GenerationPin Generation;
        std::shared_ptr<Prism::Runtime::GenerationPublication> Publication;
        std::shared_ptr<Prism::Foundation::GenerationUseState> GenerationUseState;
    };

    struct ProtocolIngressAccountInput final
    {
        Prism::Account::Credential CredentialValue;
        Prism::AccountId Id;
        Prism::GenerationId GenerationId{1};
        std::shared_ptr<Prism::Foundation::GenerationUseState> GenerationUseState;
    };

    struct ProtocolIngressAccountSelection final
    {
        std::shared_ptr<ProtocolIngressAccounts> Accounts;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
        Prism::Account::Credential CredentialValue;
        Prism::AccountId Id;
    };

    struct ProtocolIngressResources final
    {
        Prism::Contract::DatagramServices Datagrams;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
        boost::asio::any_io_executor Executor;
        std::shared_ptr<ProtocolIngressAccounts> Accounts;
    };

    struct VmessIngressResources final
    {
        Prism::SharedAuthenticator Authenticator;
        Prism::Account::CredentialIndexView Credentials;
        Prism::Contract::DatagramServices Datagrams;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
        boost::asio::any_io_executor Executor;
        std::shared_ptr<ProtocolIngressAccounts> Accounts;
    };

    [[nodiscard]] inline auto MakeProtocolIngressUseState()
        -> std::shared_ptr<Prism::Foundation::GenerationUseState>
    {
        return std::make_shared<Prism::Foundation::GenerationUseState>();
    }

    [[nodiscard]] inline auto MakeProtocolIngressAccounts(ProtocolIngressAccountInput Input)
        -> std::shared_ptr<ProtocolIngressAccounts>
    {
        auto Accounts = std::make_shared<ProtocolIngressAccounts>();
        Accounts->Generation = std::make_shared<ProtocolIngressGeneration>(Input.GenerationId);
        if (Input.GenerationUseState)
        {
            Accounts->GenerationUseState = std::move(Input.GenerationUseState);
        }
        else
        {
            Accounts->GenerationUseState = MakeProtocolIngressUseState();
        }
        auto Provider = ProviderAccount(ProviderAccountInput{Input.Id, std::move(Input.CredentialValue),
            "protocol-ingress-fixture", "protocol-ingress-fixture", {}}, Accounts->Generation);
        Accounts->Store = Provider->Store;
        Accounts->Credentials = Provider->Credentials;
        Accounts->Publication = Provider->Publication;
        Accounts->Authenticator = std::make_shared<ProtocolIngressAuthenticator>(
            Accounts->Store, Provider->Authenticator, Accounts->Publication);
        return Accounts;
    }

    [[nodiscard]] inline auto ResolveProtocolIngressAccounts(ProtocolIngressAccountSelection Input)
        -> std::shared_ptr<ProtocolIngressAccounts>
    {
        if (Input.Accounts)
        {
            if (!Input.Accounts->Generation || !Input.Accounts->Publication ||
                !Input.Accounts->GenerationUseState)
            {
                throw std::runtime_error("protocol ingress account owner is incomplete");
            }
            if (Input.UseState && Input.UseState != Input.Accounts->GenerationUseState)
            {
                throw std::runtime_error("protocol ingress generation use state differs from account owner");
            }
            return Input.Accounts;
        }
        return MakeProtocolIngressAccounts(ProtocolIngressAccountInput{
            std::move(Input.CredentialValue), Input.Id, Prism::GenerationId{1}, std::move(Input.UseState)});
    }

    [[nodiscard]] inline auto MakeProtocolIngressUuidCredential(
        const std::array<std::uint8_t, 16>& Uuid) -> Prism::Account::Credential
    {
        Prism::Account::UuidBytes Bytes{};
        for (std::size_t Index = 0; Index < Bytes.size(); ++Index)
        {
            Bytes[Index] = static_cast<std::byte>(Uuid[Index]);
        }
        return Prism::Account::Credential::Uuid(Bytes);
    }

    [[nodiscard]] inline auto MakeVlessProviderBinding(
        Prism::Vless::ServerConfig Configuration,
        ProtocolIngressResources Resources)
        -> std::shared_ptr<const Prism::Vless::Binding>
    {
        auto Accounts = ResolveProtocolIngressAccounts(ProtocolIngressAccountSelection{
            Resources.Accounts, Resources.UseState,
            MakeProtocolIngressUuidCredential(Configuration.uuid), Prism::AccountId{1}});
        auto Authenticator = Configuration.AuthenticatorOwner;
        if (Authenticator)
        {
            Authenticator = std::make_shared<ProtocolIngressAuthenticator>(
                Accounts->Store, std::move(Authenticator), Accounts->Publication);
        }
        else Authenticator = Accounts->Authenticator;
        auto Prepared = Prism::Vless::PrepareProviderBinding(Prism::Vless::ProviderRequest{
            .Instance = "test-vless", .Authentication = {Accounts->Generation, Accounts->Credentials, Authenticator},
            .Datagrams = std::move(Resources.Datagrams), .GenerationUseState = Accounts->GenerationUseState,
            .Executor = std::move(Resources.Executor), .EnableUdp = Configuration.EnableUdp});
        if (!Prepared) throw std::runtime_error("VLESS provider binding prepare failed");
        return Prism::Vless::BindProvider(std::move(*Prepared));
    }

    [[nodiscard]] inline auto MakeVlessIngress(
        Prism::Vless::ServerConfig Configuration,
        ProtocolIngressResources Resources,
        Prism::Vless::IngressRoute Route)
        -> std::shared_ptr<Prism::Vless::IngressFactory>
    {
        auto Binding = MakeVlessProviderBinding(std::move(Configuration), std::move(Resources));
        auto Ingress = Binding->WithIngress(std::move(Route));
        if (!Ingress) throw std::runtime_error("VLESS provider ingress bind failed");
        return Ingress;
    }

    [[nodiscard]] inline auto MakeTrojanProviderBinding(
        Prism::Trojan::ServerConfig Configuration,
        ProtocolIngressResources Resources)
        -> std::shared_ptr<const Prism::Trojan::Binding>
    {
        auto Accounts = ResolveProtocolIngressAccounts(ProtocolIngressAccountSelection{
            Resources.Accounts, Resources.UseState,
            Prism::Trojan::PrepareAccountCredential(Configuration.Password), Prism::AccountId{1}});
        auto Authenticator = Configuration.AuthenticatorOwner;
        if (Authenticator)
        {
            Authenticator = std::make_shared<ProtocolIngressAuthenticator>(
                Accounts->Store, std::move(Authenticator), Accounts->Publication);
        }
        else Authenticator = Accounts->Authenticator;
        auto Prepared = Prism::Trojan::PrepareProviderBinding(Prism::Trojan::ProviderRequest{
            .Instance = "test-trojan", .Authentication = {Accounts->Generation, Accounts->Credentials, Authenticator},
            .Datagrams = std::move(Resources.Datagrams), .GenerationUseState = Accounts->GenerationUseState,
            .Executor = std::move(Resources.Executor), .EnableTcp = Configuration.EnableTcp,
            .EnableUdp = Configuration.EnableUdp, .EnableMux = Configuration.EnableMux});
        if (!Prepared) throw std::runtime_error("Trojan provider binding prepare failed");
        return Prism::Trojan::BindProvider(std::move(*Prepared));
    }

    [[nodiscard]] inline auto MakeTrojanIngress(
        Prism::Trojan::ServerConfig Configuration,
        ProtocolIngressResources Resources,
        Prism::Trojan::IngressRoute Route)
        -> std::shared_ptr<Prism::Trojan::IngressFactory>
    {
        auto Binding = MakeTrojanProviderBinding(std::move(Configuration), std::move(Resources));
        auto Ingress = Binding->WithIngress(std::move(Route));
        if (!Ingress) throw std::runtime_error("Trojan provider ingress bind failed");
        return Ingress;
    }

    [[nodiscard]] inline auto MakeVmessProviderBinding(
        Prism::Vmess::ServerConfig Configuration,
        VmessIngressResources Resources)
        -> std::shared_ptr<const Prism::Vmess::Binding>
    {
        auto Accounts = ResolveProtocolIngressAccounts(ProtocolIngressAccountSelection{
            Resources.Accounts, Resources.UseState,
            MakeProtocolIngressUuidCredential(Configuration.uuid), Prism::AccountId{1}});
        if (!Resources.Credentials) Resources.Credentials = Accounts->Credentials;
        if (!Resources.Authenticator) Resources.Authenticator = Configuration.AuthenticatorOwner;
        if (Resources.Authenticator)
        {
            Resources.Authenticator = std::make_shared<ProtocolIngressAuthenticator>(
                Accounts->Store, std::move(Resources.Authenticator), Accounts->Publication);
        }
        else Resources.Authenticator = Accounts->Authenticator;
        auto Prepared = Prism::Vmess::PrepareProviderBinding(Prism::Vmess::ProviderRequest{
            .Instance = "test-vmess", .Authentication = {Accounts->Generation, Resources.Credentials, Resources.Authenticator},
            .Datagrams = std::move(Resources.Datagrams), .GenerationUseState = Accounts->GenerationUseState,
            .Executor = std::move(Resources.Executor), .EnableUdp = Configuration.EnableUdp,
            .EnableMux = Configuration.EnableMux});
        if (!Prepared) throw std::runtime_error("VMess provider binding prepare failed");
        return Prism::Vmess::BindProvider(std::move(*Prepared));
    }

    [[nodiscard]] inline auto MakeVmessIngress(
        Prism::Vmess::ServerConfig Configuration,
        VmessIngressResources Resources,
        Prism::Vmess::IngressRoute Route)
        -> std::shared_ptr<Prism::Vmess::IngressFactory>
    {
        auto Binding = MakeVmessProviderBinding(std::move(Configuration), std::move(Resources));
        auto Ingress = Binding->WithIngress(std::move(Route));
        if (!Ingress) throw std::runtime_error("VMess provider ingress bind failed");
        return Ingress;
    }

    [[nodiscard]] inline auto MakeVlessCandidate(
        Prism::Composition::Recognition::CandidateOptions Options,
        Prism::Vless::ServerConfig Configuration,
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState)
        -> Prism::Composition::Recognition::CandidateBinding;

    [[nodiscard]] inline auto MakeTrojanCandidate(
        Prism::Composition::Recognition::CandidateOptions Options,
        Prism::Trojan::ServerConfig Configuration,
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState)
        -> Prism::Composition::Recognition::CandidateBinding;

    [[nodiscard]] inline auto MakeVmessCandidate(
        Prism::Composition::Recognition::CandidateOptions Options,
        Prism::Vmess::ServerConfig Configuration,
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState)
        -> Prism::Composition::Recognition::CandidateBinding;

    [[nodiscard]] inline auto MakeVlessCandidate(
        Prism::Composition::Recognition::CandidateOptions Options,
        Prism::Vless::ServerConfig Configuration)
        -> Prism::Composition::Recognition::CandidateBinding
    {
        return MakeVlessCandidate(std::move(Options), std::move(Configuration),
            MakeProtocolIngressUseState());
    }

    [[nodiscard]] inline auto MakeVlessCandidate(
        Prism::Composition::Recognition::CandidateOptions Options,
        Prism::Vless::ServerConfig Configuration,
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState)
        -> Prism::Composition::Recognition::CandidateBinding
    {
        auto Binding = MakeVlessProviderBinding(std::move(Configuration),
            ProtocolIngressResources{{}, UseState, boost::asio::system_executor()});
        auto Candidate = Prism::Composition::Recognition::CandidateFactory::MakeVless(
            std::move(Options), std::move(Binding), std::nullopt);
        if (!Candidate) throw std::runtime_error("VLESS recognition owner is closed");
        return std::move(*Candidate);
    }

    [[nodiscard]] inline auto MakeTrojanCandidate(
        Prism::Composition::Recognition::CandidateOptions Options,
        Prism::Trojan::ServerConfig Configuration)
        -> Prism::Composition::Recognition::CandidateBinding
    {
        return MakeTrojanCandidate(std::move(Options), std::move(Configuration),
            MakeProtocolIngressUseState());
    }

    [[nodiscard]] inline auto MakeTrojanCandidate(
        Prism::Composition::Recognition::CandidateOptions Options,
        Prism::Trojan::ServerConfig Configuration,
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState)
        -> Prism::Composition::Recognition::CandidateBinding
    {
        auto Binding = MakeTrojanProviderBinding(std::move(Configuration),
            ProtocolIngressResources{{}, UseState, boost::asio::system_executor()});
        auto Candidate = Prism::Composition::Recognition::CandidateFactory::MakeTrojan(
            std::move(Options), std::move(Binding), std::nullopt);
        if (!Candidate) throw std::runtime_error("Trojan recognition owner is closed");
        return std::move(*Candidate);
    }

    [[nodiscard]] inline auto MakeVmessCandidate(
        Prism::Composition::Recognition::CandidateOptions Options,
        Prism::Vmess::ServerConfig Configuration)
        -> Prism::Composition::Recognition::CandidateBinding
    {
        return MakeVmessCandidate(std::move(Options), std::move(Configuration),
            MakeProtocolIngressUseState());
    }

    [[nodiscard]] inline auto MakeVmessCandidate(
        Prism::Composition::Recognition::CandidateOptions Options,
        Prism::Vmess::ServerConfig Configuration,
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState)
        -> Prism::Composition::Recognition::CandidateBinding
    {
        auto Binding = MakeVmessProviderBinding(std::move(Configuration),
            VmessIngressResources{{}, {}, {}, UseState, boost::asio::system_executor()});
        auto Candidate = Prism::Composition::Recognition::CandidateFactory::MakeVmess(
            std::move(Options), std::move(Binding), std::nullopt);
        if (!Candidate) throw std::runtime_error("VMess recognition owner is closed");
        return std::move(*Candidate);
    }
}
