/** @file ProtocolIngressBindings.hpp @brief TCP 协议测试按正式 Prepared/Binding 边界构造工厂。 */
#pragma once

#include <Preview/Protocols/Trojan/Binding.hpp>
#include <Preview/Protocols/Vless/Binding.hpp>
#include <Preview/Protocols/Vmess/Binding.hpp>
#include <Preview/Account/Account.hpp>
#include <Preview/Composition/Recognition/CandidateFactory.hpp>
#include <TestSupport/Preview/ProviderBindings.hpp>

#include <boost/asio/system_executor.hpp>
#include <boost/asio/any_io_executor.hpp>

#include <array>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace Preview::Testing
{
    class ProtocolIngressGeneration final : public Preview::Foundation::GenerationLifetime
    {
    public:
        explicit ProtocolIngressGeneration(Preview::GenerationId Value) : Value_(Value) {}

        auto Id() const noexcept -> Preview::GenerationId override
        {
            return Value_;
        }

    private:
        Preview::GenerationId Value_;
    };

    class ProtocolIngressAuthenticator final : public Preview::Authenticator
    {
    public:
        ProtocolIngressAuthenticator(std::shared_ptr<Preview::Account::AccountStore> Store,
            Preview::SharedAuthenticator Delegate,
            std::shared_ptr<Preview::Runtime::GenerationPublication> Publication)
            : Store_(std::move(Store)), Delegate_(std::move(Delegate)),
              Publication_(std::move(Publication)) {}

        [[nodiscard]] auto InspectCredential(const Preview::Account::CredentialView& Credential) const noexcept
            -> std::expected<bool, Preview::Fault::Failure> override
        {
            return Delegate_->InspectCredential(Credential);
        }

        [[nodiscard]] auto Authenticate(const Preview::AuthenticationRequest& Request) const noexcept
            -> Preview::AuthenticationResult override
        {
            return Delegate_->Authenticate(Request);
        }

    private:
        std::shared_ptr<Preview::Account::AccountStore> Store_;
        Preview::SharedAuthenticator Delegate_;
        std::shared_ptr<Preview::Runtime::GenerationPublication> Publication_;
    };

    struct ProtocolIngressAccounts final
    {
        std::shared_ptr<Preview::Account::AccountStore> Store;
        Preview::Account::CredentialIndexView Credentials;
        Preview::SharedAuthenticator Authenticator;
        Preview::Foundation::GenerationPin Generation;
        std::shared_ptr<Preview::Runtime::GenerationPublication> Publication;
        std::shared_ptr<Preview::Foundation::GenerationUseState> GenerationUseState;
    };

    struct ProtocolIngressAccountInput final
    {
        Preview::Account::Credential CredentialValue;
        Preview::AccountId Id;
        Preview::GenerationId GenerationId{1};
        std::shared_ptr<Preview::Foundation::GenerationUseState> GenerationUseState;
    };

    struct ProtocolIngressAccountSelection final
    {
        std::shared_ptr<ProtocolIngressAccounts> Accounts;
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState;
        Preview::Account::Credential CredentialValue;
        Preview::AccountId Id;
    };

    struct ProtocolIngressResources final
    {
        Preview::Contract::DatagramServices Datagrams;
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState;
        boost::asio::any_io_executor Executor;
        std::shared_ptr<ProtocolIngressAccounts> Accounts;
    };

    struct VmessIngressResources final
    {
        Preview::SharedAuthenticator Authenticator;
        Preview::Account::CredentialIndexView Credentials;
        Preview::Contract::DatagramServices Datagrams;
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState;
        boost::asio::any_io_executor Executor;
        std::shared_ptr<ProtocolIngressAccounts> Accounts;
    };

    [[nodiscard]] inline auto MakeProtocolIngressUseState()
        -> std::shared_ptr<Preview::Foundation::GenerationUseState>
    {
        return std::make_shared<Preview::Foundation::GenerationUseState>();
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
            std::move(Input.CredentialValue), Input.Id, Preview::GenerationId{1}, std::move(Input.UseState)});
    }

    [[nodiscard]] inline auto MakeProtocolIngressUuidCredential(
        const std::array<std::uint8_t, 16>& Uuid) -> Preview::Account::Credential
    {
        Preview::Account::UuidBytes Bytes{};
        for (std::size_t Index = 0; Index < Bytes.size(); ++Index)
        {
            Bytes[Index] = static_cast<std::byte>(Uuid[Index]);
        }
        return Preview::Account::Credential::Uuid(Bytes);
    }

    [[nodiscard]] inline auto MakeVlessProviderBinding(
        Preview::Vless::ServerConfig Configuration,
        ProtocolIngressResources Resources)
        -> std::shared_ptr<const Preview::Vless::Binding>
    {
        auto Accounts = ResolveProtocolIngressAccounts(ProtocolIngressAccountSelection{
            Resources.Accounts, Resources.UseState,
            MakeProtocolIngressUuidCredential(Configuration.uuid), Preview::AccountId{1}});
        auto Authenticator = Configuration.AuthenticatorOwner;
        if (Authenticator)
        {
            Authenticator = std::make_shared<ProtocolIngressAuthenticator>(
                Accounts->Store, std::move(Authenticator), Accounts->Publication);
        }
        else Authenticator = Accounts->Authenticator;
        auto Prepared = Preview::Vless::PrepareProviderBinding(Preview::Vless::ProviderRequest{
            .Instance = "test-vless", .Authentication = {Accounts->Generation, Accounts->Credentials, Authenticator},
            .Datagrams = std::move(Resources.Datagrams), .GenerationUseState = Accounts->GenerationUseState,
            .Executor = std::move(Resources.Executor), .EnableUdp = Configuration.EnableUdp});
        if (!Prepared) throw std::runtime_error("VLESS provider binding prepare failed");
        return Preview::Vless::BindProvider(std::move(*Prepared));
    }

    [[nodiscard]] inline auto MakeVlessIngress(
        Preview::Vless::ServerConfig Configuration,
        ProtocolIngressResources Resources,
        Preview::Vless::IngressRoute Route)
        -> std::shared_ptr<Preview::Vless::IngressFactory>
    {
        auto Binding = MakeVlessProviderBinding(std::move(Configuration), std::move(Resources));
        auto Ingress = Binding->WithIngress(std::move(Route));
        if (!Ingress) throw std::runtime_error("VLESS provider ingress bind failed");
        return Ingress;
    }

    [[nodiscard]] inline auto MakeTrojanProviderBinding(
        Preview::Trojan::ServerConfig Configuration,
        ProtocolIngressResources Resources)
        -> std::shared_ptr<const Preview::Trojan::Binding>
    {
        auto Accounts = ResolveProtocolIngressAccounts(ProtocolIngressAccountSelection{
            Resources.Accounts, Resources.UseState,
            Preview::Trojan::PrepareAccountCredential(Configuration.Password), Preview::AccountId{1}});
        auto Authenticator = Configuration.AuthenticatorOwner;
        if (Authenticator)
        {
            Authenticator = std::make_shared<ProtocolIngressAuthenticator>(
                Accounts->Store, std::move(Authenticator), Accounts->Publication);
        }
        else Authenticator = Accounts->Authenticator;
        auto Prepared = Preview::Trojan::PrepareProviderBinding(Preview::Trojan::ProviderRequest{
            .Instance = "test-trojan", .Authentication = {Accounts->Generation, Accounts->Credentials, Authenticator},
            .Datagrams = std::move(Resources.Datagrams), .GenerationUseState = Accounts->GenerationUseState,
            .Executor = std::move(Resources.Executor), .EnableTcp = Configuration.EnableTcp,
            .EnableUdp = Configuration.EnableUdp, .EnableMux = Configuration.EnableMux});
        if (!Prepared) throw std::runtime_error("Trojan provider binding prepare failed");
        return Preview::Trojan::BindProvider(std::move(*Prepared));
    }

    [[nodiscard]] inline auto MakeTrojanIngress(
        Preview::Trojan::ServerConfig Configuration,
        ProtocolIngressResources Resources,
        Preview::Trojan::IngressRoute Route)
        -> std::shared_ptr<Preview::Trojan::IngressFactory>
    {
        auto Binding = MakeTrojanProviderBinding(std::move(Configuration), std::move(Resources));
        auto Ingress = Binding->WithIngress(std::move(Route));
        if (!Ingress) throw std::runtime_error("Trojan provider ingress bind failed");
        return Ingress;
    }

    [[nodiscard]] inline auto MakeVmessProviderBinding(
        Preview::Vmess::ServerConfig Configuration,
        VmessIngressResources Resources)
        -> std::shared_ptr<const Preview::Vmess::Binding>
    {
        auto Accounts = ResolveProtocolIngressAccounts(ProtocolIngressAccountSelection{
            Resources.Accounts, Resources.UseState,
            MakeProtocolIngressUuidCredential(Configuration.uuid), Preview::AccountId{1}});
        if (!Resources.Credentials) Resources.Credentials = Accounts->Credentials;
        if (!Resources.Authenticator) Resources.Authenticator = Configuration.AuthenticatorOwner;
        if (Resources.Authenticator)
        {
            Resources.Authenticator = std::make_shared<ProtocolIngressAuthenticator>(
                Accounts->Store, std::move(Resources.Authenticator), Accounts->Publication);
        }
        else Resources.Authenticator = Accounts->Authenticator;
        auto Prepared = Preview::Vmess::PrepareProviderBinding(Preview::Vmess::ProviderRequest{
            .Instance = "test-vmess", .Authentication = {Accounts->Generation, Resources.Credentials, Resources.Authenticator},
            .Datagrams = std::move(Resources.Datagrams), .GenerationUseState = Accounts->GenerationUseState,
            .Executor = std::move(Resources.Executor), .EnableUdp = Configuration.EnableUdp,
            .EnableMux = Configuration.EnableMux});
        if (!Prepared) throw std::runtime_error("VMess provider binding prepare failed");
        return Preview::Vmess::BindProvider(std::move(*Prepared));
    }

    [[nodiscard]] inline auto MakeVmessIngress(
        Preview::Vmess::ServerConfig Configuration,
        VmessIngressResources Resources,
        Preview::Vmess::IngressRoute Route)
        -> std::shared_ptr<Preview::Vmess::IngressFactory>
    {
        auto Binding = MakeVmessProviderBinding(std::move(Configuration), std::move(Resources));
        auto Ingress = Binding->WithIngress(std::move(Route));
        if (!Ingress) throw std::runtime_error("VMess provider ingress bind failed");
        return Ingress;
    }

    [[nodiscard]] inline auto MakeVlessCandidate(
        Preview::Composition::Recognition::CandidateOptions Options,
        Preview::Vless::ServerConfig Configuration,
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState)
        -> Preview::Composition::Recognition::CandidateBinding;

    [[nodiscard]] inline auto MakeTrojanCandidate(
        Preview::Composition::Recognition::CandidateOptions Options,
        Preview::Trojan::ServerConfig Configuration,
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState)
        -> Preview::Composition::Recognition::CandidateBinding;

    [[nodiscard]] inline auto MakeVmessCandidate(
        Preview::Composition::Recognition::CandidateOptions Options,
        Preview::Vmess::ServerConfig Configuration,
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState)
        -> Preview::Composition::Recognition::CandidateBinding;

    [[nodiscard]] inline auto MakeVlessCandidate(
        Preview::Composition::Recognition::CandidateOptions Options,
        Preview::Vless::ServerConfig Configuration)
        -> Preview::Composition::Recognition::CandidateBinding
    {
        return MakeVlessCandidate(std::move(Options), std::move(Configuration),
            MakeProtocolIngressUseState());
    }

    [[nodiscard]] inline auto MakeVlessCandidate(
        Preview::Composition::Recognition::CandidateOptions Options,
        Preview::Vless::ServerConfig Configuration,
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState)
        -> Preview::Composition::Recognition::CandidateBinding
    {
        auto Binding = MakeVlessProviderBinding(std::move(Configuration),
            ProtocolIngressResources{{}, UseState, boost::asio::system_executor()});
        auto Candidate = Preview::Composition::Recognition::CandidateFactory::MakeVless(
            std::move(Options), std::move(Binding), std::nullopt);
        if (!Candidate) throw std::runtime_error("VLESS recognition owner is closed");
        return std::move(*Candidate);
    }

    [[nodiscard]] inline auto MakeTrojanCandidate(
        Preview::Composition::Recognition::CandidateOptions Options,
        Preview::Trojan::ServerConfig Configuration)
        -> Preview::Composition::Recognition::CandidateBinding
    {
        return MakeTrojanCandidate(std::move(Options), std::move(Configuration),
            MakeProtocolIngressUseState());
    }

    [[nodiscard]] inline auto MakeTrojanCandidate(
        Preview::Composition::Recognition::CandidateOptions Options,
        Preview::Trojan::ServerConfig Configuration,
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState)
        -> Preview::Composition::Recognition::CandidateBinding
    {
        auto Binding = MakeTrojanProviderBinding(std::move(Configuration),
            ProtocolIngressResources{{}, UseState, boost::asio::system_executor()});
        auto Candidate = Preview::Composition::Recognition::CandidateFactory::MakeTrojan(
            std::move(Options), std::move(Binding), std::nullopt);
        if (!Candidate) throw std::runtime_error("Trojan recognition owner is closed");
        return std::move(*Candidate);
    }

    [[nodiscard]] inline auto MakeVmessCandidate(
        Preview::Composition::Recognition::CandidateOptions Options,
        Preview::Vmess::ServerConfig Configuration)
        -> Preview::Composition::Recognition::CandidateBinding
    {
        return MakeVmessCandidate(std::move(Options), std::move(Configuration),
            MakeProtocolIngressUseState());
    }

    [[nodiscard]] inline auto MakeVmessCandidate(
        Preview::Composition::Recognition::CandidateOptions Options,
        Preview::Vmess::ServerConfig Configuration,
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState)
        -> Preview::Composition::Recognition::CandidateBinding
    {
        auto Binding = MakeVmessProviderBinding(std::move(Configuration),
            VmessIngressResources{{}, {}, {}, UseState, boost::asio::system_executor()});
        auto Candidate = Preview::Composition::Recognition::CandidateFactory::MakeVmess(
            std::move(Options), std::move(Binding), std::nullopt);
        if (!Candidate) throw std::runtime_error("VMess recognition owner is closed");
        return std::move(*Candidate);
    }
}
