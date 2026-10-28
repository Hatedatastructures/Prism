/**
 * @file IngressFactory.cpp
 * @brief TrustTunnel 认证传输与入口接入实现。
 */

#include <Prism/Protocols/Trusttunnel/IngressFactory.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/AcceptedCarrierActivity.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/CarrierOwner.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2/Transport.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/WireAuthBinding.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <charconv>
#include <exception>
#include <new>
#include <utility>

namespace Prism::Trusttunnel
{
    WireAuthBinding::WireAuthBinding(
        ServerConfig ConfigurationValue,
        Prism::SharedAuthenticator AuthenticatorValue)
        : Configuration(std::move(ConfigurationValue)),
          Credential(Configuration.username + ":" + Configuration.password),
          Authenticator(std::move(AuthenticatorValue))
    {
    }

    auto MakeWireAuthBinding(
        ServerConfig Configuration,
        Prism::SharedAuthenticator Authenticator)
        -> std::shared_ptr<const WireAuthBinding>
    {
        return std::shared_ptr<const WireAuthBinding>(
            new WireAuthBinding(std::move(Configuration), std::move(Authenticator)));
    }

    auto AuthenticatedTransport::IsOpen() const -> bool
    {
        return !Owner_->IsRetired() && Owner_->Transport && Owner_->Transport->IsOpen();
    }

    auto AuthenticatedTransport::NextLayer() noexcept -> Prism::Transmission *
    {
        return Owner_->Transport.get();
    }

    auto AuthenticatedTransport::NextLayer() const noexcept
        -> const Prism::Transmission *
    {
        return Owner_->Transport.get();
    }

    auto AuthenticatedTransport::Binding() const noexcept -> const SharedWireAuthBinding &
    {
        return Owner_->Binding;
    }

    auto AuthenticatedTransport::StartRead(std::span<std::byte> Buffer, Completion Handler) -> void
    {
        if (Owner_->IsRetired() || !Owner_->Transport)
        {
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), {0, {Prism::Fault::Code::Canceled}});
            return;
        }
        Owner_->Transport->ReadSome(Buffer, std::move(Handler));
    }

    auto AuthenticatedTransport::StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void
    {
        if (Owner_->IsRetired() || !Owner_->Transport)
        {
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), {0, {Prism::Fault::Code::Canceled}});
            return;
        }
        Owner_->Transport->WriteSome(Buffer, std::move(Handler));
    }

    auto AuthenticatedTransport::StartWriteShutdown(Completion Handler) -> void
    {
        Owner_->WriteShutdown(std::move(Handler));
    }

    auto AuthenticatedTransport::OnClose() -> ControlResult
    {
        return Owner_->Close();
    }

    auto AuthenticatedTransport::OnCancel() -> ControlResult
    {
        return Owner_->Cancel();
    }

    auto AuthenticatedTransport::SetTimeout(const std::chrono::milliseconds Timeout) -> void
    {
        if (Owner_->Transport) Owner_->Transport->SetTimeout(Timeout);
    }

    AuthenticatedTransport::AuthenticatedTransport(std::shared_ptr<Detail::CarrierOwner> Owner,
                           std::string Authority)
        : Prism::Transmission(
              Owner->Executor()),
          Executor_(Owner->Executor()), Owner_(std::move(Owner)),
          Authority_(std::move(Authority)),
          Activity_(std::make_shared<Detail::AcceptedCarrierActivity<Detail::CarrierOwner>>(
              Prism::Transmission::Activity(), Owner_, CloseReceipt()))
    {
    }

    auto AuthenticatedTransport::CreateForHandshake(
        std::shared_ptr<Detail::CarrierOwner> Owner,
        std::string Authority)
        -> std::shared_ptr<AuthenticatedTransport>
    {
        if (!Owner || !Owner->Transport || Authority.empty() || !Owner->Binding)
        {
            return {};
        }
        return std::shared_ptr<AuthenticatedTransport>(
            new AuthenticatedTransport(std::move(Owner), std::move(Authority)));
    }

    auto IngressFactory::Accept(Prism::Contract::StreamAcceptInput Input)
        -> Net::awaitable<std::expected<
            Prism::Contract::ProtocolDataPlane, Prism::Fault::Failure>>
    {
        auto Inbound = std::move(Input.Inbound);
        auto Bytes = std::move(Input.Bytes);
        if (!Inbound)
        {
            co_return std::unexpected(ToAdmissionFailure(Prism::Error::Unsupported));
        }
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Inbound);
        if (!Prepared) co_return std::unexpected(Prepared.error());
        auto Admission = std::move(*Prepared);
        std::exception_ptr Fatal;
        try
        {
            if (!Bytes)
            {
                co_return co_await Admission.Reject(ToAdmissionFailure(Prism::Error::IoError));
            }
            const auto Proof = std::dynamic_pointer_cast<AuthenticatedTransport>(Inbound);
            if (!Proof)
            {
                co_return co_await Admission.Reject(ToAdmissionFailure(Prism::Error::Unsupported));
            }
            if (!Options_.Binding || Proof->Binding().get() != Options_.Binding.get())
            {
                co_return co_await Admission.Reject(ToAdmissionFailure(Prism::Error::Unsupported));
            }

            const auto &Binding = *Options_.Binding;
            if (!Binding.Authenticator)
            {
                co_return co_await Admission.Reject(ToAdmissionFailure(Prism::Error::BadAuth));
            }

            const auto Target = ParseAuthority(Proof->Authority());
            if (!Target)
            {
                co_return co_await Admission.Reject(ToAdmissionFailure(Prism::Error::BadAddress));
            }

            auto Authentication = Binding.Authenticator->Authenticate(
                Prism::AuthenticationRequest{
                    .AccountId = {},
                    .Identity = Binding.Configuration.username,
                    .Credential = Prism::Account::CredentialView::Password(Binding.Credential),
                    .Rate = {}});
            if (!Authentication || !Authentication->AccountId())
            {
                co_return co_await Admission.Reject(ToAdmissionFailure(Prism::Error::BadAuth));
            }

            Prism::Contract::ProtocolDataPlane Plane;
            Plane.Protocol = Prism::Contract::ProtocolType::TrustTunnel;
            auto Host = Prism::Network::ParseHost(Target->Host);
            if (!Host)
                co_return co_await Admission.Reject(ToAdmissionFailure(Prism::Error::BadAddress));
            Plane.Target = {std::move(*Host), Target->Port, Prism::Network::RouteKind::Forward};
            Plane.ProtocolAuthenticated = true;
            Plane.AccountId = Authentication->AccountId();
            Plane.Identity = std::string(Authentication->Identity());
            Plane.DisplayIdentity = std::string(Authentication->DisplayIdentity());
            Plane.AccountLease = std::move(*Authentication);
            Plane.Root = Prism::Contract::StreamDataPlane{std::move(Inbound)};

            co_return co_await Admission.Admit(std::move(Plane));
        }
        catch (const std::bad_alloc &)
        {
            Fatal = std::current_exception();
        }
        co_return co_await Admission.Reject(
            Prism::Contract::InboundAdmission::ExceptionFailure(std::move(Fatal)));
    }

    auto IngressFactory::ToAdmissionFailure(const Prism::Error Error) noexcept -> Failure
    {
        return {Prism::Fault::ToCode(Prism::make_error_code(Error))};
    }

    auto IngressFactory::ParseAuthority(const std::string_view Value)
        -> std::optional<Authority>
    {
        if (Value.empty())
        {
            return std::nullopt;
        }
        std::string_view Host;
        std::string_view PortText;
        if (Value.front() == '[')
        {
            const auto Close = Value.find(']');
            if (Close == std::string_view::npos || Close + 2U > Value.size() ||
                Value[Close + 1U] != ':')
            {
                return std::nullopt;
            }
            Host = Value.substr(1U, Close - 1U);
            PortText = Value.substr(Close + 2U);
        }
        else
        {
            const auto Colon = Value.rfind(':');
            if (Colon == std::string_view::npos || Value.find(':') != Colon)
            {
                return std::nullopt;
            }
            Host = Value.substr(0, Colon);
            PortText = Value.substr(Colon + 1U);
        }

        std::uint32_t Port = 0;
        const auto [End, Error] = std::from_chars(
            PortText.data(), PortText.data() + PortText.size(), Port);
        if (Host.empty() || Port == 0U || Port > 65535U || Error != std::errc{} ||
            End != PortText.data() + PortText.size())
        {
            return std::nullopt;
        }
        return Authority{std::string(Host), static_cast<std::uint16_t>(Port)};
    }
} // namespace Prism::Trusttunnel
