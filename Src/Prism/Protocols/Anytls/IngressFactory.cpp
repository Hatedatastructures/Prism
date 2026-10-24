/** @file IngressFactory.cpp @brief AnyTLS admission 与 session 发布实现。 */
#include <Prism/Protocols/Anytls/IngressFactory.hpp>

#include <Prism/Protocols/Anytls/Detail/Session/Retirement.hpp>
#include <Prism/Protocols/Anytls/Detail/Session/Session.hpp>
#include <Prism/Protocols/Anytls/Detail/Session/State.hpp>
#include <Prism/Contract/Ingress/AdmissionTransportRetirement.hpp>
#include <Prism/Contract/Ingress/MuxRootCreateRequest.hpp>

#include <boost/asio/this_coro.hpp>

#include <exception>
#include <memory>
#include <string>
#include <utility>

namespace Prism::Anytls::Detail
{

    auto RetireUnreservedWithFailure(const Prism::SharedTransmission& Inbound,
        Prism::Fault::Failure Primary) -> Net::awaitable<Prism::Fault::Failure>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        bool CancelAttempted = false;
        bool CloseAttempted = false;
        const auto Cleanup = co_await Prism::Contract::RetireAdmissionTransport(
            Inbound, CancelAttempted, CloseAttempted);
        if (!Primary.Failed() && Cleanup.Error.Failed())
        {
            Primary = Cleanup.Error;
        }
        co_return Primary;
    }

    auto RetireWithFailure(const std::shared_ptr<TransportRetirement>& Retirement,
        Prism::Fault::Failure Primary) -> Net::awaitable<Prism::Fault::Failure>
    {
        Retirement->RetainForRetry();
        try
        {
            const auto Retired = co_await Retirement->RetireAndDrain();
            if (!Retired && !Primary.Failed())
            {
                Primary = Retired.error();
            }
        }
        catch (...)
        {
            Retirement->RequestRetirement();
            const auto Cleanup = FailureFromException(std::current_exception());
            if (!Primary.Failed())
            {
                Primary = Cleanup;
            }
        }
        co_return Primary;
    }

} // namespace Prism::Anytls::Detail

namespace Prism::Anytls
{

    IngressFactory::IngressFactory(IngressOptions Options)
        : Options_(std::move(Options))
    {
    }

    auto IngressFactory::Accept(Prism::Contract::StreamAcceptInput Input)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        auto Inbound = std::move(Input.Inbound);
        [[maybe_unused]] auto Metadata = std::move(Input.Metadata);
        auto Bytes = std::move(Input.Bytes);
        auto GenerationUseState = std::move(Input.GenerationUseState);
        if (!Inbound || !Bytes)
        {
            if (Inbound)
            {
                auto Prepared = Detail::TransportRetirement::Prepare();
                if (!Prepared)
                {
                    const auto Failure = co_await Detail::RetireUnreservedWithFailure(
                        Inbound,
                        Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
                    co_return std::unexpected(Failure);
                }
                auto Retirement = std::move(*Prepared);
                auto Attached = Retirement->Attach(
                    std::move(Inbound), Prism::Account::StreamLease{});
                if (!Attached)
                {
                    co_return std::unexpected(Attached.error());
                }
                Retirement->RetainForRetry();
                const auto Failure = co_await Detail::RetireWithFailure(
                    Retirement,
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
                co_return std::unexpected(Failure);
            }
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }

        auto Prepared = Detail::TransportRetirement::Prepare();
        if (!Prepared)
        {
            const auto Failure = co_await Detail::RetireUnreservedWithFailure(
                Inbound, Prepared.error());
            co_return std::unexpected(Failure);
        }
        auto Retirement = std::move(*Prepared);
        auto Handshake = co_await Detail::AcceptWithRetirement(
            std::move(Inbound), Options_.Configuration, Retirement);
        if (!Handshake)
        {
            co_return std::unexpected(Handshake.error());
        }
        auto Connection = std::move(*Handshake);
        if (!Options_.Streams.Egress)
        {
            Retirement->RetainForRetry();
            const auto Failure = co_await Detail::RetireWithFailure(
                Retirement, Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
            co_return std::unexpected(Failure);
        }

        Prism::Contract::ProtocolDataPlane Plane;
        if (Options_.Authenticator)
        {
            const auto Credential =
                Prism::Account::Credential::Password(Options_.Configuration.Password);
            auto Auth = Options_.Authenticator->Authenticate(
                Prism::AuthenticationRequest{.Credential = Credential.View()});
            if (!Auth)
            {
                Retirement->RetainForRetry();
                const auto Failure = co_await Detail::RetireWithFailure(
                    Retirement, Prism::Fault::Failure{Prism::Fault::Code::AuthFailed});
                co_return std::unexpected(Failure);
            }
            Plane.AccountId = Auth->AccountId();
            Plane.Identity = std::string(Auth->Identity());
            Plane.DisplayIdentity = std::string(Auth->DisplayIdentity());
            Plane.AccountLease = std::move(*Auth);
        }

        Plane.Protocol = Prism::Contract::ProtocolType::AnyTls;
        Plane.ProtocolAuthenticated = true;
        Plane.Root = Prism::Contract::MuxRootDataPlane{Connection, {}};
        if (!GenerationUseState)
        {
            Retirement->AttachMuxRootPlane(std::move(Plane));
            Retirement->RetainForRetry();
            const auto Failure = co_await Detail::RetireWithFailure(
                Retirement, Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            co_return std::unexpected(Failure);
        }

        auto CreateRequest = Prism::Contract::MuxRootCreateRequest::Prepare(
            Retirement, std::move(GenerationUseState), std::move(Plane));
        if (!CreateRequest)
        {
            if (Plane.HasTransport())
            {
                Retirement->AttachMuxRootPlane(std::move(Plane));
                Retirement->RetainForRetry();
                const auto Failure = co_await Detail::RetireWithFailure(
                    Retirement, CreateRequest.error());
                co_return std::unexpected(Failure);
            }
            co_return std::unexpected(CreateRequest.error());
        }

        auto Created = Detail::Session::Create(*CreateRequest, Options_.Streams);
        if (!Created)
        {
            co_return std::unexpected(Created.error());
        }
        auto AcceptedPlane = CreateRequest->TakePlane();
        CreateRequest->Transfer();
        Plane = std::move(AcceptedPlane);
        co_return Prism::Contract::AcceptOutcome{std::move(Plane)};
    }

} // namespace Prism::Anytls
