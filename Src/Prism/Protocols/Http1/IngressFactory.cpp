/**
 * @file IngressFactory.cpp
 * @brief HTTP/1.1 入站接入与响应交接实现
 */

#include <Prism/Protocols/Http1/IngressFactory.hpp>
#include <Prism/Protocols/Http1/Binding.hpp>
#include <Prism/Protocols/Http1/Detail/BasicAuthentication.hpp>
#include <Prism/Protocols/Http1/Detail/ParserSupport.hpp>
#include <Prism/Foundation/Utility/Crypto/Base64.hpp>

#include <atomic>
#include <memory>
#include <string_view>
#include <utility>

namespace Prism::Http11
{
    [[nodiscard]] auto PrepareAccountCredential(std::string_view Value)
        -> Prism::Account::Credential
    {
        return Prism::Account::Credential::Password(Value);
    }

    [[nodiscard]] auto BindProvider(PreparedBinding Prepared) -> std::shared_ptr<Binding>
    {
        return std::make_shared<Binding>(std::move(Prepared));
    }

    auto PrepareProviderBinding(
        std::string Instance,
        Prism::Contract::AuthenticationServices Authentication,
        boost::asio::any_io_executor Executor)
        -> std::expected<PreparedBinding, Prism::Contract::ProviderFailure>
    {
        if (!Authentication.Generation || !Authentication.Authenticator ||
            !Authentication.Credentials)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::MissingAuthentication, {}, "Authentication"});
        }
        if (!Executor)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::InvalidConfiguration, Instance, "Executor"});
        }
        if (!Authentication.Matches(Authentication.Generation))
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::GenerationMismatch, {}, "Authentication.Generation"});
        }
        return PreparedBinding{
            std::move(Instance), std::move(Authentication.Authenticator), std::move(Executor)};
    }

    IngressFactory::IngressFactory(IngressOptions Options)
        : Options_(std::move(Options))
    {
    }

    Binding::State::State(PreparedBinding Value)
        : Factory(std::make_shared<IngressFactory>(IngressOptions{
              .RequireAuth = Value.RequireAuth, .Authenticator = std::move(Value.Authenticator)})),
          Barrier(std::make_shared<Prism::Lifecycle::DrainBarrier>(
              std::make_shared<Prism::Executor::ExecutorReclaimer>(
                  std::move(Value.Executor))))
    {
    }

    Binding::AcceptActivity::AcceptActivity(
        std::shared_ptr<Prism::Lifecycle::DrainBarrier> Value)
        : Barrier_(std::move(Value))
    {
    }

    Binding::AcceptActivity::~AcceptActivity()
    {
        if (Barrier_)
        {
            Barrier_->Leave();
        }
    }

    Binding::Binding(PreparedBinding Value)
        : State_(std::make_shared<State>(std::move(Value)))
    {
    }

    Binding::~Binding()
    {
        Close();
    }

    auto Binding::Accept(Prism::Contract::StreamAcceptInput Input)
        -> boost::asio::awaitable<Prism::Contract::AcceptOutcome>
    {
        const auto State = State_;
        if (!State->Closed.load(std::memory_order_acquire) && State->Barrier->Enter())
        {
            AcceptActivity Activity(State->Barrier);
            const auto Factory = State->Factory.load(std::memory_order_acquire);
            if (Factory)
            {
                co_return co_await Factory->Accept(std::move(Input));
            }
        }
        co_return co_await RejectClosed(std::move(Input));
    }

    auto Binding::Close() noexcept -> void
    {
        State_->Barrier->Seal();
        State_->Closed.store(true, std::memory_order_release);
    }

    [[nodiscard]] auto Binding::IsRetired() const noexcept -> bool
    {
        return State_->Retired.load(std::memory_order_acquire) &&
            State_->Barrier->Active() == 0U &&
            !State_->Factory.load(std::memory_order_acquire);
    }

    auto Binding::Drain()
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_return co_await DrainState(State_);
    }

    auto Binding::RejectClosed(Prism::Contract::StreamAcceptInput Input)
        -> boost::asio::awaitable<Prism::Contract::AcceptOutcome>
    {
        if (!Input.Inbound)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(
            std::move(Input.Inbound));
        if (!Prepared)
        {
            co_return std::unexpected(Prepared.error());
        }
        co_return co_await Prepared->Reject(
            Prism::Fault::Failure{Prism::Fault::Code::Canceled});
    }

    auto Binding::DrainState(std::shared_ptr<State> Value)
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        Value->Barrier->Seal();
        Value->Closed.store(true, std::memory_order_release);
        const auto Result = co_await Value->Barrier->Drain();
        if (!Result)
        {
            (void)Value->DrainFailure.TrySet(Result.error());
        }
        if (Value->Barrier->Active() == 0U)
        {
            Value->Factory.store({}, std::memory_order_release);
            Value->Retired.store(true, std::memory_order_release);
        }
        const auto FirstFailure = Value->DrainFailure.Load();
        if (FirstFailure.Failed())
        {
            co_return std::unexpected(FirstFailure);
        }
        if (!Result)
        {
            co_return std::unexpected(Result.error());
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    namespace detail
    {
        auto AuthenticateBasic(
            const std::string_view Authorization,
            const Prism::Authenticator &Authenticator) -> Prism::AuthenticationResult
        {
            constexpr std::string_view BasicPrefix = "Basic ";
            if (Authorization.size() <= BasicPrefix.size() ||
                !Prism::Http11::detail::Iequals(
                    Authorization.substr(0, BasicPrefix.size()), BasicPrefix))
            {
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::AuthFailed});
            }

            const auto Decoded = Prism::Crypto::Base64Decode(
                Authorization.substr(BasicPrefix.size()));
            const auto Colon = Decoded.find(':');
            if (Colon == std::string_view::npos || Colon + 1U >= Decoded.size())
            {
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::AuthFailed});
            }

            const auto User = std::string_view(Decoded).substr(0, Colon);
            const auto Password = std::string_view(Decoded).substr(Colon + 1U);
            return Authenticator.Authenticate(Prism::AuthenticationRequest{
                .AccountId = {},
                .Identity = User,
                .Credential = Prism::Account::CredentialView::Password(Password),
                .Rate = {}});
        }
    } // namespace detail

    auto IngressFactory::Accept(Prism::Contract::StreamAcceptInput Input)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        Prism::Contract::ProtocolDataPlane Result;
        Result.Protocol = Prism::Contract::ProtocolType::Http;
        auto Inbound = std::move(Input.Inbound);
        auto Bytes = std::move(Input.Bytes);
        if (!Inbound)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto PreparedAdmission = co_await Prism::Contract::InboundAdmission::Prepare(Inbound);
        if (!PreparedAdmission)
        {
            co_return std::unexpected(PreparedAdmission.error());
        }
        auto Admission = std::move(*PreparedAdmission);
        if (!Bytes)
        {
            co_return co_await Admission.Reject(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        Prism::Http11::ServerConn Server(std::move(Inbound), std::move(Bytes));
        Prism::Http11::HttpRequest Request;
        const auto ReadError = co_await Server.ReadRequest(Request);
        if (ReadError.Failed())
        {
            auto Failure = ReadError;
            if (Failure.Code == Prism::Fault::Code::ParseError)
            {
                Failure.Code = Prism::Fault::Code::BadMessage;
            }
            co_return co_await RejectWithResponse(Http1Rejection{
                Server, Admission, Prism::Http11::Status::BadRequest,
                Failure});
        }

        const auto Target = Prism::Http11::ResolveTarget(Request);
        if (!Target)
        {
            co_return co_await RejectWithResponse(Http1Rejection{
                Server, Admission, Prism::Http11::Status::BadRequest,
                Prism::Fault::Failure{Prism::Fault::Code::BadMessage}});
        }

        Prism::Account::AccountLease Lease;
        if (Options_.RequireAuth)
        {
            if (!Options_.Authenticator)
            {
                co_return co_await RejectWithResponse(Http1Rejection{
                    Server, Admission, Prism::Http11::Status::ProxyAuthRequired,
                    Prism::Fault::Failure{Prism::Fault::Code::AuthFailed}});
            }

            auto AuthResult = detail::AuthenticateBasic(
                Request.authorization, *Options_.Authenticator);
            if (!AuthResult)
            {
                co_return co_await RejectWithResponse(Http1Rejection{
                    Server, Admission, Prism::Http11::Status::ProxyAuthRequired,
                    AuthResult.error()});
            }
            Lease = std::move(*AuthResult);
        }

        const bool IsConnect = Target->Form == Prism::Http11::RequestForm::Connect;
        const bool IsHead = Request.Method == "HEAD";
        const bool UpgradeRequested = Request.Headers.HasUpgrade &&
                                      Request.Headers.ConnectionContains("upgrade");
        auto Host = Prism::Network::ParseHost(Target->Host);
        if (!Host) co_return co_await Admission.Reject(Host.error());
        Result.Target = {std::move(*Host), Target->Port, Prism::Network::RouteKind::Forward};
        if (Options_.RequireAuth)
        {
            Result.AccountId = Lease.AccountId();
            Result.Identity = std::string(Lease.Identity());
            Result.DisplayIdentity = std::string(Lease.DisplayIdentity());
        }
        Result.ProtocolAuthenticated = Options_.RequireAuth;
        Result.AccountLease = std::move(Lease);

        Prism::SharedTransmission Transport = IsConnect
            ? Server.Release()
            : Server.ReleaseForward();
        if (!Transport)
        {
            co_return co_await Admission.Reject(
                Prism::Fault::Failure{Prism::Fault::Code::IoError});
        }

        Result.Root = Prism::Contract::StreamDataPlane{Transport};
        ConfigureResponse(Result, ResponsePlan{IsConnect, IsHead, UpgradeRequested});
        const auto Tracked = Admission.Track(Transport);
        if (!Tracked)
        {
            co_return co_await Admission.Reject(std::move(Result), Tracked.error());
        }
        co_return co_await Admission.Admit(std::move(Result));
    }

    auto IngressFactory::RejectWithResponse(Http1Rejection Request)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        const auto Sent = co_await Request.Server.SendResponse(Request.Response);
        if (Sent.Failed())
        {
            Request.Failure = Sent;
        }
        co_return co_await Request.Admission.Reject(Request.Failure);
    }

    auto IngressFactory::ConfigureResponse(Prism::Contract::ProtocolDataPlane &Plane,
                                  const ResponsePlan Plan) -> void
    {
        Plane.PostDial = [Client = Plane.Transport(), Plan](
                             Prism::Fault::Failure Failure)
            -> Net::awaitable<Prism::Fault::Failure>
        { return SendDeferredReply(Client, Plan.Tunnel, std::move(Failure)); };
        if (!Plan.Tunnel)
        {
            Plane.Stream()->OutboundDecorator = [Plan](Prism::SharedTransmission Outbound)
                -> Prism::SharedTransmission
            { return DecorateResponse(std::move(Outbound), Plan); };
        }
    }

    auto IngressFactory::SendDeferredReply(
        Prism::SharedTransmission Client,
        const bool IsTunnel,
        Prism::Fault::Failure Failure)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        if (!IsTunnel && Failure.Code == Prism::Fault::Code::Success)
        {
            co_return Prism::Fault::Failure{Prism::Fault::Code::Success};
        }
        auto Status = Prism::Http11::Status::Ok;
        if (Failure.Code != Prism::Fault::Code::Success)
            Status = Prism::Http11::Status::BadGateway;
        co_return co_await Prism::Http11::SendResponse(Client, Status);
    }

    auto IngressFactory::DecorateResponse(
        Prism::SharedTransmission Outbound,
        const ResponsePlan Plan) -> Prism::SharedTransmission
    {
        Prism::Http11::ForwardResponseTransportOptions Options;
        Options.Inner = std::move(Outbound);
        Options.Framing.RequestMethod = Prism::Http11::ForwardResponseMethod::Other;
        if (Plan.Head)
            Options.Framing.RequestMethod = Prism::Http11::ForwardResponseMethod::Head;
        Options.Framing.AllowUpgrade = Plan.Upgrade;
        return Prism::Http11::MakeForwardResponseTransport(std::move(Options));
    }
} // namespace Prism::Http11
