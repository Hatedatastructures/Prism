/** @file IngressFactory.cpp @brief VMess 入站数据面投影实现。 */
#include <Prism/Protocols/Vmess/IngressFactory.hpp>
#include <Prism/Protocols/Vmess/DatagramSession.hpp>
#include <Prism/Protocols/Vmess/Dgram.hpp>
#include <Prism/Protocols/Vmess/Credentials.hpp>
#include <Prism/Protocols/Mux/RootBinding.hpp>
#include <Prism/Contract/Ingress/MuxRootCreateRequest.hpp>
#include <Prism/Transport/Replay.hpp>

#include "Detail/Target.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

namespace Prism::Vmess
{

    auto Credentials::CopyUuid(const Prism::Account::CredentialView Credential)
        -> std::optional<std::array<std::uint8_t, 16>>
    {
        if (Credential.Kind() != Prism::Account::CredentialKind::Uuid ||
            Credential.Size() != 16U)
        {
            return std::nullopt;
        }
        std::array<std::uint8_t, 16> Value{};
        for (std::size_t Index = 0; Index < Value.size(); ++Index)
        {
            Value[Index] = std::to_integer<std::uint8_t>(Credential.Bytes()[Index]);
        }
        return Value;
    }

    auto Credentials::UuidsForScope(
        const Prism::Account::CredentialIndexView &CredentialsValue)
        -> std::vector<std::array<std::uint8_t, 16>>
    {
        std::vector<std::array<std::uint8_t, 16>> Records;
        if (!CredentialsValue)
        {
            return Records;
        }
        const auto Enumerated = CredentialsValue.ForEachCredential(
            Prism::Account::CredentialKind::Uuid,
            [&Records](const std::shared_ptr<const Prism::Account::AccountBinding> &,
                       const Prism::Account::CredentialMaterial &Material)
            {
                if (const auto Uuid = Credentials::CopyUuid(Material.Credential.View()))
                {
                    Records.push_back(*Uuid);
                }
            });
        if (!Enumerated)
        {
            Records.clear();
        }
        return Records;
    }

    IngressFactory::IngressFactory(std::shared_ptr<const Binding> Owner, IngressRoute Route)
        : Binding_(std::move(Owner)), Route_(std::move(Route))
    {
    }

    IngressFactory::~IngressFactory() = default;

    auto IngressFactory::Name() const -> std::string_view
    {
        return "vmess";
    }

    auto IngressFactory::Close() noexcept -> void
    {
        Binding_->Close();
    }

    auto IngressFactory::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        return Binding_->Drain();
    }

    auto IngressFactory::IsRetired() const noexcept -> bool
    {
        return Binding_->IsRetired();
    }

    auto IngressFactory::GenerationUseState() const noexcept
        -> std::shared_ptr<Prism::Foundation::GenerationUseState>
    {
        return Binding_->GenerationUseState();
    }

    auto IngressFactory::Accept(Prism::Contract::StreamAcceptInput Input)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        auto Inbound = std::move(Input.Inbound);
        auto Metadata = std::move(Input.Metadata);
        auto Bytes = std::move(Input.Bytes);
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Inbound);
        if (!Prepared) co_return std::unexpected(Prepared.error());
        auto Admission = std::move(*Prepared);
        if (!Inbound || !Bytes)
        {
            co_return co_await Admission.Reject(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto Started = Binding_->Begin(Inbound);
        if (!Started)
        {
            co_return co_await Admission.Reject(Started.error());
        }
        auto Attempt = std::move(*Started);
        auto Material = Binding_->Material();
        if (!Material)
        {
            co_return co_await Prism::Protocols::RejectProviderAccept(Admission, Attempt,
                Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }
        auto ReplayResult = CreateReplay(Inbound, std::move(Bytes));
        if (!ReplayResult)
        {
            co_return co_await Prism::Protocols::RejectProviderAccept(
                Admission, Attempt, ReplayResult.error());
        }
        auto Replay = std::move(*ReplayResult);
        if (const auto Tracked = Track(Admission, Attempt, Replay); !Tracked)
        {
            co_return co_await Prism::Protocols::RejectProviderAccept(
                Admission, Attempt, Tracked.error());
        }
        Replay->EnableWrites();
        auto Accepted = co_await AcceptCandidate(
            Replay, Material->Configuration, Material->Credentials);
        if (!Accepted)
        {
            co_return co_await Prism::Protocols::RejectProviderAccept(
                Admission, Attempt, Accepted.error());
        }
        auto Connection = std::visit([](auto& Session) -> Prism::SharedTransmission
        {
            return Session.Connection;
        }, *Accepted);
        if (!Connection)
        {
            co_return co_await Prism::Protocols::RejectProviderAccept(
                Admission, Attempt,
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        if (const auto Tracked = Track(Admission, Attempt, Connection); !Tracked)
        {
            co_return co_await Prism::Protocols::RejectProviderAccept(
                Admission, Attempt, Tracked.error());
        }
        Replay->Commit();
        auto Plane = std::expected<Prism::Contract::ProtocolDataPlane,
            Prism::Fault::Failure>{
                std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument})};
        try
        {
            Plane = BuildPlane(PlaneBuildRequest{std::move(*Accepted),
                std::move(Metadata), Route_, Material->Datagrams,
                Attempt.Owner(), Material->GenerationUseState});
        }
        catch (...)
        {
            Plane = std::unexpected(Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception()));
        }
        if (!Plane)
        {
            co_return co_await Prism::Protocols::RejectProviderAccept(
                Admission, Attempt, Plane.error());
        }
        co_return co_await Prism::Protocols::AdmitProviderPlane(
            Admission, Attempt, std::move(*Plane));
    }

    auto IngressFactory::CreateReplay(const Prism::SharedTransmission& Inbound,
        std::shared_ptr<Prism::Memory::BytePool> Bytes)
        -> std::expected<std::shared_ptr<Prism::Transport::ReplayTransmission>,
            Prism::Fault::Failure>
    {
        try
        {
            return Prism::Transport::ReplayTransmission::Create(Inbound,
                Prism::Transport::ReplayOptions{64U * 1024U,
                    Prism::Transport::ReplayMode::Candidate, std::move(Bytes)});
        }
        catch (...)
        {
            return std::unexpected(Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception()));
        }
    }

    auto IngressFactory::Track(Prism::Contract::InboundAdmission& Admission,
        Binding::AcceptAttempt& Attempt, const Prism::SharedTransmission& Transport)
        -> std::expected<void, Prism::Fault::Failure>
    {
        const auto Owned = Attempt.Owner()->Track(Transport);
        if (!Owned)
        {
            (void)Admission.Track(Transport);
            return std::unexpected(Owned.error());
        }
        return Admission.Track(Transport);
    }

    auto IngressFactory::AcceptCandidate(
        const std::shared_ptr<Prism::Transport::ReplayTransmission>& Replay,
        const ServerConfig& Configuration,
        const Prism::Account::CredentialIndexView& CredentialScope)
        -> Net::awaitable<std::expected<AcceptedSession, Prism::Fault::Failure>>
    {
        std::vector<std::array<std::uint8_t, 16>> Uuids;
        try
        {
            Uuids = Prism::Vmess::Credentials::UuidsForScope(CredentialScope);
        }
        catch (...)
        {
            co_return std::unexpected(Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception()));
        }
        for (const auto& Uuid : Uuids)
        {
            auto Result = std::expected<AcceptedSession, Prism::Fault::Failure>{
                std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::AuthFailed})};
            try
            {
                auto Candidate = Configuration;
                Candidate.uuid = Uuid;
                Result = co_await Vmess::AcceptSession(Replay, Candidate);
            }
            catch (...)
            {
                co_return std::unexpected(Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception()));
            }
            if (Result) co_return std::move(Result);
            const auto Failure = Result.error();
            if (Failure.Code != Prism::Fault::Code::AuthFailed || Failure.Native)
            {
                co_return std::unexpected(Failure);
            }
            const auto Rewound = Replay->Rewind();
            if (!Rewound) co_return std::unexpected(Rewound.error());
        }
        co_return std::unexpected(
            Prism::Fault::Failure{Prism::Fault::Code::AuthFailed});
    }

    auto Binding::WithIngress(IngressRoute Route) const -> std::shared_ptr<IngressFactory>
    {
        if (!Material()) return {};
        if (Route.Mux && !Lifetime_->AddMux(Route.Mux)) return {};
        return std::shared_ptr<IngressFactory>(
            new IngressFactory(shared_from_this(), std::move(Route)));
    }

    auto IngressFactory::BuildPlane(PlaneBuildRequest Input) const
        -> std::expected<Prism::Contract::ProtocolDataPlane, Prism::Fault::Failure>
    {
        auto Accepted = std::move(Input.Accepted);
        auto Request = std::visit([](auto& Session) -> Message
        {
            return std::move(Session.Request);
        }, Accepted);
        SharedDgram Datagram;
        auto Connection = std::visit(AcceptedConnectionTake{Datagram}, Accepted);
        if (!Connection)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }

        Prism::Contract::ProtocolDataPlane Plane;
        Plane.Protocol = Prism::Contract::ProtocolType::Vmess;
        if (Request.Cmd != CmdMux)
        {
            auto Target = Detail::ToNetworkTarget(Request.dst);
            if (!Target)
            {
                return std::unexpected(
                    Prism::Contract::FailureFromProtocolError(Prism::Error::BadAddress));
            }
            Plane.Target = std::move(*Target);
        }
        Plane.ProtocolAuthenticated = true;
        Plane.AccountId = Connection->AccountId();
        Plane.Identity = std::string(Connection->Identity());
        Plane.AccountLease = Connection->TakeAuthLease();

        if (Request.Cmd == CmdMux || (Input.Route.Mux && Request.Cmd == CmdTcp))
        {
            Plane.Root = Prism::Contract::MuxRootDataPlane{Connection, {}};
            if (Input.Route.Mux)
            {
                auto RootRequest = Prism::Contract::MuxRootCreateRequest::Prepare(
                    std::move(Input.RootOwner), std::move(Input.UseState), std::move(Plane));
                if (!RootRequest)
                {
                    return std::unexpected(RootRequest.error());
                }
                auto Created = Input.Route.Mux->Create(std::move(*RootRequest));
                if (!Created)
                {
                    return std::unexpected(Created.error());
                }
                return std::move(Created->Plane);
            }
        }
        else if (Request.Cmd == CmdUdp)
        {
            if (!Datagram)
            {
                return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
            }
            auto Session = DatagramSession::Create(
                Datagram, Plane.Target,
                DatagramSession::Options{Input.Datagrams,
                    {.Request = std::move(Input.Metadata), .Identity = Plane.Identity,
                     .DisplayIdentity = Plane.DisplayIdentity, .Protocol = Plane.Protocol,
                     .AccountId = Plane.AccountId}});
            if (!Session)
            {
                return std::unexpected(Session.error());
            }
            Plane.Root = Prism::Contract::DatagramDataPlane{Datagram, std::move(*Session)};
        }
        else
        {
            if (Datagram)
            {
                return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
            }
            Plane.Root = Prism::Contract::StreamDataPlane{std::move(Connection)};
        }
        return Plane;
    }

} // namespace Prism::Vmess
