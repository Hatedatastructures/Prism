/** @file IngressFactory.hpp @brief VMess 唯一 bound owner 接入与 session 退休入口。 */
#pragma once

#include <Preview/Protocols/Vmess/Binding.hpp>
#include <Preview/Protocols/Vmess/Detail/Target.hpp>
#include <Preview/Protocols/Vmess/Credentials.hpp>
#include <Preview/Protocols/Vmess/DatagramSession.hpp>
#include <Preview/Protocols/Vmess/Dgram.hpp>
#include <Preview/Protocols/Mux/RootBinding.hpp>
#include <Preview/Contract/Ingress/MuxRootCreateRequest.hpp>
#include <Preview/Transport/Replay.hpp>
#include <Preview/Contract/Ingress/StreamFactory.hpp>
#include <Preview/Contract/Ingress/InboundAdmission.hpp>

#include <array>
#include <cstdint>
#include <exception>
#include <expected>
#include <type_traits>
#include <vector>

namespace Preview::Vmess
{
    namespace Net = boost::asio;

    class IngressFactory final : public Preview::Contract::StreamFactory
    {
    public:
        ~IngressFactory() override = default;

        auto Accept(Preview::Contract::StreamAcceptInput Input)
            -> Net::awaitable<Preview::Contract::AcceptOutcome> override
        {
            auto Inbound = std::move(Input.Inbound);
            auto Metadata = std::move(Input.Metadata);
            auto Bytes = std::move(Input.Bytes);
            auto Prepared = co_await Preview::Contract::InboundAdmission::Prepare(Inbound);
            if (!Prepared) co_return std::unexpected(Prepared.error());
            auto Admission = std::move(*Prepared);
            if (!Inbound || !Bytes)
            {
                co_return co_await Admission.Reject(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
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
                co_return co_await Preview::Protocols::RejectProviderAccept(Admission, Attempt,
                    Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }
            auto ReplayResult = CreateReplay(Inbound, std::move(Bytes));
            if (!ReplayResult)
            {
                co_return co_await Preview::Protocols::RejectProviderAccept(
                    Admission, Attempt, ReplayResult.error());
            }
            auto Replay = std::move(*ReplayResult);
            if (const auto Tracked = Track(Admission, Attempt, Replay); !Tracked)
            {
                co_return co_await Preview::Protocols::RejectProviderAccept(
                    Admission, Attempt, Tracked.error());
            }
            Replay->EnableWrites();
            auto Accepted = co_await AcceptCandidate(
                Replay, Material->Configuration, Material->Credentials);
            if (!Accepted)
            {
                co_return co_await Preview::Protocols::RejectProviderAccept(
                    Admission, Attempt, Accepted.error());
            }
            auto Connection = std::visit([](auto& Session) -> Preview::SharedTransmission
            {
                return Session.Connection;
            }, *Accepted);
            if (!Connection)
            {
                co_return co_await Preview::Protocols::RejectProviderAccept(
                    Admission, Attempt,
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            if (const auto Tracked = Track(Admission, Attempt, Connection); !Tracked)
            {
                co_return co_await Preview::Protocols::RejectProviderAccept(
                    Admission, Attempt, Tracked.error());
            }
            Replay->Commit();
            auto Plane = std::expected<Preview::Contract::ProtocolDataPlane,
                Preview::Fault::Failure>{
                    std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument})};
            try
            {
                Plane = BuildPlane(PlaneBuildRequest{std::move(*Accepted),
                    std::move(Metadata), Route_, Material->Datagrams,
                    Attempt.Owner(), Material->GenerationUseState});
            }
            catch (...)
            {
                Plane = std::unexpected(Preview::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception()));
            }
            if (!Plane)
            {
                co_return co_await Preview::Protocols::RejectProviderAccept(
                    Admission, Attempt, Plane.error());
            }
            co_return co_await Preview::Protocols::AdmitProviderPlane(
                Admission, Attempt, std::move(*Plane));
        }

        [[nodiscard]] auto Name() const -> std::string_view override { return "vmess"; }
        auto Close() noexcept -> void { Binding_->Close(); }
        [[nodiscard]] auto Drain() -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        { return Binding_->Drain(); }
        [[nodiscard]] auto IsRetired() const noexcept -> bool { return Binding_->IsRetired(); }
        [[nodiscard]] auto GenerationUseState() const noexcept
            -> std::shared_ptr<Preview::Foundation::GenerationUseState>
        { return Binding_->GenerationUseState(); }

    private:
        friend class Binding;

        IngressFactory(std::shared_ptr<const Binding> Owner, IngressRoute Route)
            : Binding_(std::move(Owner)), Route_(std::move(Route)) {}

        [[nodiscard]] static auto CreateReplay(
            const Preview::SharedTransmission& Inbound,
            std::shared_ptr<Preview::Memory::BytePool> Bytes)
            -> std::expected<std::shared_ptr<Preview::Transport::ReplayTransmission>,
                Preview::Fault::Failure>
        {
            try
            {
                return Preview::Transport::ReplayTransmission::Create(Inbound,
                    Preview::Transport::ReplayOptions{64U * 1024U,
                        Preview::Transport::ReplayMode::Candidate, std::move(Bytes)});
            }
            catch (...)
            {
                return std::unexpected(Preview::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception()));
            }
        }

        [[nodiscard]] static auto Track(Preview::Contract::InboundAdmission& Admission,
            Binding::AcceptAttempt& Attempt, const Preview::SharedTransmission& Transport)
            -> std::expected<void, Preview::Fault::Failure>
        {
            const auto Owned = Attempt.Owner()->Track(Transport);
            if (!Owned)
            {
                (void)Admission.Track(Transport);
                return std::unexpected(Owned.error());
            }
            return Admission.Track(Transport);
        }

        [[nodiscard]] static auto AcceptCandidate(
            const std::shared_ptr<Preview::Transport::ReplayTransmission>& Replay,
            const ServerConfig& Configuration,
            const Preview::Account::CredentialIndexView& CredentialScope)
            -> Net::awaitable<std::expected<AcceptedSession, Preview::Fault::Failure>>
        {
            std::vector<std::array<std::uint8_t, 16>> Uuids;
            try
            {
                Uuids = Preview::Vmess::Credentials::UuidsForScope(CredentialScope);
            }
            catch (...)
            {
                co_return std::unexpected(Preview::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception()));
            }
            for (const auto& Uuid : Uuids)
            {
                auto Result = std::expected<AcceptedSession, Preview::Fault::Failure>{
                    std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::AuthFailed})};
                try
                {
                    auto Candidate = Configuration;
                    Candidate.uuid = Uuid;
                    Result = co_await Vmess::AcceptSession(Replay, Candidate);
                }
                catch (...)
                {
                    co_return std::unexpected(Preview::Contract::InboundAdmission::ExceptionFailure(
                        std::current_exception()));
                }
                if (Result) co_return std::move(Result);
                const auto Failure = Result.error();
                if (Failure.Code != Preview::Fault::Code::AuthFailed || Failure.Native)
                {
                    co_return std::unexpected(Failure);
                }
                const auto Rewound = Replay->Rewind();
                if (!Rewound) co_return std::unexpected(Rewound.error());
            }
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::AuthFailed});
        }

        struct PlaneBuildRequest final
        {
            AcceptedSession Accepted;
            Preview::Contract::RequestMetadata Metadata;
            const IngressRoute& Route;
            const Preview::Contract::DatagramServices& Datagrams;
            std::shared_ptr<Preview::Contract::MuxRootCreateOwner> RootOwner;
            std::shared_ptr<Preview::Foundation::GenerationUseState> UseState;
        };

        /** @brief 从唯一握手结果取出真实连接，并保留 UDP 包连接 owner。 */
        struct AcceptedConnectionTake final
        {
            SharedDgram& Datagram;

            [[nodiscard]] auto operator()(AcceptedConnection& Session) const -> SharedConn
            {
                return std::move(Session.Connection);
            }

            [[nodiscard]] auto operator()(AcceptedDatagram& Session) const -> SharedConn
            {
                Datagram = std::move(Session.Connection);
                return Datagram ? Datagram->SessionConnection() : SharedConn{};
            }
        };

        [[nodiscard]] auto BuildPlane(PlaneBuildRequest Input) const
            -> std::expected<Preview::Contract::ProtocolDataPlane, Preview::Fault::Failure>
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
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            Preview::Contract::ProtocolDataPlane Plane;
            Plane.Protocol = Preview::Contract::ProtocolType::Vmess;
            if (Request.Cmd != CmdMux)
            {
                auto Target = Preview::Vmess::Detail::ToNetworkTarget(Request.dst);
                if (!Target)
                {
                    return std::unexpected(
                        Preview::Contract::FailureFromProtocolError(Preview::Error::BadAddress));
                }
                Plane.Target = std::move(*Target);
            }
            Plane.ProtocolAuthenticated = true;
            Plane.AccountId = Connection->AccountId();
            Plane.Identity = std::string(Connection->Identity());
            Plane.AccountLease = Connection->TakeAuthLease();
            if (Request.Cmd == CmdMux || (Input.Route.Mux && Request.Cmd == CmdTcp))
            {
                Plane.Root = Preview::Contract::MuxRootDataPlane{Connection, {}};
                if (Input.Route.Mux)
                {
                    auto RootRequest = Preview::Contract::MuxRootCreateRequest::Prepare(
                        std::move(Input.RootOwner), std::move(Input.UseState), std::move(Plane));
                    if (!RootRequest) return std::unexpected(RootRequest.error());
                    auto Created = Input.Route.Mux->Create(std::move(*RootRequest));
                    if (!Created) return std::unexpected(Created.error());
                    return std::move(Created->Plane);
                }
            }
            else if (Request.Cmd == CmdUdp)
            {
                if (!Datagram)
                {
                    return std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::BadMessage});
                }
                auto Session = std::make_shared<DatagramSession>(
                    DatagramWire{Datagram, Plane.Target}, DatagramSession::Relay::Options{Input.Datagrams,
                        {.Request = std::move(Input.Metadata), .Identity = Plane.Identity,
                         .DisplayIdentity = Plane.DisplayIdentity, .Protocol = Plane.Protocol,
                         .AccountId = Plane.AccountId}});
                Plane.Root = Preview::Contract::DatagramDataPlane{Datagram, std::move(Session)};
            }
            else
            {
                if (Datagram)
                {
                    return std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::BadMessage});
                }
                Plane.Root = Preview::Contract::StreamDataPlane{std::move(Connection)};
            }
            return Plane;
        }

        std::shared_ptr<const Binding> Binding_;
        IngressRoute Route_;
    };

    inline auto Binding::WithIngress(IngressRoute Route) const -> std::shared_ptr<IngressFactory>
    {
        if (!Material()) return {};
        if (Route.Mux && !Lifetime_->AddMux(Route.Mux)) return {};
        return std::shared_ptr<IngressFactory>(
            new IngressFactory(shared_from_this(), std::move(Route)));
    }
}
