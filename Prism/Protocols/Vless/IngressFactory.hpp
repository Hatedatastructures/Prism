/** @file IngressFactory.hpp @brief VLESS 唯一 bound owner 接入与 session 退休入口。 */
#pragma once

#include <Prism/Protocols/Vless/Binding.hpp>
#include <Prism/Protocols/Vless/Detail/Target.hpp>
#include <Prism/Protocols/Vless/AssociationFactory.hpp>
#include <Prism/Protocols/Vless/Xudp/RootSession.hpp>
#include <Prism/Protocols/Mux/RootBinding.hpp>
#include <Prism/Contract/Ingress/MuxRootCreateRequest.hpp>
#include <Prism/Contract/Ingress/StreamFactory.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>

#include <exception>
#include <expected>

namespace Prism::Vless
{
    class IngressFactory final : public Prism::Contract::StreamFactory
    {
    public:
        /** @brief 已绑定配置只通过 Binding 派生，不接受第二份配置副本。 */
        ~IngressFactory() override = default;

        auto Accept(Prism::Contract::StreamAcceptInput Input)
            -> Net::awaitable<Prism::Contract::AcceptOutcome> override
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
            auto AdmissionConfiguration = Material->Configuration;
            AdmissionConfiguration.EnableUdp = AdmissionConfiguration.EnableUdp && Route_.EnableUdp;
            auto Accepted = co_await AcceptConnection(Inbound, AdmissionConfiguration);
            if (!Accepted)
            {
                co_return co_await Prism::Protocols::RejectProviderAccept(
                    Admission, Attempt, Accepted.error());
            }
            // Track 仅借用共享 owner；Accepted 仍需把连接移交给 BuildPlane。
            auto Connection = Accepted->Connection;
            if (const auto Tracked = Track(Admission, Attempt, Connection); !Tracked)
            {
                co_return co_await Prism::Protocols::RejectProviderAccept(
                    Admission, Attempt, Tracked.error());
            }
            auto Plane = std::expected<Prism::Contract::ProtocolDataPlane,
                Prism::Fault::Failure>{
                    std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument})};
            try
            {
                Plane = BuildPlane(PlaneBuildRequest{std::move(*Accepted),
                    std::move(Metadata), Route_, Material->Datagrams,
                    Material->GenerationUseState, Attempt.Owner()});
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

        [[nodiscard]] auto Name() const -> std::string_view override { return "vless"; }
        auto Close() noexcept -> void { Binding_->Close(); }
        [[nodiscard]] auto Drain() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        { return Binding_->Drain(); }
        [[nodiscard]] auto IsRetired() const noexcept -> bool { return Binding_->IsRetired(); }
        [[nodiscard]] auto GenerationUseState() const noexcept
            -> std::shared_ptr<Prism::Foundation::GenerationUseState>
        { return Binding_->GenerationUseState(); }

    private:
        friend class Binding;

        IngressFactory(std::shared_ptr<const Binding> Owner, IngressRoute Route)
            : Binding_(std::move(Owner)), Route_(std::move(Route)) {}

        [[nodiscard]] static auto AcceptConnection(
            const Prism::SharedTransmission& Inbound, const ServerConfig& Configuration)
            -> Net::awaitable<std::expected<AcceptedConnection, Prism::Fault::Failure>>
        {
            try
            {
                co_return co_await Vless::Accept(Inbound, Configuration);
            }
            catch (...)
            {
                co_return std::unexpected(Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception()));
            }
        }

        [[nodiscard]] static auto Track(Prism::Contract::InboundAdmission& Admission,
            Binding::AcceptAttempt& Attempt, const Prism::SharedTransmission& Connection)
            -> std::expected<void, Prism::Fault::Failure>
        {
            auto Owned = Attempt.Owner()->Track(Connection);
            if (!Owned)
            {
                (void)Admission.Track(Connection);
                return std::unexpected(Owned.error());
            }
            return Admission.Track(Connection);
        }

        struct PlaneBuildRequest final
        {
            AcceptedConnection Accepted;
            Prism::Contract::RequestMetadata Metadata;
            const IngressRoute& Route;
            const Prism::Contract::DatagramServices& Datagrams;
            std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
            std::shared_ptr<Prism::Contract::MuxRootCreateOwner> RootOwner;
        };

        [[nodiscard]] auto BuildPlane(PlaneBuildRequest Input) const
            -> std::expected<Prism::Contract::ProtocolDataPlane, Prism::Fault::Failure>
        {
            auto Accepted = std::move(Input.Accepted);
            auto Request = std::move(Accepted.Request);
            auto Connection = std::move(Accepted.Connection);
            if (!Connection)
            {
                return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            Prism::Contract::ProtocolDataPlane Plane;
            Plane.Protocol = Prism::Contract::ProtocolType::Vless;
            if (Request.Cmd != Command::Mux)
            {
                auto Target = Prism::Vless::Detail::ToNetworkTarget(Request.Target);
                if (!Target)
                {
                    return std::unexpected(
                        Prism::Contract::FailureFromProtocolError(Prism::Error::BadAddress));
                }
                Plane.Target = std::move(*Target);
            }
            Plane.AccountId = Connection->AccountId();
            Plane.Identity = std::string(Connection->Identity());
            Plane.AccountLease = Connection->TakeAuthLease();
            Plane.ProtocolAuthenticated = true;
            Prism::Protocols::DatagramBinding DatagramBinding{Input.Datagrams,
                {.Request = std::move(Input.Metadata), .Identity = Plane.Identity,
                 .DisplayIdentity = Plane.DisplayIdentity, .Protocol = Plane.Protocol,
                 .AccountId = Plane.AccountId}};
            if (Request.Cmd == Command::Mux ||
                (Input.Route.Mux && Request.Cmd == Command::Tcp))
            {
                if (Input.Route.Mux)
                {
                    Plane.Root = Prism::Contract::MuxRootDataPlane{Connection, {}};
                    auto RootRequest = Prism::Contract::MuxRootCreateRequest::Prepare(
                        std::move(Input.RootOwner), Input.UseState, std::move(Plane));
                    if (!RootRequest) return std::unexpected(RootRequest.error());
                    auto Created = Input.Route.Mux->Create(std::move(*RootRequest));
                    if (!Created) return std::unexpected(Created.error());
                    return std::move(Created->Plane);
                }
                auto Root = std::make_shared<Xudp::RootSession>(
                    Connection, std::move(DatagramBinding), std::move(Input.UseState));
                Plane.Root = Prism::Contract::MuxRootDataPlane{Connection, std::move(Root)};
            }
            else if (Request.Cmd == Command::Udp)
            {
                Plane.Root = Prism::Contract::DatagramDataPlane{
                    Connection, MakeDatagramSession(Connection, Request.Target, std::move(DatagramBinding))};
            }
            else
            {
                Plane.Root = Prism::Contract::StreamDataPlane{Connection};
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
