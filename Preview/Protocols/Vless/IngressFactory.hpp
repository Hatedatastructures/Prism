/** @file IngressFactory.hpp @brief VLESS 唯一 bound owner 接入与 session 退休入口。 */
#pragma once

#include <Preview/Protocols/Vless/Binding.hpp>
#include <Preview/Protocols/Vless/Detail/Target.hpp>
#include <Preview/Protocols/Vless/AssociationFactory.hpp>
#include <Preview/Protocols/Vless/Xudp/RootSession.hpp>
#include <Preview/Protocols/Mux/RootBinding.hpp>
#include <Preview/Contract/Ingress/MuxRootCreateRequest.hpp>
#include <Preview/Contract/Ingress/StreamFactory.hpp>
#include <Preview/Contract/Ingress/InboundAdmission.hpp>

#include <exception>
#include <expected>

namespace Preview::Vless
{
    class IngressFactory final : public Preview::Contract::StreamFactory
    {
    public:
        /** @brief 已绑定配置只通过 Binding 派生，不接受第二份配置副本。 */
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
            auto Accepted = co_await AcceptConnection(Inbound, Material->Configuration);
            if (!Accepted)
            {
                co_return co_await Preview::Protocols::RejectProviderAccept(
                    Admission, Attempt, Accepted.error());
            }
            // Track 仅借用共享 owner；Accepted 仍需把连接移交给 BuildPlane。
            auto Connection = Accepted->Connection;
            if (const auto Tracked = Track(Admission, Attempt, Connection); !Tracked)
            {
                co_return co_await Preview::Protocols::RejectProviderAccept(
                    Admission, Attempt, Tracked.error());
            }
            auto Plane = std::expected<Preview::Contract::ProtocolDataPlane,
                Preview::Fault::Failure>{
                    std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument})};
            try
            {
                Plane = BuildPlane(PlaneBuildRequest{std::move(*Accepted),
                    std::move(Metadata), Route_, Material->Datagrams,
                    Material->GenerationUseState, Attempt.Owner()});
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

        [[nodiscard]] auto Name() const -> std::string_view override { return "vless"; }
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

        [[nodiscard]] static auto AcceptConnection(
            const Preview::SharedTransmission& Inbound, const ServerConfig& Configuration)
            -> Net::awaitable<std::expected<AcceptedConnection, Preview::Fault::Failure>>
        {
            try
            {
                co_return co_await Vless::Accept(Inbound, Configuration);
            }
            catch (...)
            {
                co_return std::unexpected(Preview::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception()));
            }
        }

        [[nodiscard]] static auto Track(Preview::Contract::InboundAdmission& Admission,
            Binding::AcceptAttempt& Attempt, const Preview::SharedTransmission& Connection)
            -> std::expected<void, Preview::Fault::Failure>
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
            Preview::Contract::RequestMetadata Metadata;
            const IngressRoute& Route;
            const Preview::Contract::DatagramServices& Datagrams;
            std::shared_ptr<Preview::Foundation::GenerationUseState> UseState;
            std::shared_ptr<Preview::Contract::MuxRootCreateOwner> RootOwner;
        };

        [[nodiscard]] auto BuildPlane(PlaneBuildRequest Input) const
            -> std::expected<Preview::Contract::ProtocolDataPlane, Preview::Fault::Failure>
        {
            auto Accepted = std::move(Input.Accepted);
            auto Request = std::move(Accepted.Request);
            auto Connection = std::move(Accepted.Connection);
            if (!Connection)
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            Preview::Contract::ProtocolDataPlane Plane;
            Plane.Protocol = Preview::Contract::ProtocolType::Vless;
            if (Request.Cmd != Command::Mux)
            {
                auto Target = Preview::Vless::Detail::ToNetworkTarget(Request.Target);
                if (!Target)
                {
                    return std::unexpected(
                        Preview::Contract::FailureFromProtocolError(Preview::Error::BadAddress));
                }
                Plane.Target = std::move(*Target);
            }
            Plane.AccountId = Connection->AccountId();
            Plane.Identity = std::string(Connection->Identity());
            Plane.AccountLease = Connection->TakeAuthLease();
            Plane.ProtocolAuthenticated = true;
            Preview::Protocols::DatagramBinding DatagramBinding{Input.Datagrams,
                {.Request = std::move(Input.Metadata), .Identity = Plane.Identity,
                 .DisplayIdentity = Plane.DisplayIdentity, .Protocol = Plane.Protocol,
                 .AccountId = Plane.AccountId}};
            if (Request.Cmd == Command::Mux ||
                (Input.Route.Mux && Request.Cmd == Command::Tcp))
            {
                if (Input.Route.Mux)
                {
                    Plane.Root = Preview::Contract::MuxRootDataPlane{Connection, {}};
                    auto RootRequest = Preview::Contract::MuxRootCreateRequest::Prepare(
                        std::move(Input.RootOwner), Input.UseState, std::move(Plane));
                    if (!RootRequest) return std::unexpected(RootRequest.error());
                    auto Created = Input.Route.Mux->Create(std::move(*RootRequest));
                    if (!Created) return std::unexpected(Created.error());
                    return std::move(Created->Plane);
                }
                auto Root = std::make_shared<Xudp::RootSession>(
                    Connection, std::move(DatagramBinding), std::move(Input.UseState));
                Plane.Root = Preview::Contract::MuxRootDataPlane{Connection, std::move(Root)};
            }
            else if (Request.Cmd == Command::Udp)
            {
                Plane.Root = Preview::Contract::DatagramDataPlane{
                    Connection, MakeDatagramSession(Connection, Request.Target, std::move(DatagramBinding))};
            }
            else
            {
                Plane.Root = Preview::Contract::StreamDataPlane{Connection};
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
