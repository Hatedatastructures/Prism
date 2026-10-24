/** @file IngressFactory.hpp @brief VMess 唯一 bound owner 接入与 session 退休入口。 */
#pragma once

#include <Prism/Protocols/Vmess/Binding.hpp>
#include <Prism/Contract/Ingress/MuxRootCreateRequest.hpp>
#include <Prism/Transport/Replay.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Contract/Ingress/StreamFactory.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <expected>
#include <memory>
#include <string_view>
#include <utility>

namespace Prism::Vmess
{
    namespace Net = boost::asio;

    class IngressFactory final : public Prism::Contract::StreamFactory
    {
    public:
        ~IngressFactory() override;

        auto Accept(Prism::Contract::StreamAcceptInput Input)
            -> Net::awaitable<Prism::Contract::AcceptOutcome> override;

        [[nodiscard]] auto Name() const -> std::string_view override;
        auto Close() noexcept -> void;
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        [[nodiscard]] auto IsRetired() const noexcept -> bool;
        [[nodiscard]] auto GenerationUseState() const noexcept
            -> std::shared_ptr<Prism::Foundation::GenerationUseState>;

    private:
        friend class Binding;

        IngressFactory(std::shared_ptr<const Binding> Owner, IngressRoute Route);

        [[nodiscard]] static auto CreateReplay(
            const Prism::SharedTransmission& Inbound,
            std::shared_ptr<Prism::Memory::BytePool> Bytes)
            -> std::expected<std::shared_ptr<Prism::Transport::ReplayTransmission>,
                Prism::Fault::Failure>;

        [[nodiscard]] static auto Track(Prism::Contract::InboundAdmission& Admission,
            Binding::AcceptAttempt& Attempt, const Prism::SharedTransmission& Transport)
            -> std::expected<void, Prism::Fault::Failure>;

        [[nodiscard]] static auto AcceptCandidate(
            const std::shared_ptr<Prism::Transport::ReplayTransmission>& Replay,
            const ServerConfig& Configuration,
            const Prism::Account::CredentialIndexView& CredentialScope)
            -> Net::awaitable<std::expected<AcceptedSession, Prism::Fault::Failure>>;

        struct PlaneBuildRequest final
        {
            AcceptedSession Accepted;
            Prism::Contract::RequestMetadata Metadata;
            const IngressRoute& Route;
            const Prism::Contract::DatagramServices& Datagrams;
            std::shared_ptr<Prism::Contract::MuxRootCreateOwner> RootOwner;
            std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
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
            -> std::expected<Prism::Contract::ProtocolDataPlane, Prism::Fault::Failure>;

        std::shared_ptr<const Binding> Binding_;
        IngressRoute Route_;
    };

}
