/** @file IngressFactory.hpp @brief VLESS 唯一 bound owner 接入与 session 退休入口。 */
#pragma once

#include <Prism/Protocols/Vless/Binding.hpp>
#include <Prism/Protocols/Common/DatagramBinding.hpp>
#include <Prism/Contract/Ingress/MuxRootCreateRequest.hpp>
#include <Prism/Contract/Ingress/StreamFactory.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <expected>
#include <memory>
#include <string_view>
#include <utility>

namespace Prism::Vless
{
    /** @brief 接管载体与数据报服务，构造唯一的 VLESS UDP session owner。 */
    [[nodiscard]] auto MakeDatagramSession(
        std::shared_ptr<Conn<>> Carrier,
        Address Target,
        Prism::Protocols::DatagramBinding Binding)
        -> std::shared_ptr<Prism::Contract::DatagramSession>;

    class IngressFactory final : public Prism::Contract::StreamFactory
    {
    public:
        /** @brief 已绑定配置只通过 Binding 派生，不接受第二份配置副本。 */
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

        [[nodiscard]] static auto AcceptConnection(
            const Prism::SharedTransmission& Inbound, const ServerConfig& Configuration)
            -> Net::awaitable<std::expected<AcceptedConnection, Prism::Fault::Failure>>;

        [[nodiscard]] static auto Track(Prism::Contract::InboundAdmission& Admission,
            Binding::AcceptAttempt& Attempt, const Prism::SharedTransmission& Connection)
            -> std::expected<void, Prism::Fault::Failure>;

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
            -> std::expected<Prism::Contract::ProtocolDataPlane, Prism::Fault::Failure>;

        std::shared_ptr<const Binding> Binding_;
        IngressRoute Route_;
    };

}
