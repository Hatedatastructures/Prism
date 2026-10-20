/** @file SessionCarrierInstallation.cpp @brief 会话实际载体所有权移交实现。 */
#include <Prism/Runtime/Session/CarrierInstallation.hpp>

#include <utility>

namespace Prism::Runtime
{
    auto SessionCarrierInstallation::AcceptedDataPlane(
        ActiveTransports& Active,
        Prism::Contract::ProtocolDataPlane& DataPlane)
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (auto* Stream = DataPlane.Stream())
        {
            return Inbound(Active, Stream->Transport);
        }
        if (auto* Datagram = DataPlane.Datagram())
        {
            return InstallDatagram(Active, *Datagram);
        }
        if (auto* Mux = DataPlane.Mux())
        {
            return InstallMux(Active, *Mux);
        }
        return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
    }

    auto SessionCarrierInstallation::Inbound(
        ActiveTransports& Active,
        Prism::SharedTransmission& Carrier)
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!Carrier) return {};
        auto Domain = CreateDomain(Carrier);
        if (!Domain) return std::unexpected(Domain.error());
        auto Installed = Active.StoreInbound(std::move(Carrier), *Domain);
        if (!Installed) return std::unexpected(Installed.error());
        Carrier = std::move(*Installed);
        return {};
    }

    auto SessionCarrierInstallation::Outbound(
        ActiveTransports& Active,
        Prism::SharedTransmission& Carrier)
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!Carrier) return {};
        auto Domain = CreateDomain(Carrier);
        if (!Domain) return std::unexpected(Domain.error());
        auto Installed = Active.StoreOutbound(std::move(Carrier), *Domain);
        if (!Installed) return std::unexpected(Installed.error());
        Carrier = std::move(*Installed);
        return {};
    }

    auto SessionCarrierInstallation::CreateProtocolDomain(
        std::shared_ptr<Prism::Contract::CarrierActivity> Activity,
        const Prism::SharedTransmission& Carrier)
        -> std::expected<CarrierDomain, Prism::Fault::Failure>
    {
        const auto Executor = Activity ? Activity->Executor()
            : (Carrier ? Carrier->Executor() : boost::asio::any_io_executor{});
        auto Domain = CarrierDomain::Create(Executor, Activity);
        if (Domain) return Domain;
        if (Carrier)
        {
            auto HoldingDomain = CarrierDomain::Create(Carrier->Executor(), {});
            if (HoldingDomain) return HoldingDomain;
        }
        return std::unexpected(Domain.error());
    }

    auto SessionCarrierInstallation::InstallDatagram(
        ActiveTransports& Active,
        Prism::Contract::DatagramDataPlane& Datagram)
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!Datagram.Session)
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
        }
        auto Domain = CreateProtocolDomain(Datagram.Session->Activity(), Datagram.Transport);
        if (!Domain) return std::unexpected(Domain.error());
        auto Installed = Active.StoreDatagram(std::move(Datagram.Session), *Domain);
        if (!Installed) return std::unexpected(Installed.error());
        Datagram.Session = std::move(*Installed);
        return {};
    }

    auto SessionCarrierInstallation::InstallMux(
        ActiveTransports& Active,
        Prism::Contract::MuxRootDataPlane& Mux)
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!Mux.Session)
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
        }
        auto Domain = CreateProtocolDomain(Mux.Session->Activity(), Mux.Transport);
        if (!Domain) return std::unexpected(Domain.error());
        auto Installed = Active.StoreMux(std::move(Mux.Session), *Domain);
        if (!Installed) return std::unexpected(Installed.error());
        Mux.Session = std::move(*Installed);
        return {};
    }

    auto SessionCarrierInstallation::CreateDomain(const Prism::SharedTransmission& Carrier)
        -> std::expected<CarrierDomain, Prism::Fault::Failure>
    {
        const auto Activity = Carrier->Activity();
        auto Domain = CarrierDomain::Create(
            Activity ? Activity->Executor() : Carrier->Executor(), Activity);
        if (Domain) return Domain;
        auto HoldingDomain = CarrierDomain::Create(Carrier->Executor(), {});
        if (HoldingDomain) return HoldingDomain;
        return std::unexpected(Domain.error());
    }
}
