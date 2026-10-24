/**
 * @file ServiceBinding.cpp
 * @brief Hysteria2 wire 请求到 owning network services 的转换。
 */
#include "ServiceBinding.hpp"

#include <Prism/Net/Target.hpp>
#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <Prism/Protocols/Hysteria2/Types.hpp>

#include <algorithm>
#include <cstddef>
#include <span>
#include <utility>
#include <vector>

namespace Prism::Hysteria2
{
    namespace Net = boost::asio;

    namespace
    {
        [[nodiscard]] auto ToNetworkTarget(const Address& Input)
            -> std::expected<Prism::Network::Target, Prism::Fault::Failure>
        {
            auto Encoding = Prism::Network::HostEncoding::Domain;
            switch (Input.Type)
            {
            case AddressType::Ipv4:
                Encoding = Prism::Network::HostEncoding::Ipv4Text;
                break;
            case AddressType::Ipv6:
                Encoding = Prism::Network::HostEncoding::Ipv6Text;
                break;
            case AddressType::Domain:
                break;
            default:
                return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument, {}});
            }
            auto Host = Prism::Network::DecodeHost(Encoding, Input.Host);
            if (!Host)
            {
                return std::unexpected(Host.error());
            }
            return Prism::Network::Target{
                std::move(*Host), Input.Port, Prism::Network::RouteKind::Forward};
        }

        auto ReportStreamBytes(
            Prism::Foundation::TrafficObservation Observation,
            const std::size_t Uploaded,
            Prism::Fault::Failure Failure) noexcept -> void
        {
            Observation.Transfer(
                Uploaded, Prism::Foundation::TrafficObservation::Direction::Upload);
            Observation.Complete(Failure);
        }

        [[nodiscard]] auto RelayPrepared(
            const std::shared_ptr<Prism::Contract::StreamRelay>& Relay,
            const std::shared_ptr<Prism::Foundation::TrafficSink>& Traffic,
            StreamRelayRequest Request)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            auto Inbound = std::make_shared<Prism::Quic::StreamAdapter>(
                Request.Inbound->Executor(), Request.Inbound,
                std::move(Request.InitialReadTerminal));
            Prism::Foundation::TrafficObservation Observation{
                Traffic,
                Prism::Foundation::TrafficEvent{
                    .Generation = Request.Metadata.TaskIdentity.Generation,
                    .Worker = Request.Metadata.TaskIdentity.WorkerId,
                    .Session = Request.Metadata.TaskIdentity.SessionId,
                    .Stream = Request.Metadata.TaskIdentity.StreamId,
                    .Task = Request.Metadata.TaskIdentity.TaskId,
                    .Account = Request.AccountId}};
            std::size_t Offset = 0;
            while (Offset < Request.InitialPayload.size())
            {
                const auto Part = co_await Request.Outbound->WriteSome(
                    std::span(Request.InitialPayload).subspan(Offset));
                const auto Count = Part.Bytes;
                const auto Remaining = Request.InitialPayload.size() - Offset;
                if (Count <= Remaining)
                {
                    Offset += Count;
                }
                if (Part.Failure.Failed() || Count == 0 || Count > Remaining)
                {
                    auto Failure = Part.Failure;
                    if (Count > Remaining)
                    {
                        Failure = {Prism::Fault::Code::InvalidArgument};
                    }
                    else if (Failure.Succeeded())
                    {
                        Failure = {Prism::Fault::Code::WouldBlock};
                    }
                    ReportStreamBytes(Observation, Offset, Failure);
                    const auto InboundClose = Inbound->Close();
                    const auto OutboundClose = Request.Outbound->Close();
                    if (!InboundClose)
                    {
                        co_return InboundClose;
                    }
                    if (!OutboundClose)
                    {
                        co_return OutboundClose;
                    }
                    co_return std::unexpected(Failure);
                }
            }

            if (Request.InitialFin)
            {
                const auto Shutdown = co_await Request.Outbound->WriteShutdown();
                if (!Shutdown)
                {
                    ReportStreamBytes(Observation, Offset, Shutdown.error());
                    const auto InboundClose = Inbound->Close();
                    const auto OutboundClose = Request.Outbound->Close();
                    if (!InboundClose)
                    {
                        co_return InboundClose;
                    }
                    if (!OutboundClose)
                    {
                        co_return OutboundClose;
                    }
                    co_return Shutdown;
                }
            }

            Prism::Contract::StreamRelayRequest RelayRequest{
                .Inbound = std::move(Inbound),
                .Outbound = std::move(Request.Outbound),
                .Target = std::move(Request.Target),
                .AccountId = Request.AccountId,
                .Identity = std::move(Request.Identity),
                .Lease = std::move(Request.Lease),
                .Metadata = Request.Metadata,
                .InitialUploadBytes = Offset};
            co_return co_await Relay->Run(std::move(RelayRequest));
        }

        [[nodiscard]] auto ExchangePrepared(
            const std::shared_ptr<Prism::Contract::DatagramEgress>& Egress,
            DatagramRequest Request) -> Net::awaitable<DatagramResult>
        {
            auto Target = ToNetworkTarget(Request.Target);
            if (!Target)
            {
                co_return DatagramResult{.Status = Prism::Fault::Code::InvalidArgument};
            }
            std::vector<std::byte> Bytes(Request.Payload.size());
            std::transform(Request.Payload.begin(), Request.Payload.end(), Bytes.begin(),
                [](const auto Byte) { return static_cast<std::byte>(Byte); });
            auto Result = co_await Egress->Exchange(
                {std::move(*Target), std::move(Bytes), Request.AccountId});
            std::vector<std::uint8_t> Payload(Result.Payload.size());
            std::transform(Result.Payload.begin(), Result.Payload.end(), Payload.begin(),
                [](const auto Byte) { return std::to_integer<std::uint8_t>(Byte); });
            const auto Size = Payload.size();
            auto Type = AddressType::Ipv6;
            if (Result.Source.address().is_v4())
            {
                Type = AddressType::Ipv4;
            }
            co_return DatagramResult{
                Result.Failure.Code,
                {Type, Result.Source.address().to_string(), Result.Source.port()},
                std::move(Payload), Result.Uploaded, Size};
        }

        auto ReportDatagramTraffic(
            const std::shared_ptr<Prism::Foundation::TrafficSink>& Traffic,
            const DatagramSessionReport& Report) noexcept -> void
        {
            try
            {
                Prism::Foundation::TrafficObservation Observation{
                    Traffic,
                    Prism::Foundation::TrafficEvent{
                        .Generation = Report.Metadata.TaskIdentity.Generation,
                        .Worker = Report.Metadata.TaskIdentity.WorkerId,
                        .Session = Report.Metadata.TaskIdentity.SessionId,
                        .Stream = Report.Metadata.TaskIdentity.StreamId,
                        .Task = Report.Metadata.TaskIdentity.TaskId,
                        .Account = Report.AccountId}};
                if (Report.Kind == Prism::Foundation::TrafficEventKind::Bytes)
                {
                    Observation.Transfer(Report.UploadedBytes,
                        Prism::Foundation::TrafficObservation::Direction::Upload);
                    Observation.Transfer(Report.DownloadedBytes,
                        Prism::Foundation::TrafficObservation::Direction::Download);
                }
                else
                {
                    Observation.Complete();
                }
            }
            catch (...)
            {
            }
        }
    }

    [[nodiscard]] auto BindServices(Prism::Contract::QuicBindingServices Services)
        -> AdmissionServices
    {
        AdmissionServices Result;
        Result.Dial = [Egress = Services.Streams](DialRequest Request)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
        {
            co_return co_await Egress->Connect(std::move(Request.Target));
        };
        Result.RelayStream = [Relay = Services.Relay, Traffic = Services.Traffic](
            StreamRelayRequest Request)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_return co_await RelayPrepared(Relay, Traffic, std::move(Request));
        };
        Result.Resolve = [](ResolveRequest Request) -> Net::awaitable<ResolveResult>
        {
            co_return ResolveResult{Prism::Fault::Code::Success, {std::move(Request.Target)}};
        };
        Result.ExchangeDatagram = [Egress = Services.Datagrams](DatagramRequest Request)
            -> Net::awaitable<DatagramResult>
        {
            co_return co_await ExchangePrepared(Egress, std::move(Request));
        };
        Result.ReportDatagram = [Traffic = Services.Traffic](DatagramSessionReport Report)
        {
            ReportDatagramTraffic(Traffic, Report);
        };
        return Result;
    }

} // namespace Prism::Hysteria2
