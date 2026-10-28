/**
 * @file ServiceBinding.cpp
 * @brief TUIC wire 请求到 owning network services 的转换。
 */
#include <Prism/Protocols/Tuic/Detail/Binding.hpp>

#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>
#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <Prism/Net/Target.hpp>
#include <Prism/Protocols/Tuic/Types.hpp>

#include <algorithm>
#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace Prism::Tuic
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
                Encoding = Prism::Network::HostEncoding::Ipv6Bytes;
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

        [[nodiscard]] auto ExchangePrepared(
            const std::shared_ptr<Prism::Contract::DatagramEgress>& Egress,
            DatagramRequest Request) -> Net::awaitable<DatagramResult>
        {
            auto Target = ToNetworkTarget(Request.Target);
            if (!Target)
            {
                co_return DatagramResult{.Status = Prism::Error::BadAddress};
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
            auto Status = Prism::Error::IoError;
            if (Result.Failure.Succeeded())
            {
                Status = Prism::Error::None;
            }
            auto Type = AddressType::Ipv6;
            if (Result.Source.address().is_v4())
            {
                Type = AddressType::Ipv4;
            }
            co_return DatagramResult{
                Status,
                {Type, Result.Source.address().to_string(), Result.Source.port()},
                std::move(Payload), Result.Uploaded, Size};
        }

        [[nodiscard]] auto RelayPrepared(
            const std::shared_ptr<Prism::Contract::StreamRelay>& Relay,
            StreamRelayRequest Request)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            auto Target = ToNetworkTarget(Request.Request.dst);
            if (!Target)
            {
                if (Request.Inbound)
                {
                    (void)Request.Inbound->Close();
                }
                if (Request.Outbound)
                {
                    (void)Request.Outbound->Close();
                }
                co_return std::unexpected(Target.error());
            }
            Prism::Contract::StreamRelayRequest RelayRequest{
                .Inbound = std::move(Request.Inbound),
                .Outbound = std::move(Request.Outbound),
                .Target = std::move(*Target),
                .AccountId = Request.AccountId,
                .Identity = std::move(Request.Identity),
                .Lease = std::move(Request.Lease),
                .Metadata = Request.Metadata};
            co_return co_await Relay->Run(std::move(RelayRequest));
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

        template<class Trace>
        auto ReportDatagramSessionSummary(
            const Trace& TraceValue,
            const std::string& Source,
            const DatagramSessionReport& Report) -> void
        {
            if (Report.Kind != Prism::Foundation::TrafficEventKind::Completed)
            {
                return;
            }
            (void)Prism::Diagnose::Trace(TraceValue,
                "UdpSessionSummary SourceIp={} Datagrams={} UpBytes={} DownBytes={}",
                Source, Report.DatagramCount, Report.UploadedBytes,
                Report.DownloadedBytes);
        }
    }

    [[nodiscard]] auto BindServices(
        Prism::Contract::QuicBindingServices Services,
        std::string SourceIp) -> AdmissionServices
    {
        AdmissionServices Result;
        Result.Dial = [Egress = Services.Streams](DialRequest Request)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
        {
            auto Target = ToNetworkTarget(Request.Target);
            if (!Target)
            {
                co_return std::unexpected(Target.error());
            }
            co_return co_await Egress->Connect(std::move(*Target));
        };
        Result.RelayStream = [Relay = Services.Relay](StreamRelayRequest Request)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_return co_await RelayPrepared(Relay, std::move(Request));
        };
        Result.ReportStreamFailure = [Trace = Services.Trace](StreamFailureReport Report)
        {
            (void)Prism::Diagnose::Trace(Trace,
                "TuicStreamFailure Session={} Stream={} Code={} NativeCategory={} NativeValue={}",
                Report.TaskIdentity.SessionId.Value(), Report.ConnectionStreamId,
                static_cast<int>(Report.Failure.Code), Report.Failure.Native.category().name(),
                Report.Failure.Native.value());
        };
        Result.Resolve = [](ResolveRequest Request) -> Net::awaitable<ResolveResult>
        {
            co_return ResolveResult{Prism::Error::None, {std::move(Request.Target)}};
        };
        Result.ExchangeDatagram = [Egress = Services.Datagrams](DatagramRequest Request)
            -> Net::awaitable<DatagramResult>
        {
            co_return co_await ExchangePrepared(Egress, std::move(Request));
        };
        Result.ReportDatagramSession = [Traffic = Services.Traffic,
            Trace = Services.Trace, Source = std::move(SourceIp)](DatagramSessionReport Report)
        {
            ReportDatagramTraffic(Traffic, Report);
            ReportDatagramSessionSummary(Trace, Source, Report);
        };
        return Result;
    }

} // namespace Prism::Tuic
