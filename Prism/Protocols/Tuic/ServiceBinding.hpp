/** @file ServiceBinding.hpp @brief TUIC 地址、租约与 payload 到正式网络服务的单次转换。 */
#pragma once
#include <Prism/Protocols/Tuic/Detail/Target.hpp>
#include <Prism/Protocols/Tuic/Admission.hpp>
#include <Prism/Contract/Services/Quic.hpp>
#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>
#include <algorithm>
namespace Prism::Tuic
{
    inline auto ExchangePrepared(std::shared_ptr<Prism::Contract::DatagramEgress> Egress,DatagramRequest Request)
        -> Net::awaitable<DatagramResult>
    {
        auto Target = Prism::Tuic::Detail::ToNetworkTarget(Request.Target);
        if (!Target) co_return DatagramResult{.Status=Prism::Error::BadAddress};
        std::vector<std::byte> Bytes(Request.Payload.size());
        std::transform(Request.Payload.begin(),Request.Payload.end(),Bytes.begin(),[](auto Byte){return static_cast<std::byte>(Byte);});
        auto Result=co_await Egress->Exchange({std::move(*Target),std::move(Bytes),Request.AccountId});
        std::vector<std::uint8_t> Payload(Result.Payload.size());
        std::transform(Result.Payload.begin(),Result.Payload.end(),Payload.begin(),[](auto Byte){return std::to_integer<std::uint8_t>(Byte);});
        const auto Size=Payload.size();
        auto Status = Prism::Error::IoError;
        if (Result.Failure.Succeeded()) Status = Prism::Error::None;
        auto Type = AddressType::Ipv6;
        if (Result.Source.address().is_v4()) Type = AddressType::Ipv4;
        co_return DatagramResult{Status,
            {Type,Result.Source.address().to_string(),Result.Source.port()},
            std::move(Payload),Result.Uploaded,Size};
    }
    /** @brief 接管已经认证的stream请求，转换目标失败时关闭双方，成功移交唯一relay owner。 */
    inline auto RelayPrepared(std::shared_ptr<Prism::Contract::StreamRelay> Relay, StreamRelayRequest Request)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        auto Target = Prism::Tuic::Detail::ToNetworkTarget(Request.Request.dst);
        if (!Target)
        {
            if (Request.Inbound) Request.Inbound->Close();
            if (Request.Outbound) Request.Outbound->Close();
            co_return std::unexpected(Target.error());
        }
        Prism::Contract::StreamRelayRequest RelayRequest{
            .Inbound=std::move(Request.Inbound), .Outbound=std::move(Request.Outbound),
            .Target=std::move(*Target), .AccountId=Request.AccountId,
            .Identity=std::move(Request.Identity), .Lease=std::move(Request.Lease),
            .Metadata=Request.Metadata};
        co_return co_await Relay->Run(std::move(RelayRequest));
    }
    /** @brief 观察 datagram 完成字节；观察失败不改变 TUIC 协议错误和关闭路径。 */
    inline auto ReportDatagramTraffic(const std::shared_ptr<Prism::Foundation::TrafficSink> &Traffic,
        const DatagramSessionReport &Report) noexcept -> void
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
                Observation.Transfer(
                    Report.UploadedBytes,
                    Prism::Foundation::TrafficObservation::Direction::Upload);
                Observation.Transfer(
                    Report.DownloadedBytes,
                    Prism::Foundation::TrafficObservation::Direction::Download);
            }
            else
            {
                Observation.Complete();
            }
        }
        catch(...){ }
    }
    /** @brief 会话独立持有网络端口，唯一 stream lease 直接 move；不创建 Runtime/Middleware context。 */
    [[nodiscard]] inline auto BindServices(Prism::Contract::QuicBindingServices Services,std::string SourceIp)->AdmissionServices
    {
        AdmissionServices Result;
        Result.Dial=[Egress=Services.Streams](DialRequest Request)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
        {
            auto Target = Prism::Tuic::Detail::ToNetworkTarget(Request.Target);
            if (!Target) co_return std::unexpected(Target.error());
            co_return co_await Egress->Connect(std::move(*Target));
        };
        Result.RelayStream=[Relay=Services.Relay](StreamRelayRequest Request)->Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        { co_return co_await RelayPrepared(Relay, std::move(Request)); };
        Result.ReportStreamFailure=[Trace=Services.Trace](StreamFailureReport Report)
        {
            (void)Prism::Diagnose::Trace(Trace,
                "TuicStreamFailure Session={} Stream={} Code={} NativeCategory={} NativeValue={}",
                Report.TaskIdentity.SessionId.Value(),
                Report.ConnectionStreamId,
                static_cast<int>(Report.Failure.Code),
                Report.Failure.Native.category().name(),
                Report.Failure.Native.value());
        };
        Result.Resolve=[](ResolveRequest Request)->Net::awaitable<ResolveResult>
        {co_return ResolveResult{Prism::Error::None,{std::move(Request.Target)}};};
        Result.ExchangeDatagram=[Egress=Services.Datagrams](DatagramRequest Request)->Net::awaitable<DatagramResult>
        {co_return co_await ExchangePrepared(Egress,std::move(Request));};
        Result.ReportDatagramSession=[Traffic=Services.Traffic,Trace=Services.Trace,Source=std::move(SourceIp)](DatagramSessionReport Report)
        {
            ReportDatagramTraffic(Traffic,Report);
            if (Report.Kind == Prism::Foundation::TrafficEventKind::Completed)
            {
                (void)Prism::Diagnose::Trace(Trace,"UdpSessionSummary SourceIp={} Datagrams={} UpBytes={} DownBytes={}",
                    Source,Report.DatagramCount,Report.UploadedBytes,Report.DownloadedBytes);
            }
        };
        return Result;
    }
}
