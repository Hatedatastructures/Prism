/** @file ServiceBinding.hpp @brief Hysteria2 wire 请求到正式网络服务的一次语义转换。 */
#pragma once
#include <Preview/Protocols/Hysteria2/Detail/Target.hpp>
#include <Preview/Protocols/Hysteria2/Admission.hpp>
#include <Preview/Contract/Services/Quic.hpp>
namespace Preview::Hysteria2
{
    /** @brief 只观察初始 payload 的真实成功字节；观察异常不得改变 QUIC 关闭结果。 */
    inline auto ReportStreamBytes(Preview::Foundation::TrafficObservation Observation,
        const std::size_t Uploaded, Preview::Fault::Failure Failure) noexcept -> void
    {
        Observation.Transfer(Uploaded,
            Preview::Foundation::TrafficObservation::Direction::Upload);
        Observation.Complete(Failure);
    }
    inline auto RelayPrepared(std::shared_ptr<Preview::Contract::StreamRelay> Relay,
        std::shared_ptr<Preview::Foundation::TrafficSink> Traffic, StreamRelayRequest Request)
        -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        auto Inbound=std::make_shared<Preview::Quic::StreamAdapter>(Request.Inbound->Executor(),Request.Inbound);
        Preview::Foundation::TrafficObservation Observation{
            Traffic,
            Preview::Foundation::TrafficEvent{
                .Generation = Request.Metadata.TaskIdentity.Generation,
                .Worker = Request.Metadata.TaskIdentity.WorkerId,
                .Session = Request.Metadata.TaskIdentity.SessionId,
                .Stream = Request.Metadata.TaskIdentity.StreamId,
                .Task = Request.Metadata.TaskIdentity.TaskId,
                .Account = Request.AccountId}};
        std::size_t Offset=0;
        while(Offset<Request.InitialPayload.size())
        {
            const auto Part = co_await Request.Outbound->WriteSome(std::span(Request.InitialPayload).subspan(Offset));
            const auto Count = Part.Bytes;
            const auto Remaining=Request.InitialPayload.size()-Offset;
            if (Count <= Remaining) Offset += Count;
            if (Part.Failure.Failed() || Count == 0 || Count > Remaining)
            {
                auto Failure = Part.Failure;
                if (Count > Remaining) Failure = {Preview::Fault::Code::InvalidArgument};
                else if (Failure.Succeeded()) Failure = {Preview::Fault::Code::WouldBlock};
                ReportStreamBytes(Observation, Offset, Failure);
                const auto First = Inbound->Close();
                const auto Second = Request.Outbound->Close();
                if (!First) co_return First;
                if (!Second) co_return Second;
                co_return std::unexpected(Failure);
            }
        }
        if (Request.InitialFin)
        {
            const auto Shutdown = co_await Request.Outbound->WriteShutdown();
            if (!Shutdown)
            {
                ReportStreamBytes(Observation, Offset, Shutdown.error());
                const auto First = Inbound->Close();
                const auto Second = Request.Outbound->Close();
                if (!First) co_return First;
                if (!Second) co_return Second;
                co_return Shutdown;
            }
        }
        Preview::Contract::StreamRelayRequest RelayRequest{
            .Inbound=std::move(Inbound), .Outbound=std::move(Request.Outbound),
            .Target=std::move(Request.Target), .AccountId=Request.AccountId,
            .Identity=std::move(Request.Identity), .Lease=std::move(Request.Lease),
            .Metadata=Request.Metadata, .InitialUploadBytes=Offset};
        co_return co_await Relay->Run(std::move(RelayRequest));
    }
    inline auto ExchangePrepared(std::shared_ptr<Preview::Contract::DatagramEgress> Egress,DatagramRequest Request)
        -> Net::awaitable<DatagramResult>
    {
        auto Target = Preview::Hysteria2::Detail::ToNetworkTarget(Request.Target);
        if (!Target) co_return DatagramResult{.Status=Preview::Fault::Code::InvalidArgument};
        std::vector<std::byte> Bytes(Request.Payload.size());
        std::transform(Request.Payload.begin(),Request.Payload.end(),Bytes.begin(),[](auto Byte){return static_cast<std::byte>(Byte);});
        auto Result=co_await Egress->Exchange({std::move(*Target),std::move(Bytes),Request.AccountId});
        std::vector<std::uint8_t> Payload(Result.Payload.size());
        std::transform(Result.Payload.begin(),Result.Payload.end(),Payload.begin(),[](auto Byte){return std::to_integer<std::uint8_t>(Byte);});
        const auto Size=Payload.size();
        auto Type = AddressType::Ipv6;
        if (Result.Source.address().is_v4()) Type = AddressType::Ipv4;
        co_return DatagramResult{Result.Failure.Code,{Type,
            Result.Source.address().to_string(),Result.Source.port()},std::move(Payload),Result.Uploaded,Size};
    }
    /** @brief 观察 datagram 完成字节；观察失败只被吞掉，不改变协议结果。 */
    inline auto ReportDatagramTraffic(const std::shared_ptr<Preview::Foundation::TrafficSink> &Traffic,
        const DatagramSessionReport &Report) noexcept -> void
    {
        try
        {
            Preview::Foundation::TrafficObservation Observation{
                Traffic,
                Preview::Foundation::TrafficEvent{
                    .Generation = Report.Metadata.TaskIdentity.Generation,
                    .Worker = Report.Metadata.TaskIdentity.WorkerId,
                    .Session = Report.Metadata.TaskIdentity.SessionId,
                    .Stream = Report.Metadata.TaskIdentity.StreamId,
                    .Task = Report.Metadata.TaskIdentity.TaskId,
                    .Account = Report.AccountId}};
            if (Report.Kind == Preview::Foundation::TrafficEventKind::Bytes)
            {
                Observation.Transfer(
                    Report.UploadedBytes,
                    Preview::Foundation::TrafficObservation::Direction::Upload);
                Observation.Transfer(
                    Report.DownloadedBytes,
                    Preview::Foundation::TrafficObservation::Direction::Download);
            }
            else
            {
                Observation.Complete();
            }
        }
        catch (...) {}
    }
    /** @brief 保留 owning 单用途服务；取消沿 await 透传，报告失败不进入业务错误路径。 */
    [[nodiscard]] inline auto BindServices(Preview::Contract::QuicBindingServices Services)->AdmissionServices
    {
        AdmissionServices Result;
        Result.Dial=[Egress=Services.Streams](DialRequest Request)
            -> Net::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>
        { co_return co_await Egress->Connect(std::move(Request.Target)); };
        Result.RelayStream=[Relay=Services.Relay,Traffic=Services.Traffic](StreamRelayRequest Request)->Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {co_return co_await RelayPrepared(Relay,Traffic,std::move(Request));};
        Result.Resolve=[](ResolveRequest Request)->Net::awaitable<ResolveResult>
        {co_return ResolveResult{Preview::Fault::Code::Success,{std::move(Request.Target)}};};
        Result.ExchangeDatagram=[Egress=Services.Datagrams](DatagramRequest Request)->Net::awaitable<DatagramResult>
        {co_return co_await ExchangePrepared(Egress,std::move(Request));};
        Result.ReportDatagram=[Traffic=Services.Traffic](DatagramSessionReport Report)
        { ReportDatagramTraffic(Traffic,Report); };
        return Result;
    }
}
