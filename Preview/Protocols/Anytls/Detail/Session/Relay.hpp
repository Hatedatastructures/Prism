/** @file Relay.hpp @brief AnyTLS 实际 child 的增量目标、独立 nested scope、统一 Net relay 与完成报告。 */
#pragma once
#include <Preview/Protocols/Anytls/Detail/Stream/Stream.hpp>
#include <Preview/Protocols/Anytls/Detail/Session/Target.hpp>
#include <Preview/Protocols/Mux/RootBinding.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/co_spawn.hpp>

namespace Preview::Anytls::Detail
{
    inline auto SendStatus(std::shared_ptr<State> Root, std::uint32_t Id, std::string_view Error)
        -> Net::awaitable<bool>
    {
        if (Root->PeerVersion < 2 && Error.empty()) co_return true;
        Frame Value{Root->PeerVersion >= 2 ? Command::SynAck : Command::Fin, Id};
        const auto Bytes = std::as_bytes(std::span(Error));
        if (Root->PeerVersion >= 2) Value.Payload.assign(Bytes.begin(), Bytes.end());
        const auto Sent = co_await Root->Writer->Send(std::move(Value));
        if (Sent.Failure.Failed())
        {
            Root->RecordTerminalFailure(Sent.Failure);
            Root->Stop();
            co_return false;
        }
        co_return true;
    }
    inline auto RetireFailedMuxCreate(
        std::shared_ptr<TransportRetirement> Retirement,
        Preview::Fault::Failure Failure) -> Net::awaitable<Preview::Fault::Failure>
    {
        Retirement->RetainForRetry();
        try
        {
            const auto Retired = co_await Retirement->RetireAndDrain();
            if (!Retired && !Retirement->IsRetired()) Retirement->RequestRetirement();
        }
        catch (...)
        {
            Retirement->RequestRetirement();
        }
        co_return Failure;
    }
    struct ParsedStream final { TargetRequest Request; std::vector<std::byte> Tail; };
    inline auto ReadTarget(std::shared_ptr<StreamState> Stream) -> Net::awaitable<std::expected<ParsedStream, Error>>
    {
        std::vector<std::byte> Pending;
        for (;;)
        {
            boost::system::error_code ErrorCode;
            auto Data = co_await Stream->Data->async_receive(Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (ErrorCode) co_return std::unexpected(Error::UnexpectedEof);
            Pending.insert(Pending.end(), Data.begin(), Data.end());
            auto Target = ParseTarget(Pending);
            if (Target)
            {
                std::vector<std::byte> Tail(Pending.begin() + static_cast<std::ptrdiff_t>(Target->Consumed), Pending.end());
                co_return ParsedStream{std::move(*Target), std::move(Tail)};
            }
            if (Target.error() != Error::NeedMore || Pending.size() > 260)
                co_return std::unexpected(Target.error());
        }
    }
    inline auto RelayStream(std::shared_ptr<State> Root, std::shared_ptr<StreamState> Stream,
        Preview::Foundation::TrafficObservation Observation)
        -> Net::awaitable<Preview::Network::Relay::Result>
    {
        using Preview::Fault::Code;
        auto Parsed = co_await ReadTarget(Stream);
        if (!Parsed || Parsed->Request.UnsupportedUdp)
        {
            (void)co_await SendStatus(Root, Stream->Id, "UnsupportedTarget");
            co_return Preview::Network::Relay::Result{.Failure = {Code::NotSupported}};
        }
        auto Inbound = std::make_shared<StreamTransport>(StreamTransport::Input{Root, Stream, std::move(Parsed->Tail)});
        if (Parsed->Request.NestedMux)
        {
            Preview::Mux::RootOptions Options{.Services = Root->Services, .Admission = Root->Admission,
                .GenerationUseState = Root->GenerationUseState};
            Preview::Contract::ProtocolDataPlane Plane;
            Plane.Protocol = Preview::Contract::ProtocolType::AnyTls;
            Plane.Root = Preview::Contract::MuxRootDataPlane{Inbound, {}};
            if (!Stream->Retirement ||
                !Stream->Retirement->AttachMuxRootParentStreamLease(std::move(Stream->Lease)))
            {
                co_return Preview::Network::Relay::Result{
                    .Failure = {Code::ResourceUnavailable}};
            }
            Stream->RetirementAttached = true;
            auto CreateRequest = Preview::Contract::MuxRootCreateRequest::Prepare(
                Stream->Retirement, Root->GenerationUseState, std::move(Plane));
            if (!CreateRequest)
            {
                if (Plane.HasTransport())
                {
                    Stream->Retirement->AttachMuxRootPlane(std::move(Plane));
                }
                const auto Failure = co_await RetireFailedMuxCreate(
                    Stream->Retirement, CreateRequest.error());
                co_return Preview::Network::Relay::Result{.Failure = Failure};
            }
            Preview::Mux::NestedRootFactory NestedFactory(std::move(Options));
            auto Created = NestedFactory.Create(*CreateRequest);
            if (!Created)
            {
                const auto Failure = co_await RetireFailedMuxCreate(
                    Stream->Retirement, Created.error());
                co_return Preview::Network::Relay::Result{.Failure = Failure};
            }
            auto Nested = std::move(*Created);
            Stream->Nested = Nested;
            CreateRequest->Transfer();
            if (!co_await SendStatus(Root, Stream->Id, "")) co_return Preview::Network::Relay::Result{.Failure = {Code::IoError}};
            Preview::Contract::MuxRootRequest Request;
            Request.Metadata = Root->Metadata;
            Request.Metadata.TaskIdentity = Stream->Identity;
            Request.GenerationUseState = Root->GenerationUseState;
            const auto NestedResult = co_await Nested->Run(std::move(Request));
            if (!NestedResult)
            {
                co_return Preview::Network::Relay::Result{.Failure = NestedResult.error()};
            }
            Stream->Nested.reset();
            co_return Preview::Network::Relay::Result{};
        }
        if (!Root->Services.Egress || Root->Stopping.load())
            co_return Preview::Network::Relay::Result{.Failure = {Code::Canceled}};
        auto Dialed = co_await Root->Services.Egress->Connect(Parsed->Request.Target);
        if (!Dialed)
        {
            (void)co_await SendStatus(Root, Stream->Id, "DialFailed");
            co_return Preview::Network::Relay::Result{.Failure = Dialed.error()};
        }
        Stream->Outbound = std::move(*Dialed);
        if (!co_await SendStatus(Root, Stream->Id, "")) co_return Preview::Network::Relay::Result{.Failure = {Code::IoError}};
        co_return co_await Preview::Network::Relay::Run(
            {Inbound, Stream->Outbound, Root->Services.BufferSize, Root->Services.IdleTimeout, Observation, Root->Services.Bytes});
    }
    [[nodiscard]] inline auto RelayFailureFromException(const std::exception_ptr Exception) noexcept
        -> Preview::Fault::Failure
    {
        try
        {
            if (Exception) std::rethrow_exception(Exception);
        }
        catch (const boost::system::system_error &Error)
        {
            const auto Native = static_cast<std::error_code>(Error.code());
            return Preview::Fault::FromNative(Native);
        }
        catch (const std::system_error &Error)
        {
            return Preview::Fault::FromNative(Error.code());
        }
        catch (...)
        {
            return {Preview::Fault::Code::IoError};
        }
        return {Preview::Fault::Code::IoError};
    }

    struct StreamCompletion final
    {
        Preview::Network::Relay::Result Relay;
        std::exception_ptr Failure;
    };
    inline auto DrainStreamOwners(std::shared_ptr<State> Root,
        std::shared_ptr<StreamState> Stream, StreamCompletion &Completion)
        -> Net::awaitable<void>
    {
        if (Stream->Outbound)
        {
            if (!Stream->Retirement)
            {
                const Preview::Fault::Failure MissingOwner{Preview::Fault::Code::Blocked};
                Root->RecordTerminalFailure(MissingOwner);
                if (!Completion.Relay.Failure.Failed()) Completion.Relay.Failure = MissingOwner;
            }
            else
            {
                const auto Attached = Stream->Retirement->Attach(
                    std::move(Stream->Outbound), std::move(Stream->Lease));
                if (!Attached)
                {
                    Root->RecordTerminalFailure(Attached.error());
                    if (!Completion.Relay.Failure.Failed())
                        Completion.Relay.Failure = Attached.error();
                }
                else
                {
                    Stream->RetirementAttached = true;
                    Stream->Retirement->RetainForRetry();
                    std::expected<void, Preview::Fault::Failure> Retired;
                    try { Retired = co_await Stream->Retirement->RetireAndDrain(); }
                    catch (...)
                    {
                        Retired = std::unexpected(
                            RelayFailureFromException(std::current_exception()));
                        Stream->Retirement->RequestRetirement();
                    }
                    if (!Retired)
                    {
                        Root->RecordTerminalFailure(Retired.error());
                        if (!Completion.Relay.Failure.Failed())
                            Completion.Relay.Failure = Retired.error();
                        if (!Stream->Retirement->IsRetired())
                            Stream->Retirement->RequestRetirement();
                    }
                }
            }
        }
        if (!Stream->Outbound && !Stream->Nested && Stream->RetirementAttached &&
            Stream->Retirement && !Stream->Retirement->IsRetired())
        {
            Stream->Retirement->RetainForRetry();
            std::expected<void, Preview::Fault::Failure> Retired;
            try { Retired = co_await Stream->Retirement->RetireAndDrain(); }
            catch (...)
            {
                Retired = std::unexpected(
                    RelayFailureFromException(std::current_exception()));
            }
            if (!Retired)
            {
                Root->RecordTerminalFailure(Retired.error());
                if (!Completion.Relay.Failure.Failed())
                    Completion.Relay.Failure = Retired.error();
                if (!Stream->Retirement->IsRetired())
                    Stream->Retirement->RequestRetirement();
            }
            if (!Stream->Retirement->IsRetired()) Root->ChildRetirementFailed = true;
        }
        if (!Stream->Nested) co_return;
        try
        {
            Stream->Nested->Close();
            const auto Activity = Stream->Nested->Activity();
            std::expected<void, Preview::Fault::Failure> NestedDrain;
            if (Activity) NestedDrain = co_await Activity->Drain();
            else NestedDrain = std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            const auto NestedRetired = Stream->Nested->IsRetired();
            if (!NestedDrain)
            {
                Root->RecordTerminalFailure(NestedDrain.error());
                if (!Completion.Relay.Failure.Failed())
                    Completion.Relay.Failure = NestedDrain.error();
            }
            if (NestedRetired) Stream->Nested.reset();
            else
            {
                const auto Failure = NestedDrain
                    ? Preview::Fault::Failure{Preview::Fault::Code::Blocked}
                    : NestedDrain.error();
                Root->RecordTerminalFailure(Failure);
                if (!Completion.Relay.Failure.Failed()) Completion.Relay.Failure = Failure;
                Root->ChildRetirementFailed = true;
            }
        }
        catch (...)
        {
            if (!Completion.Failure) Completion.Failure = std::current_exception();
            Root->ChildRetirementFailed = true;
            Root->RecordTerminalFailure(RelayFailureFromException(std::current_exception()));
        }
    }
    /** @brief 直接 child 的唯一 completion owner；自身不在被等待的 FIN/nested registry 内。 */
    inline auto RunStream(std::shared_ptr<State> Root, std::shared_ptr<StreamState> Stream) -> Net::awaitable<void>
    {
        StreamCompletion Completion{.Failure = Stream->CloseFailure};
        const auto Binding = Root->Admission.Binding();
        Preview::Foundation::TrafficObservation Observation{
            Root->Services.Traffic,
            Preview::Foundation::TrafficEvent{
                .Generation = Root->Metadata.TaskIdentity.Generation,
                .Worker = Root->Metadata.TaskIdentity.WorkerId,
                .Session = Root->Metadata.TaskIdentity.SessionId,
                .Stream = Stream->Identity.StreamId,
                .Task = Stream->Identity.TaskId,
                .Account = Binding ? Binding->AccountId() : Preview::AccountId{}}};
        try
        {
            Completion.Relay = co_await Net::co_spawn(
                Root->Executor, RelayStream(Root, Stream, Observation),
                Net::bind_cancellation_slot(Stream->Cancellation.slot(), Net::use_awaitable));
        }
        catch (...) { Completion.Relay.Failure = RelayFailureFromException(std::current_exception()); }
        if (Stream->CloseFailure) Completion.Failure = Stream->CloseFailure;
        const auto EarlyControlFailure = Stream->ControlFailure.Load();
        if (EarlyControlFailure.Failed()) Root->RecordTerminalFailure(EarlyControlFailure);
        if (Completion.Failure)
            Root->RecordTerminalFailure(RelayFailureFromException(Completion.Failure));
        const bool ExpectedLocalCancellation = Stream->IsExpectedRelayCancellation(
            Completion.Relay.Failure, Root->Stopping.load(std::memory_order_acquire));
        if (Completion.Relay.Failure.Failed() && !ExpectedLocalCancellation)
            Root->RecordTerminalFailure(Completion.Relay.Failure);
        try
        {
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        }
        catch (...)
        {
            if (!Completion.Failure) Completion.Failure = std::current_exception();
        }
        try { Stream->Data->close(); }
        catch (...) { if (!Completion.Failure) Completion.Failure = std::current_exception(); }
        co_await DrainStreamOwners(Root, Stream, Completion);
        std::expected<void, Preview::Fault::Failure> TasksDrained;
        try { TasksDrained = co_await Stream->Tasks->Drain(); }
        catch (...) { if (!Completion.Failure) Completion.Failure = std::current_exception(); }
        if (!TasksDrained) Root->RecordTerminalFailure(TasksDrained.error());
        const auto ControlFailure = Stream->ControlFailure.Load();
        if (ControlFailure.Failed()) Root->RecordTerminalFailure(ControlFailure);
        if (Completion.Failure)
            Root->RecordTerminalFailure(RelayFailureFromException(Completion.Failure));
        if (!Stream->Outbound && !Stream->Nested && Stream->Lease) Stream->Lease.Release();
        Observation.Complete();
        if (TasksDrained && !Completion.Failure && Root->Services.Traffic &&
            Stream->Identity.StreamId.Value() != 0U)
        {
            const auto Retired = co_await Preview::Foundation::RetireTraffic(
                Root->Services.Traffic,
                Preview::Foundation::TrafficRetirement{Preview::Foundation::StreamTrafficOwner{
                    Stream->Identity.WorkerId, Stream->Identity.SessionId, Stream->Identity.StreamId}});
            (void)Retired;
        }
        const bool RetirementUnknown = Stream->RetirementAttached &&
            (!Stream->Retirement || !Stream->Retirement->IsRetired());
        const auto StreamStats = Stream->Tasks->Stats();
        if (!Stream->Nested && !Stream->Outbound && !Stream->Lease &&
            !RetirementUnknown && StreamStats.Active == 0U && !StreamStats.DrainBlocked)
            Root->Streams.erase(Stream->Id);
        if (!Completion.Failure && Stream->CloseFailure)
            Completion.Failure = Stream->CloseFailure;
        if (Completion.Failure) std::rethrow_exception(Completion.Failure);
    }
    inline auto RejectStream(std::shared_ptr<State> Root, std::uint32_t Id) -> Net::awaitable<void>
    { (void)co_await SendStatus(Root, Id, "StreamQuotaExceeded"); }
    /** @brief SYN 立即持实际 StreamLease；真实 job 的 TaskId 在提交时分配，值身份保持父级字段。 */
    inline auto OpenStream(std::shared_ptr<State> Root, std::uint32_t Id) -> bool
    {
        auto Identity = Root->Metadata.TaskIdentity;
        Identity.StreamId = Preview::StreamId{Id};
        Preview::Lifecycle::TaskRequest Request{.Context = Preview::Lifecycle::FromParent(Identity), .StartOnSubmit = true};
        auto Prepared = TransportRetirement::Prepare();
        if (!Prepared)
        {
            Root->RecordTerminalFailure(Prepared.error());
            return false;
        }
        Preview::Account::StreamLease Lease;
        if (Root->Admission)
        {
            auto Acquired = Root->Admission.Acquire();
            if (!Acquired)
                return bool(Root->Children->SpawnTracked(std::move(Request), RejectStream(Root, Id)));
            Lease = std::move(*Acquired);
        }
        auto Stream = std::make_shared<StreamState>(Root->Executor, Root->Children->CreateChild());
        Stream->Retirement = std::move(*Prepared);
        Stream->Id = Id; Stream->Lease = std::move(Lease);
        const auto Weak = std::weak_ptr<StreamState>(Stream);
        Request.Cancel = [Weak] { if (const auto Owner = Weak.lock()) Owner->Cancel(); };
        const auto Task = Root->Children->SpawnTracked(std::move(Request), RunStream(Root, Stream));
        if (!Task) { Stream->Cancel(); return false; }
        Stream->Identity = Task->Identity();
        Root->Streams.emplace(Id, std::move(Stream));
        return true;
    }
}
