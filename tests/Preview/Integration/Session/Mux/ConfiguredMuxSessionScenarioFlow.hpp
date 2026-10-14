/**
 * @file ConfiguredMuxSessionScenarioFlow.hpp
 * @brief 配置化 Mux 单根场景的异步流程与构造.
 */
#pragma once

#include "ConfiguredMuxSessionScenarioTypes.hpp"
#include <Preview/Composition/Protocol/ProtocolCatalog.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>

namespace
{
    /** @brief 构造带真实有界字节池的配置化协议接入输入。 */
    [[nodiscard]] auto MakeScenarioAcceptInput(const std::shared_ptr<ScenarioState> &State)
        -> Preview::Contract::StreamAcceptInput
    {
        return {State->Server, State->Metadata, State->Bytes};
    }

    auto RunQuotaContinuation(
        const std::shared_ptr<ScenarioState> &State,
        const std::shared_ptr<Tcp::socket> &Socket) -> Net::awaitable<bool>
    {
        std::vector<std::byte> Received(Continuation.size());
        boost::system::error_code Error;
        const auto Count = co_await Net::async_read(
            *Socket, Net::buffer(Received), Net::redirect_error(Net::use_awaitable, Error));
        const auto Expected = std::as_bytes(std::span(Continuation));
        if (Error || Count != Received.size() ||
            !std::equal(Received.begin(), Received.end(), Expected.begin(), Expected.end()))
        {
            State->FailureMessage = "TCP backend continuation payload was invalid";
            co_return false;
        }
        State->BackendContinuationBytes = Count;
        State->BackendContinuationReceived = true;
        co_await Net::async_write(
            *Socket, Net::buffer(Received), Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            State->FailureMessage = "TCP backend continuation echo failed";
            co_return false;
        }
        State->BackendContinuationEchoed = true;
        co_return true;
    }

    auto RunReplacementBackend(const std::shared_ptr<ScenarioState> &State) -> Net::awaitable<bool>
    {
        auto Socket = std::make_shared<Tcp::socket>(State->Executor);
        boost::system::error_code Error;
        co_await State->Acceptor.async_accept(
            *Socket, Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            State->FailureMessage = "replacement backend accept failed: " + Error.message();
            co_return false;
        }
        State->BackendSocket = Socket;
        State->Acceptor.close(Error);
        std::vector<std::byte> Received(ReplacementPayload.size());
        const auto Count = co_await Net::async_read(
            *Socket, Net::buffer(Received), Net::redirect_error(Net::use_awaitable, Error));
        const auto Expected = std::as_bytes(std::span(ReplacementPayload));
        if (Error || Count != Received.size() ||
            !std::equal(Received.begin(), Received.end(), Expected.begin(), Expected.end()))
        {
            State->FailureMessage = "replacement backend payload was invalid";
            co_return false;
        }
        State->ReplacementBackendBytes = Count;
        State->ReplacementBackendReceived = true;
        co_await Net::async_write(
            *Socket, Net::buffer(Received), Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            State->FailureMessage = "replacement backend echo failed";
            co_return false;
        }
        State->ReplacementEchoed = true;
        std::array<std::byte, 1> Tail{};
        const auto TailCount = co_await Socket->async_read_some(
            Net::buffer(Tail), Net::redirect_error(Net::use_awaitable, Error));
        State->ReplacementTailBytes = TailCount;
        State->ReplacementBackendPeerClosed = TailCount == 0U && Error == Net::error::eof;
        Socket->close(Error);
        State->BackendClosed = true;
        State->BackendSocket.reset();
        co_return true;
    }

    auto RunBackend(const std::shared_ptr<ScenarioState> &State) -> Net::awaitable<void>
    {
        try
        {
            auto Socket = std::make_shared<Tcp::socket>(State->Executor);
            boost::system::error_code Error;
            co_await State->Acceptor.async_accept(
                *Socket, Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                State->FailureMessage = "TCP backend accept failed: " + Error.message();
                State->BackendReturned = true;
                NotifyDone(State);
                co_return;
            }
            State->BackendAccepted = true;
            State->BackendSocket = Socket;
            if (State->Kind != ScenarioKind::Replacement)
            {
                State->Acceptor.close(Error);
            }

            std::vector<std::byte> Received(Payload.size());
            const auto Count = co_await Net::async_read(
                *Socket, Net::buffer(Received), Net::redirect_error(Net::use_awaitable, Error));
            if (Error || Count != Received.size())
            {
                State->FailureMessage = "TCP backend payload read failed";
                State->BackendReturned = true;
                NotifyDone(State);
                co_return;
            }
            State->BackendBytes = Count;
            const auto Expected = std::as_bytes(std::span(Payload));
            if (!std::equal(Received.begin(), Received.end(), Expected.begin(), Expected.end()))
            {
                State->FailureMessage = "TCP backend received an unexpected payload";
                State->BackendReturned = true;
                NotifyDone(State);
                co_return;
            }
            State->BackendReceivedPayload = true;
            (void)State->BackendReceived.try_send(boost::system::error_code{});
            if (State->Kind == ScenarioKind::CancelPending)
            {
                std::array<std::byte, 1> Tail{};
                const auto TailCount = co_await Socket->async_read_some(
                    Net::buffer(Tail), Net::redirect_error(Net::use_awaitable, Error));
                State->BackendTailBytes = TailCount;
                State->BackendPeerClosed = TailCount == 0U && Error == Net::error::eof;
                if (TailCount != 0U)
                {
                    State->FailureMessage = "TCP backend received bytes after the pending cancel payload";
                }
                Socket->close(Error);
                State->BackendClosed = true;
                State->BackendSocket.reset();
                State->BackendReturned = true;
                NotifyDone(State);
                co_return;
            }

            co_await Net::async_write(
                *Socket, Net::buffer(Received), Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                State->FailureMessage = "TCP backend echo write failed";
                State->BackendReturned = true;
                NotifyDone(State);
                co_return;
            }
            State->BackendEchoed = true;
            if (State->Kind == ScenarioKind::QuotaSecond)
            {
                if (!co_await RunQuotaContinuation(State, Socket))
                {
                    State->BackendReturned = true;
                    NotifyDone(State);
                    co_return;
                }
            }

            std::array<std::byte, 1> Tail{};
            const auto TailCount = co_await Socket->async_read_some(
                Net::buffer(Tail), Net::redirect_error(Net::use_awaitable, Error));
            State->BackendTailBytes = TailCount;
            State->BackendPeerClosed = TailCount == 0U && Error == Net::error::eof;
            if (TailCount != 0U)
            {
                State->FailureMessage = "TCP backend received bytes after the expected payload";
            }
            Socket->close(Error);
            if (State->Kind == ScenarioKind::Replacement)
            {
                State->FirstBackendClosed = true;
                State->FirstBackendPeerClosed = State->BackendPeerClosed;
                State->BackendSocket.reset();
                (void)State->FirstBackendDone.try_send(boost::system::error_code{});
                if (!co_await RunReplacementBackend(State))
                {
                    State->BackendReturned = true;
                    NotifyDone(State);
                    co_return;
                }
            }
            else
            {
                State->BackendClosed = true;
                State->BackendSocket.reset();
            }
        }
        catch (...)
        {
            State->Failure = std::current_exception();
            State->Stop();
        }
        State->BackendReturned = true;
        NotifyDone(State);
    }

    auto RunServer(const std::shared_ptr<ScenarioState> &State) -> Net::awaitable<void>
    {
        try
        {
            {
                auto Plane = co_await State->Factory->Accept(
                    MakeScenarioAcceptInput(State));
                if (State->StopRequested)
                {
                    if (Plane && Plane->Mux() && Plane->Mux()->Session)
                        Plane->Mux()->Session->Close();
                    State->ServerReturned = true;
                    NotifyDone(State);
                    co_return;
                }
                if (!Plane)
                {
                    const auto Error = Plane.error();
                    State->FailureMessage = "configured SOCKS5 Accept failed: " +
                        Preview::make_error_code(Error).message() +
                        " value=" + std::to_string(static_cast<int>(Error));
                    State->ServerReturned = true;
                    State->Stop();
                    NotifyDone(State);
                    co_return;
                }
                State->Authenticated = Plane->ProtocolAuthenticated;
                State->AccountId = Plane->AccountId;
                State->LeaseValid = static_cast<bool>(Plane->AccountLease);
                State->PlaneMux = Plane->IsMux();
                const auto Mux = Plane->Mux();
                if (!Mux || !Mux->Session)
                {
                    State->FailureMessage = "configured SOCKS5 Accept did not publish a MuxRootDataPlane";
                    State->Stop();
                    NotifyDone(State);
                    co_return;
                }
                const auto Published = State->Directory->Store->FindById(Plane->AccountId);
                const auto LeaseRecord = Plane->AccountLease.Binding();
                State->Record = Published;
                State->SameRecord = Published && LeaseRecord && Published == LeaseRecord;
                State->Root = Mux->Session;
                State->WeakRoot = State->Root;
                const auto Root = State->Root;
                Preview::Contract::MuxRootRequest Request{
                    .Lease = std::move(Plane->AccountLease), .Metadata = std::move(State->Metadata),
                    .GenerationUseState = State->UseState};
                State->RunStatus = co_await Root->Run(std::move(Request));
                State->RunReturned = true;
                State->Root.reset();
            }
            State->ServerReturned = true;
        }
        catch (...)
        {
            State->Failure = std::current_exception();
            State->Stop();
        }
        NotifyDone(State);
    }

    auto ConnectClient(const std::shared_ptr<ScenarioState> &State)
        -> Net::awaitable<Preview::SharedTransmission>
    {
        Preview::SharedTransmission Connection;
        if (State->Family == ProtocolFamily::Socks5)
        {
            const Preview::Socks5::ClientConfig Config{true, "configured-account", "task4-provider-password"};
            auto [Error, Value] = co_await Preview::Socks5::Connect(
                State->Client, Config,
                {Preview::Socks5::AddressType::Ipv4, "127.0.0.1", 80});
            if (Error != Preview::Error::None || !Value)
            {
                const auto Typed = Preview::make_error_code(Error);
                State->FailureMessage = "SOCKS5 client handshake failed: " +
                    std::string(Typed.category().name()) + ":" + Typed.message();
                co_return nullptr;
            }
            Connection = std::move(Value);
        }
        else
        {
            Preview::Shadowsocks2022::ClientConfig Config;
            const auto Psk = Preview::Shadowsocks2022::DecodePsk("d3d3d3d3d3d3d3d3d3d3dw==");
            if (!Psk)
            {
                State->FailureMessage = "SS2022 fixture PSK did not decode to 16 bytes";
                co_return nullptr;
            }
            Config.Psk = *Psk;
            auto [Error, Value] = co_await Preview::Shadowsocks2022::Connect(
                State->Client, Config,
                {Preview::Shadowsocks2022::AddressType::Ipv4, "127.0.0.1", 80});
            if (Error != Preview::Error::None || !Value)
            {
                const auto Typed = Preview::make_error_code(Error);
                State->FailureMessage = "SS2022 client handshake failed: " +
                    std::string(Typed.category().name()) + ":" + Typed.message();
                co_return nullptr;
            }
            Connection = std::move(Value);
        }
        co_return Connection;
    }

    auto RejectSecondChild(
        const std::shared_ptr<ScenarioState> &State,
        const std::shared_ptr<Preview::Mux::Smux::Client<>> &Client,
        const std::vector<std::byte> &Request) -> Net::awaitable<void>
    {
        auto Second = co_await Client->OpenStream();
        State->SecondOpened = static_cast<bool>(Second);
        if (!Second)
        {
            State->FailureMessage = "quota scenario did not open a second wire child";
            co_return;
        }
        std::error_code IoError;
        const auto RequestWrite = co_await Second->WriteExact(Request);
        IoError = Preview::Fault::ToNative(RequestWrite.Failure);
        std::array<std::byte, 1> Rejection{};
        IoError.clear();
        const auto RejectionRead = co_await Second->ReadExact(Rejection);
        IoError = Preview::Fault::ToNative(RejectionRead.Failure);
        State->SecondReadCount = RejectionRead.Bytes;
        State->SecondReadReturned = true;
        if (IoError)
        {
            State->SecondReadError = std::string(IoError.category().name()) + ":" + IoError.message();
        }
        if (State->SecondReadCount == 1U)
        {
            State->SecondStatus = std::to_integer<std::uint8_t>(Rejection[0]);
        }
        State->SecondRejected = State->SecondReadCount == 1U && State->SecondStatus == 1U;
        State->FirstStillActiveAtReject = State->Record &&
            State->Record->Runtime()->ActiveConnections() == 1U &&
            State->Record->Runtime()->ActiveStreams() == 1U;
        (void)Second->Close();
    }

    auto MakeSmuxClient(const std::shared_ptr<ScenarioState> &State,
        Preview::SharedTransmission Connection) -> Net::awaitable<std::shared_ptr<Preview::Mux::Smux::Client<>>>
    {
        const std::array<std::byte, 2> Envelope{std::byte{0}, std::byte{0}};
        std::error_code IoError;
        const auto EnvelopeWrite = co_await Connection->WriteExact(Envelope);
        IoError = Preview::Fault::ToNative(EnvelopeWrite.Failure);
        if (IoError)
        {
            State->FailureMessage = "SingMux envelope write failed";
            co_return nullptr;
        }
        auto Client = std::make_shared<Preview::Mux::Smux::Client<>>();
        if (!Client->Connect(std::move(Connection)))
        {
            State->FailureMessage = "SingMux client session did not connect";
            co_return nullptr;
        }
        co_return Client;
    }

    auto BuildLiteralRequest(
        const std::shared_ptr<ScenarioState> &State,
        const std::string_view Data) -> std::vector<std::byte>
    {
        const auto Port = State->BackendPort;
        std::vector<std::byte> Request{
            std::byte{0}, std::byte{0}, std::byte{1}, std::byte{127}, std::byte{0},
            std::byte{0}, std::byte{1}, std::byte{static_cast<std::uint8_t>(Port >> 8)},
            std::byte{static_cast<std::uint8_t>(Port)}};
        const auto PayloadBytes = std::as_bytes(std::span(Data));
        Request.insert(Request.end(), PayloadBytes.begin(), PayloadBytes.end());
        return Request;
    }

    auto OpenFirstChild(const std::shared_ptr<ScenarioState> &State,
        const std::shared_ptr<Preview::Mux::Smux::Client<>> &Client)
        -> Net::awaitable<std::pair<Preview::SharedTransmission, std::vector<std::byte>>>
    {
        auto Stream = co_await Client->OpenStream();
        if (!Stream)
        {
            State->FailureMessage = "SingMux client did not open a child stream";
            co_return std::pair<Preview::SharedTransmission, std::vector<std::byte>>{};
        }
        auto Request = BuildLiteralRequest(State, Payload);
        std::error_code IoError;
        const auto RequestWrite = co_await Stream->WriteExact(Request);
        IoError = Preview::Fault::ToNative(RequestWrite.Failure);
        if (IoError)
        {
            State->FailureMessage = "SingMux target request write failed";
            co_return std::pair<Preview::SharedTransmission, std::vector<std::byte>>{};
        }
        co_return std::pair{std::move(Stream), std::move(Request)};
    }

    auto ReadFirstChildReply(const std::shared_ptr<ScenarioState> &State,
        const Preview::SharedTransmission &Stream) -> Net::awaitable<bool>
    {
        std::error_code IoError;
        if (State->Kind == ScenarioKind::CancelPending)
        {
            State->ClientReadPendingSignaled = true;
            (void)State->ClientReadPending.try_send(boost::system::error_code{});
            std::vector<std::byte> PendingReply(Payload.size() + 1);
            const auto PendingRead = co_await Stream->ReadExact(PendingReply);
            IoError = Preview::Fault::ToNative(PendingRead.Failure);
            State->ClientReadCount = PendingRead.Bytes;
            State->ClientReadReturned = true;
            if (IoError)
            {
                State->ClientReadError =
                    std::string(IoError.category().name()) + ":" + IoError.message();
            }
            else
            {
                State->ClientReadError = "none";
            }
            if (State->ClientReadCount != 0U)
                State->FailureMessage = "cancel-pending client read returned payload bytes";
            co_return true;
        }
        std::vector<std::byte> Reply(Payload.size() + 1);
        const auto PayloadBytes = std::as_bytes(std::span(Payload));
        const auto ReplyRead = co_await Stream->ReadExact(Reply);
        IoError = Preview::Fault::ToNative(ReplyRead.Failure);
        if (IoError || Reply.front() != std::byte{0} ||
            !std::equal(Reply.begin() + 1, Reply.end(), PayloadBytes.begin(), PayloadBytes.end()))
        {
            State->FailureMessage = "SingMux child reply did not contain status 0 and the literal payload";
            co_return false;
        }
        State->CountersAtEcho = State->Record &&
            State->Record->Runtime()->ActiveConnections() == 1U &&
            State->Record->Runtime()->ActiveStreams() == 1U;
        co_return true;
    }

    auto VerifyFirstContinuation(const std::shared_ptr<ScenarioState> &State,
        const Preview::SharedTransmission &Stream) -> Net::awaitable<bool>
    {
        const auto ContinuationBytes = std::as_bytes(std::span(Continuation));
        std::error_code IoError;
        const auto ContinuationWrite = co_await Stream->WriteExact(ContinuationBytes);
        IoError = Preview::Fault::ToNative(ContinuationWrite.Failure);
        if (IoError)
        {
            State->FailureMessage = "quota first child continuation write failed";
            co_return false;
        }
        std::vector<std::byte> Reply(Continuation.size());
        const auto ContinuationRead = co_await Stream->ReadExact(Reply);
        IoError = Preview::Fault::ToNative(ContinuationRead.Failure);
        const auto Count = ContinuationRead.Bytes;
        if (IoError || Count != Continuation.size() ||
            !std::equal(Reply.begin(), Reply.end(), ContinuationBytes.begin(), ContinuationBytes.end()))
        {
            State->FailureMessage = "quota first child continuation echo failed";
            co_return false;
        }
        State->ContinuationEchoed = true;
        State->BackendOpenAtContinuation = !State->BackendClosed;
        co_return true;
    }

    /** @brief 运行 FIN 后重新开启子流的完整 replacement 行为分支。 */
    auto RunReplacementClient(const std::shared_ptr<ScenarioState> &State,
        const std::shared_ptr<Preview::Mux::Smux::Client<>> &Client,
        Preview::SharedTransmission Stream) -> Net::awaitable<bool>
    {
        (void)co_await Stream->WriteShutdown();
        co_await State->FirstBackendDone.async_receive(Net::use_awaitable);
        if (State->StopRequested) co_return false;
        std::array<std::byte, 1> FirstTail{};
        const auto FirstTailRead = co_await Stream->ReadExact(FirstTail);
        const auto IoError = Preview::Fault::ToNative(FirstTailRead.Failure);
        State->FirstClientFinCount = FirstTailRead.Bytes;
        if (IoError)
        {
            State->FirstClientFinError =
                std::string(IoError.category().name()) + ":" + IoError.message();
        }
        else
        {
            State->FirstClientFinError = "none";
        }
        State->FirstClientFinReturned = FirstTailRead.Bytes == 0U;
        State->FirstLeaseReleased = State->Record &&
            State->Record->Runtime()->ActiveConnections() == 1U &&
            State->Record->Runtime()->ActiveStreams() == 0U;
        if (!State->FirstClientFinReturned || !State->FirstLeaseReleased)
        {
            State->FailureMessage = "first child FIN did not release its stream lease";
            co_return false;
        }
        Stream.reset();
        auto Second = co_await Client->OpenStream();
        State->ReplacementOpened = static_cast<bool>(Second);
        if (!Second)
        {
            State->FailureMessage = "replacement child did not open";
            co_return false;
        }
        const auto ReplacementRequest = BuildLiteralRequest(State, ReplacementPayload);
        const auto ReplacementWrite = co_await Second->WriteExact(ReplacementRequest);
        if (ReplacementWrite.Failure.Failed() || ReplacementWrite.Bytes != ReplacementRequest.size())
        {
            State->FailureMessage = "replacement child echo did not match its literal payload";
            co_return false;
        }
        std::vector<std::byte> ReplacementReply(ReplacementPayload.size() + 1);
        const auto ReplacementRead = co_await Second->ReadExact(ReplacementReply);
        const auto ReplacementCount = ReplacementRead.Bytes;
        const auto ReplacementBytes = std::as_bytes(std::span(ReplacementPayload));
        if (ReplacementRead.Failure.Failed() || ReplacementCount != ReplacementReply.size() ||
            ReplacementReply.front() != std::byte{0} ||
            !std::equal(ReplacementReply.begin() + 1, ReplacementReply.end(),
                ReplacementBytes.begin(), ReplacementBytes.end()))
        {
            State->FailureMessage = "replacement child echo did not match its literal payload";
            co_return false;
        }
        State->ReplacementEchoed = true;
        State->CountersAtReplacementEcho = State->Record &&
            State->Record->Runtime()->ActiveConnections() == 1U &&
            State->Record->Runtime()->ActiveStreams() == 1U;
        (void)co_await Second->WriteShutdown();
        co_return true;
    }

    auto RunClient(const std::shared_ptr<ScenarioState> &State) -> Net::awaitable<void>
    {
        try
        {
            auto Connection = co_await ConnectClient(State);
            if (!Connection)
            {
                State->ClientReturned = true;
                State->Stop();
                NotifyDone(State);
                co_return;
            }
            auto Client = co_await MakeSmuxClient(State, std::move(Connection));
            if (!Client)
            {
                State->ClientReturned = true;
                State->Stop();
                NotifyDone(State);
                co_return;
            }
            auto [Stream, Request] = co_await OpenFirstChild(State, Client);
            if (!Stream)
            {
                State->ClientReturned = true;
                State->Stop();
                NotifyDone(State);
                co_return;
            }
            if (!co_await ReadFirstChildReply(State, Stream))
            {
                State->ClientReturned = true;
                State->Stop();
                NotifyDone(State);
                co_return;
            }
            if (State->Kind == ScenarioKind::Replacement)
            {
                if (!co_await RunReplacementClient(State, Client, std::move(Stream)))
                {
                    State->ClientReturned = true;
                    State->Stop();
                    NotifyDone(State);
                    co_return;
                }
            }
            else if (State->Kind == ScenarioKind::QuotaSecond)
            {
                co_await RejectSecondChild(State, Client, Request);
                if (!State->SecondRejected || !co_await VerifyFirstContinuation(State, Stream))
                {
                    State->ClientReturned = true;
                    State->Stop();
                    NotifyDone(State);
                    co_return;
                }
                (void)co_await Stream->WriteShutdown();
            }
            else
            {
                (void)co_await Stream->WriteShutdown();
            }
            if (const auto Session = Client->Session())
                co_await Session->Close();
            State->ClientClosed = true;
        }
        catch (...)
        {
            State->Failure = std::current_exception();
            State->Stop();
        }
        State->ClientReturned = true;
        NotifyDone(State);
    }

    auto RunWatchdog(const std::shared_ptr<ScenarioState> &State) -> Net::awaitable<void>
    {
        State->Deadline.expires_after(std::chrono::seconds(4));
        boost::system::error_code Error;
        co_await State->Deadline.async_wait(Net::redirect_error(Net::use_awaitable, Error));
        if (!Error)
        {
            State->TimedOut = true;
            State->FailureMessage = "configured mux session watchdog expired";
            State->Stop();
        }
    }

    auto RunScenario(const std::shared_ptr<ScenarioState> &State) -> Net::awaitable<void>
    {
        Net::co_spawn(State->Executor, RunBackend(State),
            [State](std::exception_ptr Error) { if (Error) { State->Failure = Error; State->Stop(); } });
        Net::co_spawn(State->Executor, RunServer(State),
            [State](std::exception_ptr Error) { if (Error) { State->Failure = Error; State->Stop(); } });
        Net::co_spawn(State->Executor, RunClient(State),
            [State](std::exception_ptr Error) { if (Error) { State->Failure = Error; State->Stop(); } });

        if (State->Kind == ScenarioKind::CancelPending)
        {
            co_await State->ClientReadPending.async_receive(Net::use_awaitable);
            if (!State->StopRequested)
            {
                co_await State->BackendReceived.async_receive(Net::use_awaitable);
                if (!State->StopRequested)
                {
                    State->PreCancelCounters = State->Record &&
                        State->Record->Runtime()->ActiveConnections() == 1U &&
                        State->Record->Runtime()->ActiveStreams() == 1U;
                    State->Bound->Close();
                    State->CatalogDrained = static_cast<bool>(co_await State->Bound->Drain());
                    if (State->CatalogDrained) State->Bound.reset();
                }
            }
        }
        for (std::size_t Index = 0; Index < 3; ++Index)
        {
            co_await State->Done.async_receive(Net::use_awaitable);
        }
        if (State->Bound && (State->Kind != ScenarioKind::CancelPending || State->StopRequested))
        {
            State->Bound->Close();
            State->CatalogDrained = static_cast<bool>(co_await State->Bound->Drain());
            if(State->CatalogDrained)State->Bound.reset();
        }
        if (State->UseState)
        {
            State->GenerationUsesAfterDrain = State->UseState->Outstanding();
        }
        State->Deadline.cancel();
        State->CountersDrained = State->Record &&
            State->Record->Runtime()->ActiveConnections() == 0U &&
            State->Record->Runtime()->ActiveStreams() == 0U;
        State->WeakRootExpired = State->WeakRoot.expired();
    }

    auto MakeMaxStreamDirectory(
        const std::shared_ptr<const Preview::Account::AccountBinding> &Source)
        -> std::shared_ptr<Preview::Testing::ProviderAccounts>
    {
        if (!Source)
        {
            return {};
        }
        const auto &SourceMaterial = Source->Materials()->Credentials().front();
        return Preview::Testing::ProviderAccount(
            Preview::Account::Credential(SourceMaterial.Credential.Kind(),
                Preview::Account::SecureBytes(SourceMaterial.Credential.View().Bytes())),
            Source->AccountId(), {.MaxConnections = 0, .MaxStreams = 1, .MaxBytes = 0});
    }

    auto Scenario(const ProtocolFamily Family, const ScenarioKind Kind) -> std::shared_ptr<ScenarioState>
    {
        const auto RootPath = std::filesystem::path{PRISM_TEST_REPO_ROOT};
        const auto Name = ProtocolName(Family);
        auto State = std::make_shared<ScenarioState>(Family, Kind);
        State->Egress = std::make_shared<LocalEgress>(State);
        const auto Phase = Application::Startup::GenerationPhase::Build({
            RootPath / "tests/TestSupport/Preview/ConfiguredMux" / (std::string(Name) + ".json"), {}});
        if (!Phase)
        {
            State->FailureMessage = Phase.error().Path + ": " + Phase.error().Message;
            return State;
        }

        const auto Descriptor = Preview::Composition::Protocol::ProtocolCatalog::Find(Name);
        if (!Descriptor || Descriptor->Kind != Preview::Composition::Protocol::DescriptorKind::Protocol)
        {
            State->FailureMessage = std::string(Name) + " static protocol was not recognized";
            return State;
        }
        const auto Authentication = Phase->Accounts.Find("mux-" + std::string(Name));
        if (!Authentication)
        {
            State->FailureMessage = "configured account services were not published";
            return State;
        }
        auto Accounts = std::make_shared<Preview::Testing::ProviderAccounts>(
            Preview::Testing::ProviderAccounts{Phase->Accounts.Store, Authentication->Credentials,
                Authentication->Authenticator});
        if (Kind == ScenarioKind::QuotaSecond || Kind == ScenarioKind::Replacement)
        {
            const auto Source = Phase->Accounts.Store->FindById(Preview::AccountId{1});
            auto LimitedDirectory = MakeMaxStreamDirectory(Source);
            if (!LimitedDirectory)
            {
                State->FailureMessage = "quota scenario could not publish its MaxStreams=1 account";
                return State;
            }
            Accounts = std::move(LimitedDirectory);
        }
        State->Directory = Accounts;
        State->UseState = std::make_shared<Preview::Foundation::GenerationUseState>();
        Provider::ConfigurationInput Input{
            Phase->Generation, State->UseState, Phase->Generation->Configuration().Protocols,
            Phase->Generation->Configuration().ProtocolBindings, {}};
        Input.Authentication.emplace("mux-" + std::string(Name), Preview::Contract::AuthenticationServices{
            Phase->Generation, Accounts->Credentials, Accounts->Authenticator});
        Provider::BindingServices ProviderServices{State->Executor, {}, {}, {}};
        ProviderServices.Streams.Egress = State->Egress;
        ProviderServices.Streams.Bytes = State->Bytes;
        auto Prepared = Provider::Compile(std::move(Input), std::move(ProviderServices));
        if (!Prepared)
        {
            State->FailureMessage = "provider compile failed";
            return State;
        }
        auto Frozen = Prepared->Freeze();
        if (!Frozen)
        {
            State->FailureMessage = "provider freeze failed";
            return State;
        }
        auto BoundResult = Frozen->Bind({});
        if (!BoundResult)
        {
            State->FailureMessage = "provider bind failed";
            return State;
        }

        Application::ProtocolProfile::ProtocolFactoryContext Context{
            Phase->Generation->Configuration(), *Phase->Generation,
            Phase->Accounts, {}, {},
            &*BoundResult, {}, {.Egress = State->Egress, .Bytes = State->Bytes}};
        auto Profile = Application::ProtocolProfile::MakeTcpProfile(Context);
        if (!Profile || Profile->Profile->CandidateCount() != 1U ||
            Phase->Generation->Configuration().ProtocolBindings.front().MuxModes.front() != "Smux")
        {
            State->FailureMessage = "configured SOCKS5 profile did not select one Smux mode";
            return State;
        }
        State->Factory = Profile->Resolver(Profile->Profile->CandidateIdAt(0));
        if (!State->Factory || !State->Directory)
        {
            State->FailureMessage = "configured SOCKS5 profile did not publish a factory and directory";
            return State;
        }

        Preview::Contract::RequestMetadata Metadata;
        Metadata.SourceIp = "127.0.0.1";
        Metadata.TaskIdentity.SessionId = Preview::SessionId{3003};
        Metadata.TaskIdentity.TaskId = Preview::TaskId{3004};
        State->Metadata = Metadata;
        State->Bound = std::make_shared<Provider::BoundCatalog>(std::move(*BoundResult));
        Net::co_spawn(State->Io, RunScenario(State),
            [State](std::exception_ptr Error) { if (Error) { State->Failure = Error; State->Stop(); } });
        Net::co_spawn(State->Io, RunWatchdog(State),
            [State](std::exception_ptr Error) { if (Error) { State->Failure = Error; State->Stop(); } });
        State->Io.run();
        return State;
    }
} // namespace



