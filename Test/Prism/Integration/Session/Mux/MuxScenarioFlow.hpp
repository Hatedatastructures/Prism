/**
 * @file MuxScenarioFlow.hpp
 * @brief 配置化 Mux 单根场景的异步流程与构造.
 */
#pragma once

#include "MuxScenarioTypes.hpp"
#include <Prism/Foundation/Memory/BytePool.hpp>

namespace
{
    /** @brief 构造带真实有界字节池的配置化协议接入输入。 */
    [[nodiscard]] auto MakeScenarioAcceptInput(const std::shared_ptr<ScenarioState> &State)
        -> Prism::Contract::StreamAcceptInput
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
                if (!State->StopRequested)
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
                    const auto Failure = Plane.error();
                    const auto Native = Prism::Fault::ToNative(Failure);
                    State->FailureMessage = "configured SOCKS5 Accept failed: " +
                        Native.message() + " value=" +
                        std::to_string(static_cast<int>(Failure.Code));
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
                Prism::Contract::MuxRootRequest Request{
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
        -> Net::awaitable<Prism::SharedTransmission>
    {
        Prism::SharedTransmission Connection;
        if (State->Family == ProtocolFamily::Socks5)
        {
            const Prism::Socks5::ClientConfig Config{true, "configured-account", "task4-provider-password"};
            const Prism::Socks5::Address Target{
                Prism::Socks5::AddressType::Ipv4, "127.0.0.1", 80};
            auto Connected = co_await Prism::Socks5::Connect(
                Prism::Socks5::ConnectParameters{State->Client, Config, Target});
            if (!Connected)
            {
                const auto Typed = Prism::Fault::ToNative(Connected.error());
                State->FailureMessage = "SOCKS5 client handshake failed: " +
                    std::string(Typed.category().name()) + ":" + Typed.message();
                co_return nullptr;
            }
            Connection = std::move(*Connected);
        }
        else
        {
            Prism::Shadowsocks2022::ClientConfig Config;
            const auto Psk = Prism::Shadowsocks2022::DecodePsk("d3d3d3d3d3d3d3d3d3d3dw==");
            if (!Psk)
            {
                State->FailureMessage = "SS2022 fixture PSK did not decode to 16 bytes";
                co_return nullptr;
            }
            Config.Psk = *Psk;
            auto Connected = co_await Prism::Shadowsocks2022::Connect(
                State->Client, Config,
                {Prism::Shadowsocks2022::AddressType::Ipv4, "127.0.0.1", 80});
            if (!Connected)
            {
                const auto Typed = Prism::Fault::ToNative(Connected.error());
                State->FailureMessage = "SS2022 client handshake failed: " +
                    std::string(Typed.category().name()) + ":" + Typed.message() +
                    " code=" + std::to_string(static_cast<int>(Connected.error().Code));
                co_return nullptr;
            }
            Connection = std::move(*Connected);
        }
        co_return Connection;
    }

    auto RejectSecondChild(
        const std::shared_ptr<ScenarioState> &State,
        const std::shared_ptr<Prism::Mux::Smux::Client<>> &Client,
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
        IoError = Prism::Fault::ToNative(RequestWrite.Failure);
        std::array<std::byte, 1> Rejection{};
        IoError.clear();
        const auto RejectionRead = co_await Second->ReadExact(Rejection);
        IoError = Prism::Fault::ToNative(RejectionRead.Failure);
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
        Prism::SharedTransmission Connection) -> Net::awaitable<std::shared_ptr<Prism::Mux::Smux::Client<>>>
    {
        const std::array<std::byte, 2> Envelope{std::byte{0}, std::byte{0}};
        std::error_code IoError;
        const auto EnvelopeWrite = co_await Connection->WriteExact(Envelope);
        IoError = Prism::Fault::ToNative(EnvelopeWrite.Failure);
        if (IoError)
        {
            State->FailureMessage = "SingMux envelope write failed";
            co_return nullptr;
        }
        auto Client = std::make_shared<Prism::Mux::Smux::Client<>>();
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
        const std::shared_ptr<Prism::Mux::Smux::Client<>> &Client)
        -> Net::awaitable<std::pair<Prism::SharedTransmission, std::vector<std::byte>>>
    {
        auto Stream = co_await Client->OpenStream();
        if (!Stream)
        {
            State->FailureMessage = "SingMux client did not open a child stream";
            co_return std::pair<Prism::SharedTransmission, std::vector<std::byte>>{};
        }
        auto Request = BuildLiteralRequest(State, Payload);
        std::error_code IoError;
        const auto RequestWrite = co_await Stream->WriteExact(Request);
        IoError = Prism::Fault::ToNative(RequestWrite.Failure);
        if (IoError)
        {
            State->FailureMessage = "SingMux target request write failed";
            co_return std::pair<Prism::SharedTransmission, std::vector<std::byte>>{};
        }
        co_return std::pair{std::move(Stream), std::move(Request)};
    }

    auto ReadFirstChildReply(const std::shared_ptr<ScenarioState> &State,
        const Prism::SharedTransmission &Stream) -> Net::awaitable<bool>
    {
        std::error_code IoError;
        if (State->Kind == ScenarioKind::CancelPending)
        {
            State->ClientReadPendingSignaled = true;
            (void)State->ClientReadPending.try_send(boost::system::error_code{});
            std::vector<std::byte> PendingReply(Payload.size() + 1);
            const auto PendingRead = co_await Stream->ReadExact(PendingReply);
            IoError = Prism::Fault::ToNative(PendingRead.Failure);
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
        IoError = Prism::Fault::ToNative(ReplyRead.Failure);
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
        const Prism::SharedTransmission &Stream) -> Net::awaitable<bool>
    {
        const auto ContinuationBytes = std::as_bytes(std::span(Continuation));
        std::error_code IoError;
        const auto ContinuationWrite = co_await Stream->WriteExact(ContinuationBytes);
        IoError = Prism::Fault::ToNative(ContinuationWrite.Failure);
        if (IoError)
        {
            State->FailureMessage = "quota first child continuation write failed";
            co_return false;
        }
        std::vector<std::byte> Reply(Continuation.size());
        const auto ContinuationRead = co_await Stream->ReadExact(Reply);
        IoError = Prism::Fault::ToNative(ContinuationRead.Failure);
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
        const std::shared_ptr<Prism::Mux::Smux::Client<>> &Client,
        Prism::SharedTransmission Stream) -> Net::awaitable<bool>
    {
        (void)co_await Stream->WriteShutdown();
        co_await State->FirstBackendDone.async_receive(Net::use_awaitable);
        if (State->StopRequested) co_return false;
        std::array<std::byte, 1> FirstTail{};
        const auto FirstTailRead = co_await Stream->ReadExact(FirstTail);
        const auto IoError = Prism::Fault::ToNative(FirstTailRead.Failure);
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
                    const auto CatalogDrain = co_await State->Bound->Drain();
                    State->CatalogDrained = static_cast<bool>(CatalogDrain);
                    if (!CatalogDrain) State->CatalogDrainFailure = CatalogDrain.error();
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
            const auto CatalogDrain = co_await State->Bound->Drain();
            State->CatalogDrained = static_cast<bool>(CatalogDrain);
            if (!CatalogDrain) State->CatalogDrainFailure = CatalogDrain.error();
            if(State->CatalogDrained)State->Bound.reset();
        }
        if (State->CatalogDrained) State->AdmissionPublication.reset();
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

} // namespace



