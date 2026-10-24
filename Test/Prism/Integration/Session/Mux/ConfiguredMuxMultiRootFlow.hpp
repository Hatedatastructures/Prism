/**
 * @file ConfiguredMuxMultiRootFlow.hpp
 * @brief 配置化 Mux 双 root 场景的异步流程与 drain 验证.
 */
#pragma once

#include "MuxMultiRootTypes.hpp"
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Composition/Protocol/ProtocolCatalog.hpp>

namespace
{
    /** @brief 为每个真实 mux root 输入创建有界共享字节池。 */
    [[nodiscard]] auto MakeMultiRootAcceptInput(
        const std::shared_ptr<MultiRootState> &State,
        const std::size_t Index) -> Prism::Contract::StreamAcceptInput
    {
        return {State->Server[Index], {}, State->Bytes[Index]};
    }

    auto MultiRootPayload(const std::size_t Index) -> std::string_view
    {
        return MultiRootPayloads[Index];
    }

    auto BuildMultiRootRequest(const std::shared_ptr<MultiRootState> &State, const std::size_t Index)
        -> std::vector<std::byte>
    {
        const auto Port = State->BackendPort[Index];
        std::vector<std::byte> Request{
            std::byte{0}, std::byte{0}, std::byte{1}, std::byte{127}, std::byte{0},
            std::byte{0}, std::byte{1}, std::byte{static_cast<std::uint8_t>(Port >> 8)},
            std::byte{static_cast<std::uint8_t>(Port)}};
        const auto Bytes = std::as_bytes(std::span(MultiRootPayload(Index)));
        Request.insert(Request.end(), Bytes.begin(), Bytes.end());
        return Request;
    }

    auto PrepareMultiRoot(const std::shared_ptr<MultiRootState> &State) -> bool
    {
        const auto RootPath = std::filesystem::path{PRISM_TEST_REPO_ROOT};
        const auto Name = ProtocolName(State->Family);
        auto Phase = Application::Startup::GenerationPhase::Build({
            RootPath / "Test/TestSupport/Prism/ConfiguredMux" / (std::string(Name) + ".json"), {}});
        if (!Phase)
        {
            State->SetupError = Phase.error().Path + ": " + Phase.error().Message;
            return false;
        }
        State->Pin = Phase->Generation;
        State->WeakGeneration = State->Pin;
        State->UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        auto Published = Prism::Testing::PublishConfiguredAccountCatalog(
            Phase->Accounts, Phase->Generation);
        if (!Published)
        {
            State->SetupError = "multi-root account authority publish failed: " +
                Prism::Fault::ToNative(Published.error()).message();
            return false;
        }
        State->AdmissionPublication = std::move(*Published);
        const auto Descriptor = Prism::Composition::Protocol::ProtocolCatalog::Find(Name);
        if (!Descriptor || Descriptor->Kind != Prism::Composition::Protocol::DescriptorKind::Protocol)
        {
            State->SetupError = "configured protocol was not recognized";
            return false;
        }
        const auto *Authentication = Phase->Accounts.Find("mux-" + std::string(Name));
        if (!Authentication)
        {
            State->SetupError = "configured account services were not published";
            return false;
        }
        State->Directory = std::make_shared<Prism::Testing::ProviderAccounts>(
            Prism::Testing::ProviderAccounts{Phase->Accounts.Store, Authentication->Credentials,
                Authentication->Authenticator});
        State->Record = State->Directory->Store->FindById(Prism::AccountId{1});
        State->Egress = std::make_shared<MultiRootEgress>(State);
        Provider::ConfigurationInput Input{
            Phase->Generation, State->UseState, Phase->Generation->Configuration().Protocols,
            Phase->Generation->Configuration().ProtocolBindings, {}};
        Input.Authentication.emplace("mux-" + std::string(Name), *Authentication);
        Provider::BindingServices ProviderServices{State->Executor, {}, {}, {}};
        ProviderServices.Streams.Egress = State->Egress;
        ProviderServices.Streams.Bytes = State->Bytes[0];
        auto MissingUseStateInput = Input;
        MissingUseStateInput.UseState.reset();
        auto MissingUseState = Provider::Compile(std::move(MissingUseStateInput), ProviderServices);
        if (MissingUseState || MissingUseState.error().Code != Prism::Contract::ProviderError::GenerationMismatch)
        {
            State->SetupError = "mux provider accepted a missing generation use-state";
            return false;
        }
        auto Prepared = Provider::Compile(std::move(Input), std::move(ProviderServices));
        if (!Prepared)
        {
            State->SetupError = "provider compile failed";
            return false;
        }
        auto Frozen = Prepared->Freeze();
        if (!Frozen)
        {
            State->SetupError = "provider freeze failed";
            return false;
        }
        auto Bound = Frozen->Bind({});
        if (!Bound)
        {
            State->SetupError = "provider bind failed";
            return false;
        }
        State->Bound = std::make_shared<Provider::BoundCatalog>(std::move(*Bound));
        const auto *Entry = State->Bound->Find("mux-" + std::string(Name));
        if (!Entry || !State->Record)
        {
            State->SetupError = "bound instance or configured account was missing";
            return false;
        }
        State->NoColdAuthentication = State->Record->Runtime()->ActiveConnections() == 0U &&
            State->Record->Runtime()->ActiveStreams() == 0U;
        for (std::size_t RootIndex = 0; RootIndex < State->Factory.size(); ++RootIndex)
        {
            Prism::Contract::StreamServices Services;
            Services.Egress = State->Egress;
            Services.Bytes = State->Bytes[RootIndex];
            State->RootBinding[RootIndex] = std::make_shared<Prism::Mux::RootBinding>(
                Prism::Mux::RootOptions{.Wire = Prism::Mux::Mode::Smux,
                    .Services = std::move(Services), .GenerationUseState = State->UseState});
            State->Factory[RootIndex] = Entry->MuxStream(State->RootBinding[RootIndex]);
            if (!State->Factory[RootIndex])
            {
                State->SetupError = "second cold mux factory was not published";
                return false;
            }
        }
        State->DistinctFactories = State->Factory[0] != State->Factory[1];
        State->DistinctRootBindings = State->RootBinding[0] != State->RootBinding[1];
        return State->DistinctFactories && State->DistinctRootBindings;
    }

    auto RunMultiBackend(const std::shared_ptr<MultiRootState> &State, const std::size_t Index)
        -> Net::awaitable<void>
    {
        try
        {
            State->BackendStage[Index] = "accept";
            auto Socket = std::make_shared<Tcp::socket>(State->Executor);
            boost::system::error_code Error;
            co_await State->BackendAcceptor[Index]->async_accept(
                *Socket, Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                if (!State->StopRequested)
                    State->FailureMessage = "multi-root backend accept failed: " + Error.message();
                State->Stop("backend-accept");
                co_return;
            }
            State->BackendSocket[Index] = Socket;
            State->BackendStage[Index] = "read-payload";
            const auto Payload = MultiRootPayload(Index);
            std::vector<std::byte> Received(Payload.size());
            const auto Count = co_await Net::async_read(
                *Socket, Net::buffer(Received), Net::redirect_error(Net::use_awaitable, Error));
            const auto Expected = std::as_bytes(std::span(Payload));
            if (Error || Count != Received.size() ||
                !std::equal(Received.begin(), Received.end(), Expected.begin(), Expected.end()))
            {
                State->FailureMessage = "multi-root backend literal payload was invalid";
                State->Stop("backend-payload");
                co_return;
            }
            State->BackendBytes[Index] = Count;
            State->BackendReceived[Index] = true;
            (void)State->BackendReady.try_send(boost::system::error_code{});
            if (Index == 0)
            {
                State->BackendStage[Index] = "echo";
            }
            else
            {
                State->BackendStage[Index] = "wait-first-backend-eof";
            }
            if (Index == 0)
            {
                co_await Net::async_write(
                    *Socket, Net::buffer(Received), Net::redirect_error(Net::use_awaitable, Error));
                if (Error)
                {
                    State->FailureMessage = "first multi-root backend echo failed";
                    State->Stop("backend-echo");
                    co_return;
                }
            }
            else
            {
                State->BackendStage[Index] = "echo-second";
                co_await State->SecondEchoGate.async_receive(Net::use_awaitable);
                if (State->StopRequested) co_return;
                co_await Net::async_write(
                    *Socket, Net::buffer(Received), Net::redirect_error(Net::use_awaitable, Error));
                if (Error)
                {
                    State->FailureMessage = "second multi-root backend echo failed";
                    State->Stop("backend-second-echo");
                    co_return;
                }
                State->SecondBackendEchoed = true;
                State->BackendStage[Index] = "pending-peer-close";
            }
            std::array<std::byte, 1> Tail{};
            const auto TailCount = co_await Socket->async_read_some(
                Net::buffer(Tail), Net::redirect_error(Net::use_awaitable, Error));
            State->BackendTailBytes[Index] = TailCount;
            if (Error)
            {
                State->BackendTailError[Index] =
                    std::string(Error.category().name()) + ":" + Error.message();
            }
            else
            {
                State->BackendTailError[Index] = "none";
            }
            State->BackendPeerClosed[Index] = TailCount == 0U && Error == Net::error::eof;
            Socket->close(Error);
            State->BackendClosed[Index] = true;
            State->BackendSocket[Index].reset();
            State->BackendStage[Index] = "done";
            if (Index == 0)
            {
                const bool Sent = State->FirstBackendEof.try_send(boost::system::error_code{});
                std::fprintf(stderr,
                    "[ConfiguredMuxSession] signal=first-backend-eof sent=%d tail=%zu error=%s\n",
                    static_cast<int>(Sent), State->BackendTailBytes[Index], State->BackendTailError[Index].c_str());
                std::fflush(stderr);
            }
        }
        catch (...)
        {
            State->Failure = std::current_exception();
            State->Stop("backend-exception");
        }
        (void)State->BackendDone.try_send(boost::system::error_code{});
    }

    auto RunMultiServer(const std::shared_ptr<MultiRootState> &State, const std::size_t Index)
        -> Net::awaitable<void>
    {
        try
        {
            State->ServerStage[Index] = "accept";
            auto Plane = co_await State->Factory[Index]->Accept(
                MakeMultiRootAcceptInput(State, Index));
            if (State->StopRequested)
            {
                if (Plane && Plane->Mux() && Plane->Mux()->Session)
                    Plane->Mux()->Session->Close();
                co_return;
            }
            if (!Plane)
            {
                const auto Failure = Plane.error();
                const auto Native = Prism::Fault::ToNative(Failure);
                State->FailureMessage = "multi-root factory Accept failed: " + Native.message() +
                    " value=" + std::to_string(static_cast<int>(Failure.Code));
                State->Stop("server-plane");
                co_return;
            }
            if (!Plane->IsMux() || !Plane->Mux() || !Plane->Mux()->Session)
            {
                State->FailureMessage = "multi-root factory did not publish a mux plane";
                State->Stop("server-plane");
                co_return;
            }
            State->Authenticated[Index] = Plane->ProtocolAuthenticated;
            State->LeaseValid[Index] = static_cast<bool>(Plane->AccountLease);
            State->Root[Index] = Plane->Mux()->Session;
            State->WeakRoot[Index] = State->Root[Index];
            (void)State->RootReady.try_send(boost::system::error_code{});
            State->ServerStage[Index] = "root-run";
            Prism::Contract::RequestMetadata Metadata;
            Metadata.SourceIp = "127.0.0.1";
            Metadata.TaskIdentity.SessionId = Prism::SessionId{5000U + Index};
            Metadata.TaskIdentity.TaskId = Prism::TaskId{6000U + Index};
            State->RunStatus[Index] = co_await State->Root[Index]->Run(
                Prism::Contract::MuxRootRequest{.Lease = std::move(Plane->AccountLease),
                    .Metadata = Metadata, .GenerationUseState = State->UseState});
            State->RootReturned[Index] = true;
            State->Root[Index].reset();
            State->ServerStage[Index] = "done";
        }
        catch (...)
        {
            State->Failure = std::current_exception();
            State->Stop("server-exception");
        }
        const bool Sent = State->RootDone.try_send(boost::system::error_code{});
        std::fprintf(stderr, "[ConfiguredMuxSession] signal=root-done index=%zu sent=%d\n",
            Index, static_cast<int>(Sent));
        std::fflush(stderr);
    }

    auto RunMultiClientChild(const std::shared_ptr<MultiRootState> &State, const std::size_t Index)
        -> Net::awaitable<bool>
    {
        const auto Stream = State->Child[Index];
        const auto Request = BuildMultiRootRequest(State, Index);
        std::error_code IoError;
        const auto RequestWrite = co_await Stream->WriteExact(Request);
        IoError = Prism::Fault::ToNative(RequestWrite.Failure);
        if (IoError)
        {
            State->FailureMessage = "multi-root child request write failed";
            State->Stop("client-child-write");
            co_return false;
        }
        if (Index == 0)
        {
            State->ClientStage[Index] = "first-read";
            std::vector<std::byte> Reply(MultiRootPayload(Index).size() + 1U);
            const auto ReplyRead = co_await Stream->ReadExact(Reply);
            IoError = Prism::Fault::ToNative(ReplyRead.Failure);
            const auto Bytes = std::as_bytes(std::span(MultiRootPayload(Index)));
            State->FirstEchoed = !IoError && Reply.front() == std::byte{0} &&
                std::equal(Reply.begin() + 1, Reply.end(), Bytes.begin(), Bytes.end());
            (void)State->FirstEcho.try_send(boost::system::error_code{});
            co_await State->FirstCloseRequest.async_receive(Net::use_awaitable);
            if (State->StopRequested) co_return false;
            std::array<std::byte, 1> Tail{};
            IoError.clear();
            const auto TailRead = co_await Stream->ReadExact(Tail);
            IoError = Prism::Fault::ToNative(TailRead.Failure);
            const bool Sent = State->FirstClientClosed.try_send(boost::system::error_code{});
            std::fprintf(stderr, "[ConfiguredMuxSession] signal=first-client-closed sent=%d\n",
                static_cast<int>(Sent));
            std::fflush(stderr);
        }
        else
        {
            State->ClientStage[Index] = "second-pending-read";
            State->SecondPendingSignaled = State->SecondPending.try_send(boost::system::error_code{});
            std::vector<std::byte> Reply(MultiRootPayload(Index).size() + 1U);
            IoError.clear();
            const auto ReplyRead = co_await Stream->ReadExact(Reply);
            IoError = Prism::Fault::ToNative(ReplyRead.Failure);
            const auto Bytes = std::as_bytes(std::span(MultiRootPayload(Index)));
            State->SecondPayloadEchoed = !IoError && Reply.front() == std::byte{0} &&
                std::equal(Reply.begin() + 1, Reply.end(), Bytes.begin(), Bytes.end());
            if (!State->SecondPayloadEchoed)
            {
                State->FailureMessage = "second multi-root literal echo was invalid";
                State->Stop("client-second-echo");
                co_return false;
            }
            (void)State->SecondEcho.try_send(boost::system::error_code{});
            State->ClientStage[Index] = "second-pending-after-echo";
            std::array<std::byte, 1> Tail{};
            IoError.clear();
            const auto TailRead = co_await Stream->ReadExact(Tail);
            IoError = Prism::Fault::ToNative(TailRead.Failure);
            State->ClientReadReturned[Index] = true;
        }
        co_return true;
    }

    auto RunMultiClient(const std::shared_ptr<MultiRootState> &State, const std::size_t Index)
        -> Net::awaitable<void>
    {
        try
        {
            State->ClientStage[Index] = "auth";
            Prism::SharedTransmission Connection;
            if (State->Family == ProtocolFamily::Socks5)
            {
                const Prism::Socks5::ClientConfig Configuration{
                    true, "configured-account", "task4-provider-password"};
                const Prism::Socks5::Address Target{
                    Prism::Socks5::AddressType::Ipv4, "127.0.0.1", 80};
                auto Connected = co_await Prism::Socks5::Connect(
                    Prism::Socks5::ConnectParameters{State->Client[Index], Configuration, Target});
                if (!Connected)
                {
                    const auto Native = Prism::Fault::ToNative(Connected.error());
                    State->FailureMessage = "multi-root SOCKS5 authentication failed: " +
                        Native.message() + " code=" +
                        std::to_string(static_cast<int>(Connected.error().Code));
                    State->Stop("client-socks-auth");
                    co_return;
                }
                Connection = std::move(*Connected);
            }
            else
            {
                Prism::Shadowsocks2022::ClientConfig Configuration;
                const auto Psk = Prism::Shadowsocks2022::DecodePsk("d3d3d3d3d3d3d3d3d3d3dw==");
                if (!Psk)
                {
                    State->FailureMessage = "multi-root SS2022 PSK did not decode";
                    State->Stop("client-ss-auth");
                    co_return;
                }
                Configuration.Psk = *Psk;
                auto Connected = co_await Prism::Shadowsocks2022::Connect(
                    State->Client[Index], Configuration,
                    {Prism::Shadowsocks2022::AddressType::Ipv4, "127.0.0.1", 80});
                if (!Connected)
                {
                    const auto Native = Prism::Fault::ToNative(Connected.error());
                    State->FailureMessage = "multi-root SS2022 authentication failed: " +
                        Native.message() + " code=" +
                        std::to_string(static_cast<int>(Connected.error().Code));
                    State->Stop("client-ss-auth");
                    co_return;
                }
                Connection = std::move(*Connected);
            }
            const std::array<std::byte, 2> Envelope{std::byte{0}, std::byte{0}};
            State->ClientStage[Index] = "envelope";
            const auto EnvelopeWrite = co_await Connection->WriteExact(Envelope);
            if (EnvelopeWrite.Failure.Failed() || EnvelopeWrite.Bytes != Envelope.size())
            {
                State->FailureMessage = "multi-root smux envelope write failed";
                State->Stop("client-envelope");
                co_return;
            }
            State->ClientMux[Index] = std::make_shared<Prism::Mux::Smux::Client<>>();
            if (!State->ClientMux[Index]->Connect(std::move(Connection)))
            {
                State->FailureMessage = "multi-root smux client did not connect";
                State->Stop("client-smux-connect");
                co_return;
            }
            State->ClientStage[Index] = "open-child";
            auto Stream = co_await State->ClientMux[Index]->OpenStream();
            if (!Stream)
            {
                State->FailureMessage = "multi-root client did not open child";
                State->Stop("client-open-child");
                co_return;
            }
            State->Child[Index] = Stream;
            if (!co_await RunMultiClientChild(State, Index))
            {
                co_return;
            }
            if (const auto Session = State->ClientMux[Index]->Session())
            {
                co_await Session->Close();
            }
            State->ClientDone[Index] = true;
            (void)State->ClientFinished.try_send(boost::system::error_code{});
            State->ClientStage[Index] = "done";
        }
        catch (...)
        {
            State->Failure = std::current_exception();
            State->Stop("client-exception");
        }
    }

    auto RunMultiDrain(const std::shared_ptr<MultiRootState> &State, const std::size_t Index)
        -> Net::awaitable<void>
    {
        (void)State->DrainEntered.try_send(boost::system::error_code{});
        try
        {
            // 两个 waiter 分别排空独立 RootBinding；BoundCatalog 的并发访问不在其契约内。
            const auto Result = co_await State->RootBinding[Index]->Drain();
            State->DrainSucceeded[Index]=static_cast<bool>(Result);
            State->DrainFailed[Index]=!Result;
            if(!Result)State->DrainFailure[Index]=Result.error();
        }
        catch (...)
        {
            State->DrainFailed[Index] = true;
            State->Failure = std::current_exception();
        }
        (void)State->DrainDone.try_send(boost::system::error_code{});
    }

    auto RunMultiWatchdog(const std::shared_ptr<MultiRootState> &State) -> Net::awaitable<void>
    {
        State->Deadline.expires_after(std::chrono::seconds(8));
        boost::system::error_code Error;
        co_await State->Deadline.async_wait(Net::redirect_error(Net::use_awaitable, Error));
        if (!Error)
        {
            State->TimedOut = true;
            State->FailureMessage = "multi-root timeout coordinator=" + State->CoordinatorStage +
                " backend0=" + State->BackendStage[0] + " backend1=" + State->BackendStage[1] +
                " server0=" + State->ServerStage[0] + " server1=" + State->ServerStage[1] +
                " client0=" + State->ClientStage[0] + " client1=" + State->ClientStage[1];
            std::fprintf(stderr, "[ConfiguredMuxSession] %s\n", State->FailureMessage.c_str());
            std::fflush(stderr);
            State->Stop("watchdog");
        }
    }

    /** @brief 记录一个真实 mux 子任务的完成并传播异步异常。 */
    auto CompleteMultiTask(
        const std::shared_ptr<MultiRootState> &State,
        std::exception_ptr Error) -> void
    {
        if (Error)
        {
            State->Failure = std::move(Error);
            State->Stop("child-handler");
        }
        ++State->TasksCompleted;
        (void)State->TasksDone.try_send(boost::system::error_code{});
    }

    /** @brief 等待全部已登记的 mux 子任务实际退栈。 */
    auto WaitForMultiTasks(const std::shared_ptr<MultiRootState> &State) -> Net::awaitable<void>
    {
        while (State->TasksCompleted < State->TasksStarted)
            co_await State->TasksDone.async_receive(Net::use_awaitable);
    }

    /** @brief 停机时等待真实子任务完成，不把协调信号当作完成回执。 */
    auto ExitForMultiStop(const std::shared_ptr<MultiRootState> &State) -> Net::awaitable<bool>
    {
        if (!State->StopRequested) co_return false;
        co_await WaitForMultiTasks(State);
        co_return true;
    }

    auto RunMultiScenario(const std::shared_ptr<MultiRootState> &State) -> Net::awaitable<void>
    {
        State->CoordinatorStage = "spawn";
        for (std::size_t Index = 0; Index < 2; ++Index)
        {
            Net::co_spawn(State->Io, RunMultiBackend(State, Index),
                [State](std::exception_ptr Error) { CompleteMultiTask(State, std::move(Error)); });
            ++State->TasksStarted;
            Net::co_spawn(State->Io, RunMultiServer(State, Index),
                [State](std::exception_ptr Error) { CompleteMultiTask(State, std::move(Error)); });
            ++State->TasksStarted;
            Net::co_spawn(State->Io, RunMultiClient(State, Index),
                [State](std::exception_ptr Error) { CompleteMultiTask(State, std::move(Error)); });
            ++State->TasksStarted;
        }
        for (std::size_t Index = 0; Index < 2; ++Index)
        {
            State->CoordinatorStage = "wait-root-backend-" + std::to_string(Index);
            co_await State->RootReady.async_receive(Net::use_awaitable);
            if (co_await ExitForMultiStop(State)) co_return;
            co_await State->BackendReady.async_receive(Net::use_awaitable);
            if (co_await ExitForMultiStop(State)) co_return;
        }
        State->CoordinatorStage = "wait-first-echo";
        co_await State->FirstEcho.async_receive(Net::use_awaitable);
        if (co_await ExitForMultiStop(State)) co_return;
        State->CoordinatorStage = "wait-second-pending";
        co_await State->SecondPending.async_receive(Net::use_awaitable);
        if (co_await ExitForMultiStop(State)) co_return;
        if (State->Failure)
        {
            co_await WaitForMultiTasks(State);
            co_return;
        }
        State->ConnectionsBeforeClose = State->Record->Runtime()->ActiveConnections();
        State->StreamsBeforeClose = State->Record->Runtime()->ActiveStreams();
        State->Root[0]->Close();
        (void)State->FirstCloseRequest.try_send(boost::system::error_code{});
        State->CoordinatorStage = "wait-root0-done";
        co_await State->RootDone.async_receive(Net::use_awaitable);
        if (co_await ExitForMultiStop(State)) co_return;
        State->CoordinatorStage = "wait-first-client-close";
        co_await State->FirstClientClosed.async_receive(Net::use_awaitable);
        if (co_await ExitForMultiStop(State)) co_return;
        State->CoordinatorStage = "wait-first-backend-eof";
        co_await State->FirstBackendEof.async_receive(Net::use_awaitable);
        if (co_await ExitForMultiStop(State)) co_return;
        State->ConnectionsAfterFirstClose = State->Record->Runtime()->ActiveConnections();
        State->StreamsAfterFirstClose = State->Record->Runtime()->ActiveStreams();
        State->FirstRootClosedSiblingActive = State->RootReturned[0] && !State->RootReturned[1] &&
            !State->ClientReadReturned[1] && State->ConnectionsAfterFirstClose == 1U &&
            State->StreamsAfterFirstClose == 1U;
        (void)State->SecondEchoGate.try_send(boost::system::error_code{});
        State->CoordinatorStage = "wait-second-echo";
        co_await State->SecondEcho.async_receive(Net::use_awaitable);
        if (co_await ExitForMultiStop(State)) co_return;
        for (std::size_t Index = 0; Index < 2; ++Index)
        {
            Net::co_spawn(State->Io, RunMultiDrain(State, Index),
                [State](std::exception_ptr Error) { CompleteMultiTask(State, std::move(Error)); });
            ++State->TasksStarted;
        }
        State->CoordinatorStage = "wait-drain-entered";
        co_await State->DrainEntered.async_receive(Net::use_awaitable);
        if (co_await ExitForMultiStop(State)) co_return;
        co_await State->DrainEntered.async_receive(Net::use_awaitable);
        if (co_await ExitForMultiStop(State)) co_return;
        State->CoordinatorStage = "wait-drain-done";
        co_await State->DrainDone.async_receive(Net::use_awaitable);
        if (co_await ExitForMultiStop(State)) co_return;
        co_await State->DrainDone.async_receive(Net::use_awaitable);
        if (co_await ExitForMultiStop(State)) co_return;
        State->CoordinatorStage = "wait-second-close";
        co_await State->RootDone.async_receive(Net::use_awaitable);
        if (co_await ExitForMultiStop(State)) co_return;
        co_await State->BackendDone.async_receive(Net::use_awaitable);
        if (co_await ExitForMultiStop(State)) co_return;
        co_await State->BackendDone.async_receive(Net::use_awaitable);
        if (co_await ExitForMultiStop(State)) co_return;
        co_await State->ClientFinished.async_receive(Net::use_awaitable);
        if (co_await ExitForMultiStop(State)) co_return;
        co_await State->ClientFinished.async_receive(Net::use_awaitable);
        if (co_await ExitForMultiStop(State)) co_return;
        const auto CatalogDrain = co_await State->Bound->Drain();
        State->CatalogDrained = static_cast<bool>(CatalogDrain);
        if (!CatalogDrain)
        {
            State->CatalogDrainFailure = CatalogDrain.error();
            State->FailureMessage = "multi-root catalog drain failed: " +
                DescribeMuxFailure(CatalogDrain.error());
        }
        State->ConnectionsAfterDrain = State->Record->Runtime()->ActiveConnections();
        State->StreamsAfterDrain = State->Record->Runtime()->ActiveStreams();
        State->CoordinatorStage = "done";
        State->Deadline.cancel();
        co_await WaitForMultiTasks(State);
    }

    auto CleanupMultiRoot(const std::shared_ptr<MultiRootState> &State) -> void
    {
        State->WeakRecord = State->Record;
        for (auto &Value : State->Child)
        {
            Value.reset();
        }
        for (auto &Value : State->ClientMux)
        {
            Value.reset();
        }
        for (auto &Value : State->Root)
        {
            Value.reset();
        }
        for (auto &Value : State->Factory)
        {
            Value.reset();
        }
        for (auto &Value : State->RootBinding)
        {
            Value.reset();
        }
        State->Bound.reset();
        for (auto &Value : State->Client)
        {
            Value.reset();
        }
        for (auto &Value : State->Server)
        {
            Value.reset();
        }
        for (const auto &Value : State->BackendAcceptor)
        {
            if (Value)
            {
                boost::system::error_code Error;
                Value->close(Error);
            }
        }
        State->Egress.reset();
        State->Record.reset();
        State->Directory.reset();
        State->AdmissionPublication.reset();
        State->Pin.reset();
    }

    auto MultiRootScenario(const ProtocolFamily Family) -> std::shared_ptr<MultiRootState>
    {
        auto State = std::make_shared<MultiRootState>(Family);
        State->DebugState("sync-constructed");
        if (!PrepareMultiRoot(State))
        {
            State->DebugState("prepare-failed");
            return State;
        }
        State->DebugState("prepare-complete");
        State->CoordinatorStage = "io-run-start";
        State->DebugState("io-run-start");
        Net::co_spawn(State->Io, RunMultiScenario(State),
            [State](std::exception_ptr Error) { if (Error) { State->Failure = Error; State->Stop("scenario-handler"); } });
        Net::co_spawn(State->Io, RunMultiWatchdog(State),
            [State](std::exception_ptr Error) { if (Error) { State->Failure = Error; State->Stop("watchdog-handler"); } });
        State->Io.run();
        CleanupMultiRoot(State);
        return State;
    }

    auto VerifyMultiRootScenario(const std::shared_ptr<MultiRootState> &State) -> void
    {
        ASSERT_TRUE(State);
        EXPECT_FALSE(State->Failure);
        EXPECT_FALSE(State->TimedOut) << State->FailureMessage;
        EXPECT_TRUE(State->SetupError.empty()) << State->SetupError;
        EXPECT_TRUE(State->LoopbackBound);
        EXPECT_TRUE(State->NoColdAuthentication);
        EXPECT_TRUE(State->DistinctFactories);
        EXPECT_TRUE(State->DistinctRootBindings);
        EXPECT_TRUE(State->FirstEchoed);
        EXPECT_TRUE(State->SecondPendingSignaled);
        EXPECT_TRUE(State->SecondBackendEchoed);
        EXPECT_TRUE(State->SecondPayloadEchoed);
        EXPECT_EQ(State->Dials, 2U);
        EXPECT_TRUE(State->Authenticated[0]);
        EXPECT_TRUE(State->Authenticated[1]);
        EXPECT_TRUE(State->LeaseValid[0]);
        EXPECT_TRUE(State->LeaseValid[1]);
        EXPECT_TRUE(State->BackendReceived[0]);
        EXPECT_TRUE(State->BackendReceived[1]);
        EXPECT_EQ(State->BackendBytes[0], MultiRootPayload(0).size());
        EXPECT_EQ(State->BackendBytes[1], MultiRootPayload(1).size());
        EXPECT_TRUE(State->FirstRootClosedSiblingActive);
        EXPECT_TRUE(State->DrainSucceeded[0]) << DescribeMuxFailure(State->DrainFailure[0]);
        EXPECT_TRUE(State->DrainSucceeded[1]) << DescribeMuxFailure(State->DrainFailure[1]);
        EXPECT_TRUE(State->CatalogDrained)
            << State->FailureMessage << " " << DescribeMuxFailure(State->CatalogDrainFailure);
        ASSERT_TRUE(State->UseState);
        EXPECT_EQ(State->UseState->Outstanding(), 0U);
        EXPECT_FALSE(State->DrainFailed[0]);
        EXPECT_FALSE(State->DrainFailed[1]);
        EXPECT_TRUE(State->RootReturned[0]);
        EXPECT_TRUE(State->RootReturned[1]);
        EXPECT_TRUE(State->RunStatus[0]) << DescribeMuxResult(State->RunStatus[0]);
        EXPECT_TRUE(State->RunStatus[1]) << DescribeMuxResult(State->RunStatus[1]);
        EXPECT_TRUE(State->ClientReadReturned[1]);
        EXPECT_TRUE(State->BackendClosed[0]);
        EXPECT_TRUE(State->BackendClosed[1]);
        EXPECT_TRUE(State->BackendPeerClosed[0]);
        EXPECT_TRUE(State->BackendPeerClosed[1]);
        EXPECT_EQ(State->ConnectionsBeforeClose, 2U);
        EXPECT_EQ(State->StreamsBeforeClose, 2U);
        EXPECT_EQ(State->ConnectionsAfterFirstClose, 1U);
        EXPECT_EQ(State->StreamsAfterFirstClose, 1U);
        EXPECT_EQ(State->ConnectionsAfterDrain, 0U);
        EXPECT_EQ(State->StreamsAfterDrain, 0U);
        EXPECT_TRUE(State->WeakRoot[0].expired());
        EXPECT_TRUE(State->WeakRoot[1].expired());
        EXPECT_EQ(State->TasksCompleted, State->TasksStarted);
        EXPECT_TRUE(State->WeakRecord.expired());
        EXPECT_TRUE(State->WeakGeneration.expired());
        if (State->Failure)
        {
            try
            {
                std::rethrow_exception(State->Failure);
            }
            catch (const std::exception &Error)
            {
                ADD_FAILURE() << Error.what();
            }
        }
    }
} // namespace



