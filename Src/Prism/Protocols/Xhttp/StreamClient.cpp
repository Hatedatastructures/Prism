/**
 * @file StreamClient.cpp
 * @brief StreamClient.hpp 非模板 owner 实现。
 */
#include <Prism/Protocols/Xhttp/Detail/Http2ReadCompletion.hpp>
#include <Prism/Protocols/Xhttp/Detail/StreamClient.hpp>

namespace Prism::Xhttp::Detail
{
    auto CloseClientOwnerOnExecutor(const std::shared_ptr<ClientState> &State) noexcept
        -> Prism::Fault::Failure{
        Prism::Fault::Failure FirstFailure;
        const auto Record = [&FirstFailure](Prism::Transmission::ControlResult Result) noexcept
        {
            if (!Result && FirstFailure.Succeeded()) FirstFailure = Result.error();
        };
        if (State->Transport && !State->Transport->DrainTerminalPending())
            Record(State->Transport->Close());
        if (State->Encrypted)
        {
            try
            {
                Record(State->Encrypted->Cancel());
            }
            catch (...)
            {
                if (FirstFailure.Succeeded())
                    FirstFailure = Prism::Contract::InboundAdmission::ExceptionFailure(
                        std::current_exception());
            }
        }
        if (State->Wire) State->Wire->Close();
        if (State->Encrypted)
        {
            try
            {
                Record(State->Encrypted->Close());
            }
            catch (...)
            {
                if (FirstFailure.Succeeded())
                    FirstFailure = Prism::Contract::InboundAdmission::ExceptionFailure(
                        std::current_exception());
            }
        }
        if (State->Transport)
        {
            State->Transport->RecordCloseFailure(FirstFailure);
            if (FirstFailure.Failed())
                State->Transport->NotifyError(Prism::Fault::ToNative(FirstFailure));
        }
        return FirstFailure;
    }

    auto CloseClientOwner(const std::weak_ptr<ClientState> &WeakState) noexcept
        -> Prism::Fault::Failure{
        const auto State = WeakState.lock();
        if (!State)
        {
            return {};
        }
        if (State->Closing.exchange(true))
        {
            return State->CloseFailureValue();
        }
        return CloseClientOwnerOnExecutor(State);
    }

    auto HandleClientWireFailure(
        const std::weak_ptr<ClientState> &WeakState,
        const Prism::Fault::Failure Failure) noexcept -> void
    {
        if (const auto State = WeakState.lock(); State && State->Transport)
        {
            State->Transport->HandleOutputFailure(Failure, [&WeakState]
            { (void)CloseClientOwner(WeakState); });
            return;
        }
        (void)CloseClientOwner(WeakState);
    }

[[nodiscard]] auto WriteClientWire(
        const std::shared_ptr<Prism::Transport::Encrypted> &Encrypted,
        std::span<const std::byte> Data)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>{
        const auto Result = co_await Encrypted->WriteExact(Data);
        if (Result.Failure.Failed())
        {
            co_return std::unexpected(Result.Failure);
        }
        if (Result.Bytes != Data.size())
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::IoError});
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    [[nodiscard]] auto FlushClientFrames(
        const std::shared_ptr<ClientState> &State)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>{
        std::vector<std::byte> Out;
        if (State->Session->Collect(Out) && !Out.empty())
        {
            co_return co_await State->Wire->Write(Out);
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto SubmitClientData(
        const std::weak_ptr<ClientState> &WeakState,
        const std::int32_t StreamId,
        std::span<const std::byte> Data)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>{
        const auto State = WeakState.lock();
        if (!State)
        {
            co_return std::unexpected(Prism::Fault::FromNative(
                std::make_error_code(std::errc::broken_pipe)));
        }
        std::size_t Offset = 0;
        bool EmptySubmitted = false;
        while (Offset < Data.size() || !EmptySubmitted)
        {
            const auto Count = (std::min)(std::size_t{16U * 1024U}, Data.size() - Offset);
            const auto Chunk = Data.subspan(Offset, Count);
            auto Status = State->Session->SubmitData(StreamId, Chunk, false);
            while (Status == h2::SubmitDataStatus::Blocked)
            {
                const auto Flushed = co_await FlushClientFrames(State);
                if (!Flushed) co_return std::unexpected(Flushed.error());
                const auto Writable = co_await State->Session->AwaitWritable(StreamId, Count);
                if (!Writable) co_return std::unexpected(Writable.error());
                Status = State->Session->SubmitData(StreamId, Chunk, false);
            }
            if (Status != h2::SubmitDataStatus::Accepted)
            {
                const auto Code = Status == h2::SubmitDataStatus::Closed
                    ? Prism::Fault::Code::ConnectionAborted
                    : Prism::Fault::Code::InvalidArgument;
                co_return std::unexpected(Prism::Fault::Failure{Code});
            }
            Offset += Count;
            EmptySubmitted = true;
            const auto Flushed = co_await FlushClientFrames(State);
            if (!Flushed) co_return std::unexpected(Flushed.error());
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto FinishClientStream(
        const std::weak_ptr<ClientState> &WeakState,
        const std::int32_t StreamId)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>{
        const auto State = WeakState.lock();
        if (!State)
        {
            co_return std::unexpected(Prism::Fault::FromNative(
                std::make_error_code(std::errc::broken_pipe)));
        }
        const auto Status = State->Session->SubmitData(StreamId, {}, true);
        if (Status != h2::SubmitDataStatus::Accepted)
        {
            const auto Code = Status == h2::SubmitDataStatus::Closed
                ? Prism::Fault::Code::ConnectionAborted
                : Prism::Fault::Code::InvalidArgument;
            co_return std::unexpected(Prism::Fault::Failure{Code});
        }
        std::vector<std::byte> Output;
        if (State->Session->Collect(Output) && !Output.empty())
        {
            co_return co_await State->Wire->Write(Output);
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto HandleClientHeaders(
        const std::weak_ptr<ClientState> &WeakState,
        const ClientHeadersEvent &Event) -> void{
        const auto State = WeakState.lock();
        if (!State || Event.StreamId != State->Transport->StreamId_)
        {
            return;
        }
        bool StatusOk = false;
        bool ContentTypeOk = false;
        for (const auto &Header : Event.Headers)
        {
            if (Header.Name == ":status" && Header.Value == "200")
            {
                StatusOk = true;
            }
            else if (Header.Name == "content-type" && Header.Value == "text/event-stream")
            {
                ContentTypeOk = true;
            }
        }
        const bool Accepted = StatusOk && ContentTypeOk;
        Prism::Fault::Failure Failure;
        if (!Accepted)
        {
            Failure = {Prism::Fault::Code::ProtocolError};
        }
        (void)State->Response->try_send(boost::system::error_code{}, Failure, Accepted);
        if (Event.EndStream)
        {
            State->Transport->NotifyEof();
        }
    }

    auto HandleClientData(
        const std::weak_ptr<ClientState> &WeakState,
        const std::int32_t StreamId,
        std::span<const std::byte> Data) -> void{
        if (const auto State = WeakState.lock();
            State && StreamId == State->Transport->StreamId_)
        {
            State->Transport->Push(Data);
        }
    }

    auto HandleClientClose(
        const std::weak_ptr<ClientState> &WeakState,
        const h2::StreamReceiveClosure &Closure) -> void{
        if (const auto State = WeakState.lock();
            State && Closure.StreamId == State->Transport->StreamId_)
        {
            if (Closure.Kind == h2::StreamReceiveClosureKind::EndStream)
            {
                State->Transport->NotifyEof();
            }
            else
            {
                State->Transport->NotifyError(std::make_error_code(std::errc::protocol_error));
            }
        }
    }

    auto RunClientDriver(std::shared_ptr<ClientState> State)
        -> Net::awaitable<void>{
        std::array<std::byte, 16384> Buffer{};
        bool Failed = false;
        bool CleanEof = false;
        bool LocalCloseCompletion = false;
        Prism::Fault::Failure Failure;
        while (true)
            {
                const auto Part = co_await State->Encrypted->ReadSome(Buffer);
                const auto Read = Part.Bytes;
                if (Read != 0U && Part.Failure.Code == Prism::Fault::Code::Eof)
                    State->Transport->PreserveAcceptedDataForOutputFailure();
                const auto Step = ProcessHttp2ReadCompletion(
                    *State->Session, Buffer, Part);
                const auto ReadFailure = Step.Failure;
                CleanEof = Step.ReadTerminal &&
                    (!ReadFailure.Failed() || ReadFailure.Code == Prism::Fault::Code::Eof);
                if (Read > Buffer.size())
                {
                    Failed = true;
                    Failure = {Prism::Fault::Code::InvalidArgument};
                    break;
                }
                if (ReadFailure.Failed() && !CleanEof)
                {
                    const bool LocalClose = Detail::IsLocalCloseCancellation(
                        State->Closing.load(std::memory_order_acquire), ReadFailure);
                    if (LocalClose)
                    {
                        LocalCloseCompletion = true;
                        Failure = {};
                        if (Step.ReadTerminal)
                            State->Transport->NotifyReadTerminal(
                                {Prism::Fault::Code::Eof});
                        break;
                    }
                    Failed = true;
                    Failure = ReadFailure;
                    if (Step.ReadTerminal)
                        State->Transport->NotifyReadTerminal(ReadFailure);
                    else
                        State->Transport->NotifyError(Prism::Fault::ToNative(ReadFailure));
                    break;
                }
                if (Read == 0)
                {
                    if (Step.ReadTerminal)
                    {
                        const bool LocalClose = Detail::IsLocalCloseCancellation(
                            State->Closing.load(std::memory_order_acquire),
                            ReadFailure);
                        if (LocalClose)
                        {
                            LocalCloseCompletion = true;
                            State->Transport->NotifyReadTerminal(
                                {Prism::Fault::Code::Eof});
                            break;
                        }
                        Failure = ReadFailure.Failed()
                            ? ReadFailure
                            : Prism::Fault::Failure{Prism::Fault::Code::Eof};
                        State->Transport->NotifyReadTerminal(Failure);
                        CleanEof = Failure.Code == Prism::Fault::Code::Eof;
                        Failed = !CleanEof;
                    }
                    else
                    {
                        Failure = {Prism::Fault::Code::WouldBlock};
                        Failed = true;
                    }
                    break;
                }
                std::vector<std::byte> Output;
                if (State->Session->Collect(Output) && !Output.empty())
                {
                    const auto Written = co_await State->Wire->Write(Output);
                    if (!Written)
                    {
                        Failed = true;
                        Failure = Written.error();
                        NotifyHttp2OutputFailure(
                            *State->Transport, Step, Written.error());
                        break;
                    }
                }
                if (CleanEof)
                {
                    if (Step.ReadTerminal)
                        State->Transport->NotifyReadTerminal(ReadFailure);
                    Failure = ReadFailure;
                    break;
                }
                if (Step.ReadTerminal)
                {
                    State->Transport->NotifyReadTerminal(ReadFailure);
                    Failure = ReadFailure;
                    CleanEof = Failure.Succeeded();
                    Failed = !CleanEof;
                    break;
                }
                if (State->HasCloseFailure())
                {
                    Failed = true;
                    Failure = State->CloseFailureValue();
                    break;
                }
            }
            if (State->Transport->DrainTerminalPending())
            {
                const auto CloseFailure =
                    CloseClientOwner(std::weak_ptr<ClientState>(State));
                if (Failure.Succeeded() && CloseFailure.Failed()) Failure = CloseFailure;
            }
            if (Failed || State->HasCloseFailure())
            {
                auto NotifyFailure = Failure;
                if (NotifyFailure.Succeeded())
                {
                    NotifyFailure = {Prism::Fault::Code::IoError};
                }
                if (!State->Transport->DrainTerminalPending())
                    State->Transport->NotifyError(Prism::Fault::ToNative(NotifyFailure));
                const auto CloseFailure = CloseClientOwner(std::weak_ptr<ClientState>(State));
                if (Failure.Succeeded() && CloseFailure.Failed()) Failure = CloseFailure;
                if (Failure.Succeeded()) Failure = {Prism::Fault::Code::IoError};
            }
            else
            {
                if (!State->Transport->DrainTerminalPending())
                    State->Transport->NotifyEof();
                if (LocalCloseCompletion)
                    Failure = {};
                else if (Failure.Succeeded())
                    Failure = {Prism::Fault::Code::Eof};
            }
        (void)State->Response->try_send(boost::system::error_code{}, Failure, false);
    }

    [[nodiscard]] auto MakeClientState(
        Prism::Transport::Encrypted::SharedStream Stream,
        std::shared_ptr<Prism::Memory::BytePool> Bytes) -> std::shared_ptr<ClientState>{
        auto State = std::make_shared<ClientState>();
        State->Encrypted = std::make_shared<Prism::Transport::Encrypted>(
            std::move(Stream), std::move(Bytes));
        State->Session = std::make_shared<h2::Session>(State->Encrypted->Executor(), false);
        State->Wire = std::make_shared<WireWriter>(
            State->Encrypted->Executor(),
            [Encrypted = State->Encrypted](std::span<const std::byte> Data)
            { return WriteClientWire(Encrypted, Data); },
            [WeakState = std::weak_ptr<ClientState>(State)](
                const Prism::Fault::Failure Failure)
            { HandleClientWireFailure(WeakState, Failure); });
        const std::weak_ptr<ClientState> WeakState = State;
        State->Transport = std::make_shared<XhttpTransport>(
            XhttpTransport::Options{
                .Executor = State->Encrypted->Executor(),
                .Write = [WeakState](std::int32_t StreamId, std::span<const std::byte> Data)
                { return SubmitClientData(WeakState, StreamId, Data); },
                .Finish = [WeakState](std::int32_t StreamId)
                { return FinishClientStream(WeakState, StreamId); },
                .CloseOwner = [WeakState]() -> Prism::Fault::Failure
                { return CloseClientOwner(WeakState); }});
        State->Response = std::make_shared<ResponseChannel>(State->Encrypted->Executor(), 1);
        State->DriverDone = std::make_shared<DriverCompletionChannel>(
            State->Encrypted->Executor(), 1);
        State->Session->OnHeaders = [WeakState](
            std::int32_t StreamId, const h2::HeaderList &Headers, bool EndStream)
        { HandleClientHeaders(WeakState, ClientHeadersEvent{StreamId, Headers, EndStream}); };
        State->Session->OnData = [WeakState](
            std::int32_t StreamId, std::span<const std::byte> Data)
        { HandleClientData(WeakState, StreamId, Data); };
        State->Session->OnStreamClose = [WeakState](
            const h2::StreamReceiveClosure &Closure)
        { HandleClientClose(WeakState, Closure); };
        return State;
    }

    [[nodiscard]] auto RetireClientState(
        FactoryRetirement<ClientState> &Retirement,
        Prism::Fault::Failure Cause) -> Net::awaitable<Prism::Fault::Failure>{
        co_return co_await Retirement.Retire(Cause);
    }

    auto CompleteClientDriver(
        const std::shared_ptr<ClientState> &State,
        std::exception_ptr Exception) -> void{
        Prism::Fault::Failure Failure;
        if (Exception)
        {
            Failure = FailureFromException(std::move(Exception));
        }
        if (Failure.Failed())
        {
            State->Transport->NotifyError(Prism::Fault::ToNative(Failure));
            (void)CloseClientOwner(std::weak_ptr<ClientState>(State));
            (void)State->Response->try_send(boost::system::error_code{}, Failure, false);
        }
        (void)State->DriverDone->try_send(boost::system::error_code{}, Failure);
    }

    auto StartClientDriver(const std::shared_ptr<ClientState> &State) -> void{
        Net::co_spawn(
            State->Encrypted->Executor(),
            RunClientDriver(State),
            [State](std::exception_ptr Exception)
            {
                CompleteClientDriver(State, std::move(Exception));
            });
        State->DriverStarted = true;
    }

    [[nodiscard]] auto OpenClientStream(
        const std::shared_ptr<ClientState> &State,
        const Config &Cfg,
        std::string_view Host) -> std::expected<void, Prism::Fault::Failure>{
        State->Session->SendSettings();
        const auto StreamId = State->Session->OpenStream(
            {{":method", "POST"}, {":path", Cfg.Path}, {":scheme", "https"},
             {":authority", std::string(Host)}, {"content-type", "text/event-stream"}},
            false);
        if (!StreamId)
        {
            return std::unexpected(StreamId.error());
        }
        State->Transport->BindStream(*StreamId);
        return {};
    }

    [[nodiscard]] auto WaitClientResponse(
        const std::shared_ptr<ClientState> &State,
        FactoryRetirement<ClientState> &Retirement) -> Net::awaitable<FactoryResult>{
        boost::system::error_code ResponseEc;
        Net::steady_timer Deadline(State->Encrypted->Executor());
        Deadline.expires_after(std::chrono::seconds(30));
        auto Receive = State->Response->async_receive(
            Net::redirect_error(Net::use_awaitable, ResponseEc));
        const auto Result = co_await (
            std::move(Receive) || Deadline.async_wait(Net::use_awaitable));
        if (Result.index() == 1)
        {
            co_return std::unexpected(co_await RetireClientState(
                Retirement, Prism::Fault::Failure{Prism::Fault::Code::Timeout}));
        }
        if (ResponseEc)
        {
            co_return std::unexpected(co_await RetireClientState(
                Retirement, Prism::Fault::FromNative(static_cast<std::error_code>(ResponseEc))));
        }
        const auto [Failure, ResponseAccepted] = std::get<0>(Result);
        if (!ResponseAccepted)
        {
            auto Rejection = Failure;
            if (Rejection.Succeeded())
                Rejection = {Prism::Fault::Code::ProtocolError};
            co_return std::unexpected(co_await RetireClientState(Retirement, Rejection));
        }
        auto AcceptedTransportOwner = std::make_shared<AcceptedTransport<ClientState>>(
            Retirement.shared_from_this(), State->Transport);
        co_return Prism::SharedTransmission{std::move(AcceptedTransportOwner)};
    }

    [[nodiscard]] auto ConnectStream(
        ClientConnectRequest Request) -> Net::awaitable<FactoryResult>{
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Request.Raw);
        if (!Prepared) co_return std::unexpected(Prepared.error());
        auto Admission = std::move(*Prepared);
        std::shared_ptr<FactoryRetirement<ClientState>> Retirement;
        std::optional<FactoryResult> Outcome;
        std::exception_ptr Fatal;
        try
        {
            Retirement = FactoryRetirement<ClientState>::Prepare(Request.Raw->Executor());
            Outcome = co_await ConnectStreamCore(std::move(Request), Admission, *Retirement);
        }
        catch (...)
        {
            Fatal = std::current_exception();
        }
        if (Fatal)
        {
            auto Cause = FailureFromException(Fatal);
            const auto InboundFailure = co_await Admission.Retire(Cause);
            if (Cause.Succeeded() && InboundFailure.Failed()) Cause = InboundFailure;
            if (Retirement)
            {
                const auto OwnerFailure = co_await Retirement->Retire(Cause);
                if (Cause.Succeeded() && OwnerFailure.Failed()) Cause = OwnerFailure;
            }
            co_return std::unexpected(Cause);
        }
        co_return std::move(*Outcome);
    }

    [[nodiscard]] auto ConnectStreamCore(
        ClientConnectRequest Request,
        Prism::Contract::InboundAdmission &Admission,
        FactoryRetirement<ClientState> &Retirement) -> Net::awaitable<FactoryResult>{
        if (!Request.SslContext)
        {
            co_return std::unexpected(co_await Admission.Retire(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument}));
        }
        auto Tls = co_await ConnectTls(
            ClientTlsRequest{std::move(Request.Raw), *Request.SslContext, Request.Host,
                             Request.Bytes}, Admission);
        if (!Tls)
        {
            co_return std::unexpected(Tls.error());
        }
        auto Stream = std::move(*Tls);
        if (!Request.Configuration.Enabled())
        {
            co_return std::unexpected(co_await RetireClientTlsFailure(
                Admission, std::move(Stream),
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument}));
        }
        auto State = MakeClientState(std::move(Stream), std::move(Request.Bytes));
        Retirement.Attach(State);
        Admission.Release();
        StartClientDriver(State);
        const auto Opened = OpenClientStream(State, Request.Configuration, Request.Host);
        if (!Opened)
        {
            co_return std::unexpected(co_await RetireClientState(
                Retirement, Opened.error()));
        }
        const auto Flush = co_await FlushClientFrames(State);
        if (!Flush)
            co_return std::unexpected(
                co_await RetireClientState(Retirement, Flush.error()));
        co_return co_await WaitClientResponse(State, Retirement);
    }

} // namespace Prism::Xhttp::Detail
