/**
 * @file StreamServer.cpp
 * @brief StreamServer.hpp 非模板 owner 实现。
 */
#include <Prism/Protocols/Xhttp/Detail/Http2ReadCompletion.hpp>
#include <Prism/Protocols/Xhttp/Detail/StreamServer.hpp>

namespace Prism::Xhttp::Detail
{
    auto ServerState::CloseAndDrain()
        -> Net::awaitable<FactoryRetirementReceipt>{
        return Detail::CloseAndDrainState(*this);
    }

    [[nodiscard]] auto FlushServerFrames(
        const SharedH2Session &Session,
        const std::shared_ptr<WireWriter> &Wire)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>{
        std::vector<std::byte> Output;
        if (Session->Collect(Output) && !Output.empty())
        {
            co_return co_await Wire->Write(Output);
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto CloseServerOwnerOnExecutor(const std::shared_ptr<ServerState> &State) noexcept
        -> Prism::Fault::Failure{
        State->Closing.store(true, std::memory_order_release);
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
        return Detail::IsLocalCloseCancellation(
                   State->Closing.load(std::memory_order_acquire), FirstFailure)
            ? Prism::Fault::Failure{}
            : FirstFailure;
    }

    auto CloseServerOwner(const std::weak_ptr<ServerState> &WeakState) noexcept
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
        return CloseServerOwnerOnExecutor(State);
    }

    auto HandleServerWireFailure(
        const std::weak_ptr<ServerState> &WeakState,
        const Prism::Fault::Failure Failure) noexcept -> void
    {
        if (const auto State = WeakState.lock(); State && State->Transport)
        {
            State->Transport->HandleOutputFailure(Failure, [&WeakState]
            { (void)CloseServerOwner(WeakState); });
            return;
        }
        (void)CloseServerOwner(WeakState);
    }

    auto FailServerControl(
        const std::shared_ptr<ServerState> &State,
        Prism::Fault::Failure Failure) noexcept -> void{
        if (!Failure.Failed())
        {
            Failure = {Prism::Fault::Code::ProtocolError};
        }
        State->Transport->RecordCloseFailure(Failure);
        State->Transport->NotifyError(Prism::Fault::ToNative(Failure));
        const auto Closed = CloseServerOwner(std::weak_ptr<ServerState>(State));
        if (Closed.Failed())
        {
            State->Transport->RecordCloseFailure(Closed);
        }
    }

    [[nodiscard]] auto WriteServerWire(
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

    auto SubmitServerData(
        const std::weak_ptr<ServerState> &WeakState,
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
                const auto Flushed = co_await FlushServerFrames(State->Session, State->Wire);
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
            const auto Flushed = co_await FlushServerFrames(State->Session, State->Wire);
            if (!Flushed) co_return std::unexpected(Flushed.error());
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto FinishServerStream(
        const std::weak_ptr<ServerState> &WeakState,
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
        co_return co_await FlushServerFrames(State->Session, State->Wire);
    }

    auto HandleServerHeaders(
        const std::weak_ptr<ServerState> &WeakState,
        const ServerHeadersEvent &Event) -> void{
        const auto State = WeakState.lock();
        if (!State || State->Transport->StreamId_ >= 0)
        {
            return;
        }
        bool IsPost = false;
        bool HostOk = State->Host.empty();
        std::string_view Path;
        for (const auto &Header : Event.Headers)
        {
            if (Header.Name == ":method" && Header.Value == "POST")
            {
                IsPost = true;
            }
            else if (Header.Name == ":path")
            {
                Path = Header.Value;
            }
            else if (Header.Name == ":authority")
            {
                HostOk = State->Host.empty() || Header.Value == State->Host;
            }
        }
        const std::string_view Base(State->Path.data(), State->Path.size());
        bool PathOk = Path.rfind(Base, 0) == 0;
        if (Base == "/")
        {
            PathOk = Path.rfind('/', 0) == 0;
        }
        if (!IsPost || !PathOk || !HostOk)
        {
            const auto Reset = State->Session->ResetStream(Event.StreamId, 1);
            if (!Reset)
            {
                FailServerControl(State, Reset.error());
                return;
            }
            State->Transport->NotifyError(std::make_error_code(std::errc::protocol_error));
            return;
        }
        State->Transport->BindStream(Event.StreamId);
        const auto Headers = State->Session->SubmitHeaders(
            Event.StreamId, {{":status", "200"}, {"content-type", "text/event-stream"}}, false);
        if (!Headers)
        {
            FailServerControl(State, Headers.error());
            return;
        }
        if (Event.EndStream)
        {
            State->Transport->NotifyEof();
        }
    }

    auto HandleServerData(
        const std::weak_ptr<ServerState> &WeakState,
        const std::int32_t StreamId,
        std::span<const std::byte> Data) -> void{
        if (const auto State = WeakState.lock();
            State && StreamId == State->Transport->StreamId_)
        {
            State->Transport->Push(Data);
        }
    }

    auto HandleServerClose(
        const std::weak_ptr<ServerState> &WeakState,
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

    [[nodiscard]] auto DriveServerSession(
        const std::shared_ptr<ServerState> &State,
        std::span<std::byte> Buffer,
        ServerDriverOutcome &Outcome) -> Net::awaitable<void>{
        bool CleanEof = false;
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
                    Outcome.Failed = true;
                    Outcome.Failure = {Prism::Fault::Code::InvalidArgument};
                    break;
                }
                if (ReadFailure.Failed() && !CleanEof)
                {
                    const bool LocalClose = Detail::IsLocalCloseCancellation(
                        State->Closing.load(std::memory_order_acquire), ReadFailure);
                    if (LocalClose)
                    {
                        Outcome.Failure = {};
                        if (Step.ReadTerminal)
                            State->Transport->NotifyReadTerminal(
                                {Prism::Fault::Code::Eof});
                        break;
                    }
                    Outcome.Failed = true;
                    Outcome.Failure = ReadFailure;
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
                            State->Transport->NotifyReadTerminal(
                                {Prism::Fault::Code::Eof});
                            break;
                        }
                        Outcome.Failure = ReadFailure.Failed()
                            ? ReadFailure
                            : Prism::Fault::Failure{Prism::Fault::Code::Eof};
                        State->Transport->NotifyReadTerminal(Outcome.Failure);
                        CleanEof = Outcome.Failure.Code == Prism::Fault::Code::Eof;
                        Outcome.Failed = !CleanEof;
                    }
                    else
                    {
                        Outcome.Failure = {Prism::Fault::Code::WouldBlock};
                        Outcome.Failed = true;
                    }
                    break;
                }
                std::vector<std::byte> Output;
                if (State->Session->Collect(Output) && !Output.empty())
                {
                    const auto Written = co_await State->Wire->Write(Output);
                    if (!Written)
                    {
                        Outcome.Failed = true;
                        Outcome.Failure = Written.error();
                        NotifyHttp2OutputFailure(
                            *State->Transport, Step, Written.error());
                        break;
                    }
                }
                if (CleanEof)
                {
                    if (Step.ReadTerminal)
                        State->Transport->NotifyReadTerminal(ReadFailure);
                    Outcome.Failure = ReadFailure;
                    break;
                }
                if (Step.ReadTerminal)
                {
                    State->Transport->NotifyReadTerminal(ReadFailure);
                    Outcome.Failure = ReadFailure;
                    CleanEof = Outcome.Failure.Succeeded();
                    Outcome.Failed = !CleanEof;
                    break;
                }
                if (State->HasCloseFailure())
                {
                    Outcome.Failed = true;
                    Outcome.Failure = State->CloseFailureValue();
                    break;
                }
            }
    }

    auto RunServerDriver(std::shared_ptr<ServerState> State)
        -> Net::awaitable<void>{
        std::array<std::byte, 16384> Buffer{};
        ServerDriverOutcome Outcome;
        co_await DriveServerSession(State, Buffer, Outcome);
        if (State->Transport->DrainTerminalPending())
        {
            const auto CloseFailure =
                CloseServerOwner(std::weak_ptr<ServerState>(State));
            if (Outcome.Failure.Succeeded() && CloseFailure.Failed())
                Outcome.Failure = CloseFailure;
        }
        if (Outcome.Failed || State->HasCloseFailure())
        {
            const auto CloseFailure =
                CloseServerOwner(std::weak_ptr<ServerState>(State));
            if (Outcome.Failure.Succeeded() && CloseFailure.Failed())
                Outcome.Failure = CloseFailure;
            if (Outcome.Failure.Succeeded())
                Outcome.Failure = {Prism::Fault::Code::IoError};
            State->DriverFailure = Outcome.Failure;
            if (State->Transport && !State->Transport->DrainTerminalPending())
                State->Transport->NotifyError(Prism::Fault::ToNative(Outcome.Failure));
        }
        else
        {
            // 干净 EOF 会保留终止码，但不构成失败；此处只发布成功回执。
            State->DriverFailure = {};
            if (!State->Transport->DrainTerminalPending())
                State->Transport->NotifyEof();
        }
    }

    auto CompleteServerDriver(
        const std::shared_ptr<ServerState> &State,
        std::exception_ptr Exception) -> void{
        if (Exception)
        {
            State->DriverFailure = FailureFromException(std::move(Exception));
            if (State->Transport)
                State->Transport->NotifyError(Prism::Fault::ToNative(State->DriverFailure));
            const auto Closed = CloseServerOwner(std::weak_ptr<ServerState>(State));
            if (State->DriverFailure.Succeeded() && Closed.Failed())
                State->DriverFailure = Closed;
        }
        (void)State->DriverDone->try_send(
            boost::system::error_code{}, State->DriverFailure);
    }

    auto StartServerDriver(const std::shared_ptr<ServerState> &State) -> void{
        Net::co_spawn(
            State->Encrypted->Executor(), RunServerDriver(State),
            [State](std::exception_ptr Exception)
            {
                CompleteServerDriver(State, std::move(Exception));
            });
        State->DriverStarted = true;
    }

        [[nodiscard]] auto XhttpAccept::Run(Prism::Contract::InboundAdmission &Admission)
            -> Net::awaitable<ServerAcceptResult>{
            std::shared_ptr<FactoryRetirement<ServerState>> Retirement;
            std::optional<ServerAcceptResult> Outcome;
            std::exception_ptr Fatal;
            try
            {
                Retirement = FactoryRetirement<ServerState>::Prepare(Raw_->Executor());
                Outcome = co_await RunCore(Admission, *Retirement);
            }
            catch (...)
            {
                Fatal = std::current_exception();
            }
            if (Fatal)
            {
                auto Cause = FailureFromException(std::move(Fatal));
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

    XhttpAccept::XhttpAccept(XhttpAcceptRequest Request)
            : Raw_(std::move(Request.Raw)), SslCtx_(Request.SslContext),
              Cfg_(std::move(Request.Configuration)), Bytes_(std::move(Request.Bytes)){
        }

    [[nodiscard]] auto XhttpAccept::RunCore(
            Prism::Contract::InboundAdmission &Admission,
            FactoryRetirement<ServerState> &Retirement)
            -> Net::awaitable<ServerAcceptResult>{
            if (!Raw_ || !Bytes_)
            {
                co_return std::unexpected(co_await Admission.Retire(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument}));
            }
            if (!Cfg_.Enabled() || Cfg_.IsSplit())
                co_return std::unexpected(co_await Admission.Retire(
                    Prism::Fault::Failure{Prism::Fault::Code::NotSupported}));
            auto Handshake = co_await Prism::Transport::Encrypted::SslHandshake(
                {std::move(Raw_), SslCtx_,
                 std::chrono::steady_clock::now() + Prism::Transport::Encrypted::DefaultHandshakeTimeout,
                 std::move(Bytes_)});
            if (Handshake.Failure.Code != Prism::Fault::Code::Success || !Handshake.Stream)
            {
                auto Failure = Handshake.Failure;
                if (Failure.Succeeded()) Failure = {Prism::Fault::Code::TlsHsfail};
                if (Handshake.Recovered)
                {
                    const auto Tracked = Admission.Track(Handshake.Recovered);
                    if (!Tracked && Failure.Succeeded()) Failure = Tracked.error();
                }
                if (Handshake.Stream)
                {
                    auto TlsOwner = std::make_shared<Prism::Transport::Encrypted>(
                        std::move(Handshake.Stream), std::move(Handshake.Bytes));
                    auto Child = std::static_pointer_cast<Prism::Transmission>(TlsOwner);
                    const auto Tracked = Admission.Track(Child);
                    if (!Tracked)
                    {
                        Prism::Contract::ProtocolDataPlane Plane;
                        Plane.Root = Prism::Contract::StreamDataPlane{Child, {}};
                        const auto Rejected = co_await Admission.Reject(
                            std::move(Plane), Failure);
                        const auto Retired = co_await Retirement.Retire(Rejected.error());
                        co_return std::unexpected(Retired);
                    }
                }
                co_return std::unexpected(co_await Admission.Retire(Failure));
            }
            auto State = std::make_shared<ServerState>();
            State->Encrypted = std::make_shared<Prism::Transport::Encrypted>(
                std::move(Handshake.Stream), std::move(Handshake.Bytes));
            Retirement.Attach(State);
            Admission.Release();
            State->Session = std::make_shared<h2::Session>(State->Encrypted->Executor(), true);
            State->Path = Cfg_.Path;
            State->Host = Cfg_.Host;
            State->Wire = std::make_shared<WireWriter>(
                State->Encrypted->Executor(),
                [Encrypted = State->Encrypted](std::span<const std::byte> Data)
                { return WriteServerWire(Encrypted, Data); },
                [WeakState = std::weak_ptr<ServerState>(State)](
                    const Prism::Fault::Failure Failure)
                { HandleServerWireFailure(WeakState, Failure); });
            State->DriverDone = std::make_shared<DriverCompletionChannel>(
                State->Encrypted->Executor(), 1);
            const std::weak_ptr<ServerState> WeakState = State;
            State->Transport = std::make_shared<XhttpTransport>(
                XhttpTransport::Options{
                    .Executor = State->Encrypted->Executor(),
                    .Write = [WeakState](std::int32_t StreamId, std::span<const std::byte> Data)
                    { return SubmitServerData(WeakState, StreamId, Data); },
                    .Finish = [WeakState](std::int32_t StreamId)
                    { return FinishServerStream(WeakState, StreamId); },
                     .CloseOwner = [WeakState]() -> Prism::Fault::Failure
                    { return CloseServerOwner(WeakState); }});
            State->Session->OnHeaders = [WeakState](
                std::int32_t StreamId, const h2::HeaderList &Headers, bool EndStream)
            { HandleServerHeaders(WeakState, ServerHeadersEvent{StreamId, Headers, EndStream}); };
            State->Session->OnData = [WeakState](
                std::int32_t StreamId, std::span<const std::byte> Data)
            { HandleServerData(WeakState, StreamId, Data); };
            State->Session->OnStreamClose = [WeakState](
                const h2::StreamReceiveClosure &Closure)
            { HandleServerClose(WeakState, Closure); };

            StartServerDriver(State);
            auto Accepted = std::make_shared<AcceptedTransport<ServerState>>(
                Retirement.shared_from_this(), State->Transport);
            co_return ServerAcceptance{
                Prism::SharedTransmission{std::move(Accepted)},
                std::move(Handshake.Negotiated)};
        }

} // namespace Prism::Xhttp::Detail
