/**
 * @file SplitClient.cpp
 * @brief SplitClient.hpp 非模板 owner 实现。
 */
#include <Prism/Protocols/Xhttp/Detail/Http2ReadCompletion.hpp>
#include <Prism/Protocols/Xhttp/Detail/SplitClient.hpp>

namespace Prism::Xhttp::Detail
{
    auto CloseSplitClientOwner(
        const std::weak_ptr<SplitClientState> &WeakState) noexcept -> Prism::Fault::Failure{
        const auto State = WeakState.lock();
        if (!State)
        {
            return {};
        }
        if (State->CloseStarted)
        {
            return State->CloseFailure;
        }
        State->CloseStarted = true;
        State->Closing.store(true, std::memory_order_release);
        Prism::Fault::Failure FirstFailure;
        if (State->Encrypted)
        {
            try
            {
                const auto Canceled = State->Encrypted->Cancel();
                if (!Canceled) FirstFailure = Canceled.error();
            }
            catch (...)
            {
                FirstFailure = Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception());
            }
        }
        if (State->Wire) State->Wire->Close();
        if (State->Encrypted)
        {
            try
            {
                const auto Closed = State->Encrypted->Close();
                if (FirstFailure.Succeeded() && !Closed) FirstFailure = Closed.error();
            }
            catch (...)
            {
                if (FirstFailure.Succeeded())
                    FirstFailure = Prism::Contract::InboundAdmission::ExceptionFailure(
                        std::current_exception());
            }
        }
        if (Detail::IsLocalCloseCancellation(
                State->Closing.load(std::memory_order_acquire), FirstFailure))
            FirstFailure = Prism::Fault::Failure{};
        if (State->CloseFailure.Succeeded() && FirstFailure.Failed())
            State->CloseFailure = FirstFailure;
        return State->CloseFailure;
    }

    [[nodiscard]] auto FlushSplitClient(
        const std::shared_ptr<SplitClientState> &State)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>{
        std::vector<std::byte> Output;
        if (State->Session->Collect(Output) && !Output.empty())
        {
            co_return co_await State->Wire->Write(Output);
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto CloseSplitClient(const std::shared_ptr<SplitClientState> &State) -> void{
        if (State->Transport)
        {
            if (State->Transport->DrainTerminalPending())
            {
                const auto OwnerClosed =
                    CloseSplitClientOwner(std::weak_ptr<SplitClientState>(State));
                Detail::RecordRetirementFailure(State->CloseFailure, OwnerClosed);
                return;
            }
            const auto Closed = State->Transport->Close();
            if (!Closed)
            {
                Detail::RecordRetirementFailure(State->CloseFailure, Closed.error());
                const auto OwnerClosed =
                    CloseSplitClientOwner(std::weak_ptr<SplitClientState>(State));
                Detail::RecordRetirementFailure(State->CloseFailure, OwnerClosed);
            }
        }
        else
        {
            (void)CloseSplitClientOwner(std::weak_ptr<SplitClientState>(State));
        }
    }

    [[nodiscard]] auto MakeSplitClientState(SplitClientStateRequest Request)
        -> std::shared_ptr<SplitClientState>{
        auto State = std::make_shared<SplitClientState>();
        State->Cfg = std::move(Request.Configuration);
        State->Host = std::move(Request.Host);
        State->SessionId = NextSplitSessionId();
        State->Encrypted = std::make_shared<Prism::Transport::Encrypted>(
            std::move(Request.Stream), std::move(Request.Bytes));
        State->Session = std::make_shared<h2::Session>(State->Encrypted->Executor(), false);
        State->Wire = std::make_shared<WireWriter>(
            State->Encrypted->Executor(), SplitClientWireWriter{State->Encrypted});
        State->Response = std::make_shared<ResponseChannel>(State->Encrypted->Executor(), 1);
        State->DriverDone = std::make_shared<DriverCompletionChannel>(
            State->Encrypted->Executor(), 1);
        const auto WeakState = std::weak_ptr<SplitClientState>(State);
        State->Session->OnHeaders = SplitClientHeadersObserver{WeakState};
        State->Session->OnData = SplitClientDataObserver{WeakState};
        State->Session->OnStreamClose = SplitClientStreamCloseObserver{WeakState};
        State->Transport = std::make_shared<SplitTransport>(
            State->Encrypted->Executor(),
            SplitClientUploadWriter{WeakState}, SplitClientCloseHandler{WeakState});
        return State;
    }

    [[nodiscard]] auto OpenSplitClientStreams(
        const std::shared_ptr<SplitClientState> &State)
        -> std::expected<void, Prism::Fault::Failure>{
        State->Session->SendSettings();
        const auto DownPath = MakeSplitPath(State->Cfg.Path, State->SessionId);
        if (State->Cfg.Mode == "StreamUp")
        {
            const auto Opened = State->Session->OpenStream(
                {{":method", "POST"},
                 {":path", DownPath},
                 {":scheme", "https"},
                 {":authority", State->Host},
                 {"content-type", "application/octet-stream"}},
                false);
            if (!Opened)
            {
                return std::unexpected(Opened.error());
            }
            State->UploadStream = *Opened;
        }
        const auto Download = State->Session->OpenStream(
            {{":method", "GET"},
             {":path", DownPath},
             {":scheme", "https"},
             {":authority", State->Host}},
            true);
        if (!Download)
        {
            return std::unexpected(Download.error());
        }
        State->DownloadStream = *Download;
        return {};
    }

    [[nodiscard]] auto RunSplitClientDriver(
        std::shared_ptr<SplitClientState> State) -> Net::awaitable<void>{
        std::array<std::byte, 16384> Buffer{};
        bool CleanEof = false;
        Prism::Fault::Failure Failure;
        while (true)
            {
                const auto Part = co_await State->Encrypted->ReadSome(Buffer);
                const auto Read = Part.Bytes;
                const auto Step = ProcessHttp2ReadCompletion(
                    *State->Session, Buffer, Part);
                const auto ReadFailure = Step.Failure;
                const auto ErrorCode = Prism::Fault::ToNative(ReadFailure);
                const bool LocalClose = Detail::IsLocalCloseCancellation(
                    State->Closing.load(std::memory_order_acquire), ReadFailure);
                const auto CleanTlsEof = Step.ReadTerminal &&
                    (!ReadFailure.Failed() ||
                        ErrorCode == Prism::Fault::make_error_code(Prism::Fault::Code::Eof));
                if (Read > Buffer.size())
                {
                    Failure = {Prism::Fault::Code::InvalidArgument};
                    State->Transport->NotifyError(Prism::Fault::ToNative(Failure));
                    break;
                }
                if (Read == 0)
                {
                    if (LocalClose)
                    {
                        if (Step.ReadTerminal)
                            State->Transport->NotifyReadTerminal(
                                {Prism::Fault::Code::Eof});
                        break;
                    }
                    CleanEof = !ErrorCode || CleanTlsEof;
                    if (Step.ReadTerminal)
                        State->Transport->NotifyReadTerminal(ReadFailure);
                    if (!CleanEof)
                    {
                        Failure = ReadFailure;
                        if (!Step.ReadTerminal) State->Transport->NotifyError(ErrorCode);
                    }
                    else if (ReadFailure.Failed())
                    {
                        Failure = ReadFailure;
                    }
                    break;
                }
                if (ErrorCode && !CleanTlsEof)
                {
                    if (LocalClose)
                    {
                        if (Step.ReadTerminal)
                            State->Transport->NotifyReadTerminal(
                                {Prism::Fault::Code::Eof});
                        break;
                    }
                    Failure = ReadFailure;
                    if (Step.ReadTerminal)
                        State->Transport->NotifyReadTerminal(ReadFailure);
                    else
                        State->Transport->NotifyError(ErrorCode);
                    break;
                }
                const auto CloseFailure = State->Transport->CloseFailure();
                if (CloseFailure.Failed())
                {
                    Failure = CloseFailure;
                    Detail::RecordRetirementFailure(State->CloseFailure, Failure);
                    break;
                }
                const auto Flushed = co_await FlushSplitClient(State);
                if (!Flushed)
                {
                    Failure = Flushed.error();
                    NotifyHttp2OutputFailure(*State->Transport, Step, Failure);
                    break;
                }
                if (CleanTlsEof)
                {
                    CleanEof = true;
                    if (Step.ReadTerminal)
                        State->Transport->NotifyReadTerminal(ReadFailure);
                    Failure = ReadFailure;
                    break;
                }
            }
        if (CleanEof)
        {
            if (!State->Transport->DrainTerminalPending())
                State->Transport->NotifyEof();
            if (Failure.Succeeded()) Failure = {Prism::Fault::Code::Eof};
        }
        if (State->Transport->DrainTerminalPending())
        {
            CloseSplitClient(State);
        }
        else if (!CleanEof)
        {
            CloseSplitClient(State);
        }
        (void)State->Response->try_send(boost::system::error_code{}, Failure, false);
        co_return;
    }

    auto CompleteSplitClientDriver(
        const std::shared_ptr<SplitClientState> &State,
        std::exception_ptr Exception) -> void{
        Prism::Fault::Failure Failure;
        if (Exception)
        {
            Failure = FailureFromException(std::move(Exception));
        }
        if (Failure.Failed())
        {
            State->Transport->NotifyError(Prism::Fault::ToNative(Failure));
            CloseSplitClient(State);
            (void)State->Response->try_send(
                boost::system::error_code{}, Failure, false);
        }
        (void)State->DriverDone->try_send(boost::system::error_code{}, Failure);
    }

    auto StartSplitClientDriver(const std::shared_ptr<SplitClientState> &State) -> void{
        Net::co_spawn(
            State->Encrypted->Executor(), RunSplitClientDriver(State),
            [State](std::exception_ptr Exception)
            {
                CompleteSplitClientDriver(State, std::move(Exception));
            });
        State->DriverStarted = true;
    }

    [[nodiscard]] auto RetireSplitClientState(
        FactoryRetirement<SplitClientState> &Retirement,
        Prism::Fault::Failure Cause) -> Net::awaitable<Prism::Fault::Failure>{
        co_return co_await Retirement.Retire(Cause);
    }

    [[nodiscard]] auto WaitSplitClientResponse(
        const std::shared_ptr<SplitClientState> &State,
        FactoryRetirement<SplitClientState> &Retirement) -> Net::awaitable<FactoryResult>{
        boost::system::error_code ResponseError;
        Net::steady_timer Deadline(State->Encrypted->Executor());
        Deadline.expires_after(std::chrono::seconds(30));
        auto Receive = State->Response->async_receive(
            Net::redirect_error(Net::use_awaitable, ResponseError));
        const auto Result = co_await (
            std::move(Receive) || Deadline.async_wait(Net::use_awaitable));
        if (Result.index() == 1)
        {
            co_return std::unexpected(co_await RetireSplitClientState(
                Retirement, Prism::Fault::Failure{Prism::Fault::Code::Timeout}));
        }
        if (ResponseError)
            co_return std::unexpected(co_await RetireSplitClientState(
                Retirement, Prism::Fault::FromNative(static_cast<std::error_code>(ResponseError))));
        const auto [Failure, ResponseAccepted] = std::get<0>(Result);
        if (!ResponseAccepted)
        {
            auto Rejection = Failure;
            if (Rejection.Succeeded())
                Rejection = {Prism::Fault::Code::ProtocolError};
            co_return std::unexpected(co_await RetireSplitClientState(Retirement, Rejection));
        }
        auto AcceptedTransportOwner = std::make_shared<AcceptedTransport<SplitClientState>>(
            Retirement.shared_from_this(), State->Transport);
        co_return Prism::SharedTransmission{std::move(AcceptedTransportOwner)};
    }

    [[nodiscard]] auto ConnectSplit(SplitClientConnectRequest Request)
        -> Net::awaitable<FactoryResult>{
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Request.Raw);
        if (!Prepared) co_return std::unexpected(Prepared.error());
        auto Admission = std::move(*Prepared);
        std::shared_ptr<FactoryRetirement<SplitClientState>> Retirement;
        std::optional<FactoryResult> Outcome;
        std::exception_ptr Fatal;
        try
        {
            Retirement = FactoryRetirement<SplitClientState>::Prepare(Request.Raw->Executor());
            Outcome = co_await ConnectSplitCore(std::move(Request), Admission, *Retirement);
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

    [[nodiscard]] auto ConnectSplitCore(
        SplitClientConnectRequest Request,
        Prism::Contract::InboundAdmission &Admission,
        FactoryRetirement<SplitClientState> &Retirement) -> Net::awaitable<FactoryResult>{
        auto Tls = co_await ConnectTls(
            ClientTlsRequest{std::move(Request.Raw), Request.SslContext, Request.Host,
                             Request.Bytes}, Admission);
        if (!Tls)
        {
            co_return std::unexpected(Tls.error());
        }
        auto Stream = std::move(*Tls);
        if (!Request.Cfg.Enabled() || !Request.Cfg.IsSplit())
            co_return std::unexpected(co_await RetireClientTlsFailure(
                Admission, std::move(Stream),
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument}));
        auto State = MakeSplitClientState(
            SplitClientStateRequest{std::move(Stream), std::move(Request.Cfg),
                                    std::move(Request.Host), std::move(Request.Bytes)});
        Retirement.Attach(State);
        Admission.Release();
        const auto Opened = OpenSplitClientStreams(State);
        if (!Opened)
        {
            co_return std::unexpected(co_await RetireSplitClientState(
                Retirement, Opened.error()));
        }
        StartSplitClientDriver(State);
        const auto Flush = co_await FlushSplitClient(State);
        if (!Flush)
            co_return std::unexpected(
                co_await RetireSplitClientState(Retirement, Flush.error()));
        co_return co_await WaitSplitClientResponse(State, Retirement);
    }

    [[nodiscard]] auto SplitClientWireWriter::Run(
            std::weak_ptr<Prism::Transport::Encrypted> Encrypted,
            std::span<const std::byte> Data)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>{
            const auto Owner = Encrypted.lock();
            if (!Owner)
            {
                co_return std::unexpected(Prism::Fault::FromNative(
                    std::make_error_code(std::errc::not_connected)));
            }
            const auto Result = co_await Owner->WriteExact(Data);
            if (Result.Failure.Failed())
            {
                co_return std::unexpected(Result.Failure);
            }
            if (Result.Bytes != Data.size())
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::IoError});
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

    [[nodiscard]] auto SplitClientUploadWriter::Run(
            std::weak_ptr<SplitClientState> State,
            std::span<const std::byte> Data)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>{
            const auto Owner = State.lock();
            if (!Owner)
            {
                co_return std::unexpected(Prism::Fault::FromNative(
                    std::make_error_code(std::errc::not_connected)));
            }
            std::int32_t StreamId = Owner->UploadStream;
            if (Owner->Cfg.Mode == "PacketUp")
            {
                const auto Path = MakeSplitPath(
                    Owner->Cfg.Path, Owner->SessionId, Owner->NextSequence++);
                const auto Opened = Owner->Session->OpenStream(
                    {{":method", "POST"},
                     {":path", Path},
                     {":scheme", "https"},
                     {":authority", Owner->Host},
                     {"content-type", "application/octet-stream"}},
                    false);
                if (!Opened)
                {
                    co_return std::unexpected(Opened.error());
                }
                StreamId = *Opened;
            }
            const auto EndStream = Owner->Cfg.Mode == "PacketUp";
            if (StreamId < 0)
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
                const auto Last = Offset + Count == Data.size();
                auto Status = Owner->Session->SubmitData(StreamId, Chunk, EndStream && Last);
                while (Status == h2::SubmitDataStatus::Blocked)
                {
                    const auto Flushed = co_await FlushSplitClient(Owner);
                    if (!Flushed) co_return std::unexpected(Flushed.error());
                    const auto Writable = co_await Owner->Session->AwaitWritable(StreamId, Count);
                    if (!Writable) co_return std::unexpected(Writable.error());
                    Status = Owner->Session->SubmitData(StreamId, Chunk, EndStream && Last);
                }
                if (Status != h2::SubmitDataStatus::Accepted)
                {
                    if (Status == h2::SubmitDataStatus::Closed)
                    {
                        co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::ConnectionAborted});
                    }
                    co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
                }
                Offset += Count;
                EmptySubmitted = true;
                const auto Flushed = co_await FlushSplitClient(Owner);
                if (!Flushed) co_return std::unexpected(Flushed.error());
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

    auto SplitClientHeadersObserver::operator()(
            const std::int32_t StreamId, const h2::HeaderList &Headers, const bool) const -> void{
            const auto Owner = State.lock();
            if (!Owner || StreamId != Owner->DownloadStream)
            {
                return;
            }
            bool StatusOk = false;
            for (const auto &Header : Headers)
            {
                if (Header.Name == ":status" && Header.Value == "200")
                {
                    StatusOk = true;
                }
            }
            Prism::Fault::Failure Failure;
            if (!StatusOk)
            {
                Failure = {Prism::Fault::Code::ProtocolError};
            }
            (void)Owner->Response->try_send(boost::system::error_code{}, Failure, StatusOk);
        }

    auto SplitClientStreamCloseObserver::operator()(const h2::StreamReceiveClosure &Closure) const -> void{
            const auto Owner = State.lock();
            if (!Owner || Closure.StreamId != Owner->DownloadStream || !Owner->Transport) return;
            if (Closure.Kind == h2::StreamReceiveClosureKind::EndStream)
                Owner->Transport->NotifyEof();
            else
                Owner->Transport->NotifyError(std::make_error_code(std::errc::protocol_error));
        }

    auto SplitClientDataObserver::operator()(
            const std::int32_t StreamId, const std::span<const std::byte> Data) const -> void{
            const auto Owner = State.lock();
            if (Owner && StreamId == Owner->DownloadStream && Owner->Transport)
            {
                Owner->Transport->Push(Data);
            }
        }

} // namespace Prism::Xhttp::Detail
