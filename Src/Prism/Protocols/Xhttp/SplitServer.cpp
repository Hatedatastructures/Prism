/**
 * @file SplitServer.cpp
 * @brief SplitServer.hpp 非模板 owner 实现。
 */
#include <Prism/Protocols/Xhttp/Detail/Http2ReadCompletion.hpp>
#include <Prism/Protocols/Xhttp/Detail/SplitServer.hpp>
#include <Prism/Protocols/Xhttp/Detail/SplitServerWireWriter.hpp>

namespace Prism::Xhttp::Detail
{
    auto SplitServerState::CloseAndDrain()
        -> Net::awaitable<FactoryRetirementReceipt>{
        return Detail::CloseAndDrainState(*this);
    }

    [[nodiscard]] auto FlushSplitSession(
        const std::shared_ptr<SplitServerState> &State)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>{
        std::vector<std::byte> Output;
        if (State->Session->Collect(Output) && !Output.empty())
        {
            co_return co_await State->Wire->Write(Output);
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto CloseSplitServerOwner(
        const std::weak_ptr<SplitServerState> &WeakState) noexcept -> Prism::Fault::Failure{
        const auto State = WeakState.lock();
        if (!State)
        {
            return {};
        }
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
        if (State->CloseFailure.Succeeded() && FirstFailure.Failed())
            State->CloseFailure = FirstFailure;
        return State->CloseFailure;
    }

    auto SignalSplitReady(
        const std::shared_ptr<SplitServerState> &State,
        const bool Accepted,
        Prism::Fault::Failure Failure) -> void{
        if (State->ReadySignaled)
        {
            return;
        }
        State->ReadySignaled = true;
        (void)State->Ready->try_send(boost::system::error_code{}, Failure, Accepted);
    }

    auto PushSplitServerData(
        const std::shared_ptr<SplitServerState> &State,
        std::span<const std::byte> Data) -> void{
        if (Data.empty())
        {
            return;
        }
        if (State->Transport)
        {
            State->Transport->Push(Data);
            return;
        }
        State->PendingUpload.emplace_back(Data.begin(), Data.end());
    }

    [[nodiscard]] auto MakeSplitResponse(
        const std::string_view Status,
        const bool EndStream) -> h2::HeaderList{
        (void)EndStream;
        return {{":status", std::string(Status)},
                {"content-type", "text/event-stream"},
                {"cache-control", "no-cache"}};
    }

    auto FailSplitServerControl(
        const std::shared_ptr<SplitServerState> &State,
        Prism::Fault::Failure Failure) -> void{
        if (State->DriverFailure.Succeeded())
        {
            State->DriverFailure = Failure;
        }
        if (State->DriverFailure.Succeeded())
        {
            State->DriverFailure = {Prism::Fault::Code::ProtocolError};
        }
        if (State->CloseFailure.Succeeded())
        {
            State->CloseFailure = State->DriverFailure;
        }
        SignalSplitReady(State, false, State->DriverFailure);
        if (State->Transport)
        {
            State->Transport->NotifyError(Prism::Fault::ToNative(State->DriverFailure));
            const auto Closed = State->Transport->Close();
            if (!Closed && State->CloseFailure.Succeeded())
            {
                State->CloseFailure = Closed.error();
            }
            return;
        }
        const auto Closed = CloseSplitServerOwner(std::weak_ptr<SplitServerState>(State));
        if (State->CloseFailure.Succeeded() && Closed.Failed())
        {
            State->CloseFailure = Closed;
        }
    }

    auto RejectSplitRequest(
        const std::shared_ptr<SplitServerState> &State,
        const std::int32_t StreamId) -> void{
        const auto Headers = State->Session->SubmitHeaders(
            StreamId,
            MakeSplitResponse("404", true),
            true);
        if (!Headers)
        {
            FailSplitServerControl(State, Headers.error());
        }
    }

    auto BindSplitServerTransport(
        const std::shared_ptr<SplitServerState> &State) -> void{
        if (State->Transport || State->DownloadStream < 0)
        {
            return;
        }
        State->Transport = std::make_shared<SplitTransport>(
            State->Encrypted->Executor(),
            SplitServerUploadWriter{State}, SplitServerCloseHandler{State});
        for (auto &Pending : State->PendingUpload)
        {
            State->Transport->Push(Pending);
        }
        State->PendingUpload.clear();
        if (State->UploadEnded)
        {
            State->Transport->NotifyEof();
        }
    }

    auto HandleSplitServerHeaders(SplitServerHeaderInput Input) -> void{
        const auto &State = Input.State;
        const auto StreamId = Input.StreamId;
        const auto &Headers = Input.Headers;
        const auto EndStream = Input.EndStream;
        bool IsGet = false;
        bool IsPost = false;
        bool HostOk = State->Cfg.Host.empty();
        std::string_view Path;
        for (const auto &Header : Headers)
        {
            if (Header.Name == ":method")
            {
                IsGet = Header.Value == "GET";
                IsPost = Header.Value == "POST";
            }
            else if (Header.Name == ":path")
            {
                Path = Header.Value;
            }
            else if (Header.Name == ":authority")
            {
                HostOk = State->Cfg.Host.empty() || Header.Value == State->Cfg.Host;
            }
        }

        const auto Parsed = ParseSplitPath(
            State->Cfg.Path,
            Path,
            State->Cfg.Mode == "PacketUp" && IsPost);
        const auto IsDownstream = IsGet && Parsed && !Parsed->HasSequence;
        const auto IsStreamUpload = State->Cfg.Mode == "StreamUp" && IsPost && Parsed &&
                                    !Parsed->HasSequence;
        const auto IsPacketUpload = State->Cfg.Mode == "PacketUp" && IsPost && Parsed &&
                                    Parsed->HasSequence;
        if (!HostOk || !Parsed || (!IsDownstream && !IsStreamUpload && !IsPacketUpload))
        {
            RejectSplitRequest(State, StreamId);
            return;
        }
        if (State->SessionId.empty())
        {
            State->SessionId = Parsed->Session;
        }
        if (State->SessionId != Parsed->Session)
        {
            RejectSplitRequest(State, StreamId);
            return;
        }
        if (IsDownstream)
        {
            if (State->DownloadStream >= 0)
            {
                RejectSplitRequest(State, StreamId);
                return;
            }
            State->DownloadStream = StreamId;
            const auto Response = State->Session->SubmitHeaders(
                StreamId,
                MakeSplitResponse("200", false),
                false);
            if (!Response)
            {
                FailSplitServerControl(State, Response.error());
                return;
            }
            BindSplitServerTransport(State);
            SignalSplitReady(State, true, {});
            return;
        }
        if (IsStreamUpload)
        {
            if (State->UploadStream >= 0)
            {
                RejectSplitRequest(State, StreamId);
                return;
            }
            State->UploadStream = StreamId;
            const auto Response = State->Session->SubmitHeaders(
                StreamId,
                MakeSplitResponse("200", false),
                false);
            if (!Response)
            {
                FailSplitServerControl(State, Response.error());
                return;
            }
            if (EndStream)
            {
                State->UploadEnded = true;
            }
            return;
        }

        State->PacketBodies.emplace(StreamId, std::vector<std::byte>{});
        const auto Response = State->Session->SubmitHeaders(
            StreamId,
            MakeSplitResponse("200", true),
            false);
        if (!Response)
        {
            State->PacketBodies.erase(StreamId);
            FailSplitServerControl(State, Response.error());
            return;
        }
        if (EndStream)
        {
            State->PacketBodies.erase(StreamId);
        }
    }

    auto HandleSplitServerData(
        const std::shared_ptr<SplitServerState> &State,
        const std::int32_t StreamId,
        std::span<const std::byte> Data) -> void{
        if (State->Cfg.Mode == "StreamUp" && StreamId == State->UploadStream)
        {
            PushSplitServerData(State, Data);
            return;
        }
        const auto Packet = State->PacketBodies.find(StreamId);
        if (Packet != State->PacketBodies.end())
        {
            Packet->second.insert(Packet->second.end(), Data.begin(), Data.end());
        }
    }

    auto HandleSplitServerClose(
        const std::shared_ptr<SplitServerState> &State,
        const h2::StreamReceiveClosure &Closure) -> void{
        if (State->Cfg.Mode == "StreamUp" && Closure.StreamId == State->UploadStream)
        {
            State->UploadEnded = true;
            if (State->Transport && Closure.Kind == h2::StreamReceiveClosureKind::EndStream)
            {
                State->Transport->NotifyEof();
            }
            else if (State->Transport)
            {
                State->Transport->NotifyError(std::make_error_code(std::errc::protocol_error));
            }
            return;
        }
        const auto Packet = State->PacketBodies.find(Closure.StreamId);
        if (Packet != State->PacketBodies.end())
        {
            if (Closure.Kind == h2::StreamReceiveClosureKind::EndStream)
            {
                PushSplitServerData(State, Packet->second);
                if (State->Session->SubmitData(Closure.StreamId, {}, true) != h2::SubmitDataStatus::Accepted)
                {
                    FailSplitServerControl(
                        State, Prism::Fault::Failure{Prism::Fault::Code::ProtocolError});
                }
            }
            State->PacketBodies.erase(Packet);
        }
        if (Closure.StreamId == State->DownloadStream && State->Transport)
        {
            // GET 请求的远端 END_STREAM 只关闭请求方向，不能结束响应数据方向。
            if (Closure.Kind == h2::StreamReceiveClosureKind::Reset)
            {
                State->Transport->NotifyError(std::make_error_code(std::errc::protocol_error));
            }
        }
    }

    struct SplitServerDriverExit final
    {
        Prism::Fault::Failure Failure;
        bool CleanEof{false};
    };

    [[nodiscard]] auto FinishSplitServerDriver(
        const std::shared_ptr<SplitServerState> &State,
        const SplitServerDriverExit Exit) -> Net::awaitable<void>
    {
        auto Failure = Exit.Failure;
        const bool CleanEof = Exit.CleanEof;
        if (!State->ReadySignaled)
        {
            if (Failure.Succeeded())
            {
                if (CleanEof)
                {
                    Failure = {Prism::Fault::Code::Eof};
                }
                else
                {
                    Failure = {Prism::Fault::Code::ProtocolError};
                }
            }
            State->DriverFailure = Failure;
            SignalSplitReady(State, false, Failure);
        }
        else
        {
            State->DriverFailure = Failure;
        }
        const bool DrainReadTerminal =
            State->Transport && State->Transport->DrainTerminalPending();
        if (DrainReadTerminal)
        {
            const auto OwnerClosed =
                CloseSplitServerOwner(std::weak_ptr<SplitServerState>(State));
            if (Failure.Succeeded() && OwnerClosed.Failed()) Failure = OwnerClosed;
        }
        if (State->Transport && CleanEof && !DrainReadTerminal)
        {
            State->Transport->NotifyEof();
        }
        if (!CleanEof && !DrainReadTerminal)
        {
            const auto OwnerClosed =
                CloseSplitServerOwner(std::weak_ptr<SplitServerState>(State));
            if (Failure.Succeeded() && OwnerClosed.Failed())
            {
                Failure = OwnerClosed;
            }
            if (State->Transport)
            {
                const auto Closed = State->Transport->Close();
                if (Failure.Succeeded() && !Closed)
                {
                    Failure = Closed.error();
                }
            }
            if (State->DriverFailure.Succeeded() && Failure.Failed())
                State->DriverFailure = Failure;
        }
        co_return;
    }

    [[nodiscard]] auto RunSplitServerDriver(
        std::shared_ptr<SplitServerState> State) -> Net::awaitable<void>{
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
                    State->DriverFailure = Failure;
                    if (State->Transport)
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
                        State->DriverFailure = Failure;
                        if (State->Transport && !Step.ReadTerminal)
                            State->Transport->NotifyError(ErrorCode);
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
                    State->DriverFailure = Failure;
                    if (State->Transport)
                    {
                        if (Step.ReadTerminal)
                            State->Transport->NotifyReadTerminal(ReadFailure);
                        else
                            State->Transport->NotifyError(ErrorCode);
                    }
                    break;
                }
                if (State->DriverFailure.Failed())
                {
                    Failure = State->DriverFailure;
                    break;
                }
                if (State->Transport && State->Transport->CloseFailure().Failed())
                {
                    Failure = State->Transport->CloseFailure();
                    State->CloseFailure = Failure;
                    break;
                }
                const auto Flushed = co_await FlushSplitSession(State);
                if (!Flushed)
                {
                    Failure = Flushed.error();
                    State->DriverFailure = Failure;
                    if (State->Transport)
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
        co_await FinishSplitServerDriver(State, SplitServerDriverExit{Failure, CleanEof});
    }

    [[nodiscard]] auto SplitServerUploadWriter::Run(
            std::weak_ptr<SplitServerState> State,
            std::span<const std::byte> Data)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>{
            const auto Owner = State.lock();
            if (!Owner || Owner->DownloadStream < 0)
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
                auto Status = Owner->Session->SubmitData(Owner->DownloadStream, Chunk, false);
                while (Status == h2::SubmitDataStatus::Blocked)
                {
                    const auto Flushed = co_await FlushSplitSession(Owner);
                    if (!Flushed) co_return std::unexpected(Flushed.error());
                    const auto Writable = co_await Owner->Session->AwaitWritable(
                        Owner->DownloadStream, Count);
                    if (!Writable) co_return std::unexpected(Writable.error());
                    Status = Owner->Session->SubmitData(Owner->DownloadStream, Chunk, false);
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
                const auto Flushed = co_await FlushSplitSession(Owner);
                if (!Flushed) co_return std::unexpected(Flushed.error());
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

    [[nodiscard]] auto SplitServerWireWriter::Run(
        std::weak_ptr<Prism::Transport::Encrypted> Encrypted,
        std::span<const std::byte> Data)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
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
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::IoError});
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

} // namespace Prism::Xhttp::Detail
