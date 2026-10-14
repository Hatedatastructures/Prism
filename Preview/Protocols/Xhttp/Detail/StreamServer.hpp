/**
 * @file StreamServer.hpp
 * @brief XHTTP Stream-one 服务端握手与 HTTP/2 驱动。
 */

#pragma once

#include <Preview/Contract/Ingress/DataPlane.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Protocols/Xhttp/Detail/Common.hpp>
#include <Preview/Protocols/Xhttp/Detail/StreamTransport.hpp>
#include <Preview/Protocols/Xhttp/Detail/Wire.hpp>
#include <Preview/Protocols/Xhttp/Detail/AcceptedTransport.hpp>
#include <Preview/Protocols/Xhttp/Detail/FactoryRetirement.hpp>
#include <Preview/Transport/Encrypted.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace Preview::Xhttp::Detail
{

    /** @brief XHTTP Stream-one 服务端接受状态的完整 owning 输入。 */
    struct XhttpAcceptRequest final
    {
        SharedTransmission Raw;
        Net::ssl::context &SslContext;
        Config Configuration;
        std::shared_ptr<Preview::Memory::BytePool> Bytes;
    };

    struct ServerState final
    {
        std::shared_ptr<Preview::Transport::Encrypted> Encrypted;
        SharedH2Session Session;
        std::shared_ptr<WireWriter> Wire;
        std::shared_ptr<XhttpTransport> Transport;
        std::shared_ptr<DriverCompletionChannel> DriverDone;
        bool DriverStarted{false};
        bool DriverCompleted{false};
        Preview::Fault::Failure DriverFailure;
        std::string Path;
        std::string Host;
        std::atomic_bool Closing{false};

        [[nodiscard]] auto HasCloseFailure() const noexcept -> bool
        {
            return Transport && Transport->CloseFailure().Failed();
        }

        [[nodiscard]] auto CloseFailureValue() const noexcept -> Preview::Fault::Failure
        {
            if (Transport)
            {
                return Transport->CloseFailure();
            }
            return {};
        }

        [[nodiscard]] auto CloseAndDrain()
            -> Net::awaitable<FactoryRetirementReceipt>;
    };

    inline auto ServerState::CloseAndDrain()
        -> Net::awaitable<FactoryRetirementReceipt>
    {
        return Detail::CloseAndDrainState(*this);
    }

    [[nodiscard]] inline auto FlushServerFrames(
        const SharedH2Session &Session,
        const std::shared_ptr<WireWriter> &Wire)
        -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        std::vector<std::byte> Output;
        if (Session->Collect(Output) && !Output.empty())
        {
            co_return co_await Wire->Write(Output);
        }
        co_return std::expected<void, Preview::Fault::Failure>{};
    }
    struct ServerHeadersEvent final
    {
        std::int32_t StreamId;
        const h2::HeaderList &Headers;
        bool EndStream;
    };

    inline auto CloseServerOwnerOnExecutor(const std::shared_ptr<ServerState> &State) noexcept
        -> Preview::Fault::Failure
    {
        Preview::Fault::Failure FirstFailure;
        const auto Record = [&FirstFailure](Preview::Transmission::ControlResult Result) noexcept
        {
            if (!Result && FirstFailure.Succeeded()) FirstFailure = Result.error();
        };
        if (State->Transport) Record(State->Transport->Close());
        if (State->Encrypted)
        {
            try
            {
                Record(State->Encrypted->Cancel());
            }
            catch (...)
            {
                if (FirstFailure.Succeeded())
                    FirstFailure = Preview::Contract::InboundAdmission::ExceptionFailure(
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
                    FirstFailure = Preview::Contract::InboundAdmission::ExceptionFailure(
                        std::current_exception());
            }
        }
        if (State->Transport)
        {
            State->Transport->RecordCloseFailure(FirstFailure);
            if (FirstFailure.Failed())
                State->Transport->NotifyError(Preview::Fault::ToNative(FirstFailure));
        }
        return FirstFailure;
    }

    /** @brief 仅由 Encrypted executor 调用；首 close failure 同步返回。 */
    inline auto CloseServerOwner(const std::weak_ptr<ServerState> &WeakState) noexcept
        -> Preview::Fault::Failure
    {
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

    inline auto FailServerControl(
        const std::shared_ptr<ServerState> &State,
        Preview::Fault::Failure Failure) noexcept -> void
    {
        if (!Failure.Failed())
        {
            Failure = {Preview::Fault::Code::ProtocolError};
        }
        State->Transport->RecordCloseFailure(Failure);
        State->Transport->NotifyError(Preview::Fault::ToNative(Failure));
        const auto Closed = CloseServerOwner(std::weak_ptr<ServerState>(State));
        if (Closed.Failed())
        {
            State->Transport->RecordCloseFailure(Closed);
        }
    }

    [[nodiscard]] inline auto WriteServerWire(
        const std::shared_ptr<Preview::Transport::Encrypted> &Encrypted,
        std::span<const std::byte> Data)
        -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        const auto Result = co_await Encrypted->WriteExact(Data);
        if (Result.Failure.Failed())
        {
            co_return std::unexpected(Result.Failure);
        }
        if (Result.Bytes != Data.size())
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::IoError});
        co_return std::expected<void, Preview::Fault::Failure>{};
    }

    inline auto SubmitServerData(
        const std::weak_ptr<ServerState> &WeakState,
        const std::int32_t StreamId,
        std::span<const std::byte> Data)
        -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        const auto State = WeakState.lock();
        if (!State)
        {
            co_return std::unexpected(Preview::Fault::FromNative(
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
                    ? Preview::Fault::Code::ConnectionAborted
                    : Preview::Fault::Code::InvalidArgument;
                co_return std::unexpected(Preview::Fault::Failure{Code});
            }
            Offset += Count;
            EmptySubmitted = true;
            const auto Flushed = co_await FlushServerFrames(State->Session, State->Wire);
            if (!Flushed) co_return std::unexpected(Flushed.error());
        }
        co_return std::expected<void, Preview::Fault::Failure>{};
    }

    inline auto HandleServerHeaders(
        const std::weak_ptr<ServerState> &WeakState,
        const ServerHeadersEvent &Event) -> void
    {
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

    inline auto HandleServerData(
        const std::weak_ptr<ServerState> &WeakState,
        const std::int32_t StreamId,
        std::span<const std::byte> Data) -> void
    {
        if (const auto State = WeakState.lock();
            State && StreamId == State->Transport->StreamId_)
        {
            State->Transport->Push(Data);
        }
    }

    inline auto HandleServerClose(
        const std::weak_ptr<ServerState> &WeakState,
        const h2::StreamReceiveClosure &Closure) -> void
    {
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

    inline auto RunServerDriver(std::shared_ptr<ServerState> State)
        -> Net::awaitable<void>
    {
        std::array<std::byte, 16384> Buffer{};
        bool Failed = false;
        bool CleanEof = false;
        Preview::Fault::Failure Failure;
            while (true)
            {
                const auto Part = co_await State->Encrypted->ReadSome(Buffer);
                std::error_code ErrorCode = Preview::Fault::ToNative(Part.Failure);
                const auto Read = Part.Bytes;
                CleanEof = Part.Failure.Code == Preview::Fault::Code::Eof;
                if (Read > Buffer.size())
                {
                    Failed = true;
                    Failure = {Preview::Fault::Code::InvalidArgument};
                    break;
                }
                if (Part.Failure.Failed() && !CleanEof)
                {
                    Failed = true;
                    Failure = Part.Failure;
                    break;
                }
                if (Read == 0)
                {
                    if (CleanEof)
                        Failure = Part.Failure;
                    else
                        Failure = {Preview::Fault::Code::WouldBlock};
                    Failed = !CleanEof;
                    break;
                }
                if (!State->Session->Feed(
                        std::span<const std::byte>(Buffer.data(), Read), ErrorCode) &&
                    ErrorCode != make_error_code(Error::NeedMore))
                {
                    Failed = true;
                    if (ErrorCode)
                    {
                        Failure = Preview::Fault::FromNative(ErrorCode);
                    }
                    else
                    {
                        Failure = {Preview::Fault::Code::ProtocolError};
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
                        break;
                    }
                }
                if (CleanEof)
                {
                    Failure = Part.Failure;
                    break;
                }
            }
            if (Failed || State->HasCloseFailure())
            {
                const auto CloseFailure = CloseServerOwner(std::weak_ptr<ServerState>(State));
                if (Failure.Succeeded() && CloseFailure.Failed()) Failure = CloseFailure;
                if (Failure.Succeeded()) Failure = {Preview::Fault::Code::IoError};
                State->DriverFailure = Failure;
                if (State->Transport)
                    State->Transport->NotifyError(Preview::Fault::ToNative(Failure));
            }
            else
            {
                State->DriverFailure = Failure;
                State->Transport->NotifyEof();
            }
        }

    inline auto CompleteServerDriver(
        const std::shared_ptr<ServerState> &State,
        std::exception_ptr Exception) -> void
    {
        if (Exception)
        {
            State->DriverFailure = FailureFromException(std::move(Exception));
            if (State->Transport)
                State->Transport->NotifyError(Preview::Fault::ToNative(State->DriverFailure));
            const auto Closed = CloseServerOwner(std::weak_ptr<ServerState>(State));
            if (State->DriverFailure.Succeeded() && Closed.Failed())
                State->DriverFailure = Closed;
        }
        (void)State->DriverDone->try_send(
            boost::system::error_code{}, State->DriverFailure);
    }

    inline auto StartServerDriver(const std::shared_ptr<ServerState> &State) -> void
    {
        Net::co_spawn(
            State->Encrypted->Executor(), RunServerDriver(State),
            [State](std::exception_ptr Exception)
            {
                CompleteServerDriver(State, std::move(Exception));
            });
        State->DriverStarted = true;
    }

    /**
     * @class XhttpAccept
     * @brief 编排 XHTTP Stream-one 服务端 TLS、HTTP/2 与 POST 匹配。
     * @details 该对象只拥有本次接受操作的 Raw 传输和 TLS 上下文引用；
     *          返回的 XhttpTransport 持有数据面状态，driver 通过共享状态继续运行。
     */
    class XhttpAccept final : public std::enable_shared_from_this<XhttpAccept>
    {
    public:
        explicit XhttpAccept(XhttpAcceptRequest Request)
            : Raw_(std::move(Request.Raw)), SslCtx_(Request.SslContext),
              Cfg_(std::move(Request.Configuration)), Bytes_(std::move(Request.Bytes))
        {
        }

        [[nodiscard]] auto Run(Preview::Contract::InboundAdmission &Admission)
            -> Net::awaitable<ServerAcceptResult>
        {
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

    private:
        [[nodiscard]] auto RunCore(
            Preview::Contract::InboundAdmission &Admission,
            FactoryRetirement<ServerState> &Retirement)
            -> Net::awaitable<ServerAcceptResult>
        {
            if (!Raw_ || !Bytes_)
            {
                co_return std::unexpected(co_await Admission.Retire(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument}));
            }
            if (!Cfg_.Enabled() || Cfg_.IsSplit())
                co_return std::unexpected(co_await Admission.Retire(
                    Preview::Fault::Failure{Preview::Fault::Code::NotSupported}));
            auto Handshake = co_await Preview::Transport::Encrypted::SslHandshake(
                {std::move(Raw_), SslCtx_,
                 std::chrono::steady_clock::now() + Preview::Transport::Encrypted::DefaultHandshakeTimeout,
                 std::move(Bytes_)});
            if (Handshake.Failure.Code != Preview::Fault::Code::Success || !Handshake.Stream)
            {
                auto Failure = Handshake.Failure;
                if (Failure.Succeeded()) Failure = {Preview::Fault::Code::TlsHsfail};
                if (Handshake.Recovered)
                {
                    const auto Tracked = Admission.Track(Handshake.Recovered);
                    if (!Tracked && Failure.Succeeded()) Failure = Tracked.error();
                }
                if (Handshake.Stream)
                {
                    auto TlsOwner = std::make_shared<Preview::Transport::Encrypted>(
                        std::move(Handshake.Stream), std::move(Handshake.Bytes));
                    auto Child = std::static_pointer_cast<Preview::Transmission>(TlsOwner);
                    const auto Tracked = Admission.Track(Child);
                    if (!Tracked)
                    {
                        Preview::Contract::ProtocolDataPlane Plane;
                        Plane.Root = Preview::Contract::StreamDataPlane{Child, {}};
                        const auto Rejected = co_await Admission.Reject(
                            std::move(Plane), Failure);
                        const auto Retired = co_await Retirement.Retire(Rejected.error());
                        co_return std::unexpected(Retired);
                    }
                }
                co_return std::unexpected(co_await Admission.Retire(Failure));
            }
            auto State = std::make_shared<ServerState>();
            State->Encrypted = std::make_shared<Preview::Transport::Encrypted>(
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
                [WeakState = std::weak_ptr<ServerState>(State)]
                { CloseServerOwner(WeakState); });
            State->DriverDone = std::make_shared<DriverCompletionChannel>(
                State->Encrypted->Executor(), 1);
            const std::weak_ptr<ServerState> WeakState = State;
            State->Transport = std::make_shared<XhttpTransport>(
                XhttpTransport::Options{
                    .Executor = State->Encrypted->Executor(),
                    .Write = [WeakState](std::int32_t StreamId, std::span<const std::byte> Data)
                    { return SubmitServerData(WeakState, StreamId, Data); },
                     .CloseOwner = [WeakState]() -> Preview::Fault::Failure
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
                Preview::SharedTransmission{std::move(Accepted)},
                std::move(Handshake.Negotiated)};
        }

    private:
        SharedTransmission Raw_;
        Net::ssl::context &SslCtx_;
        Config Cfg_;
        std::shared_ptr<Preview::Memory::BytePool> Bytes_;
    };

} // namespace Preview::Xhttp::Detail
