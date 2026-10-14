/**
 * @file StreamClient.hpp
 * @brief XHTTP Stream-one 客户端状态机。
 */

#pragma once

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Protocols/Xhttp/Detail/ClientTls.hpp>
#include <Preview/Protocols/Xhttp/Detail/StreamClientState.hpp>
#include <Preview/Protocols/Xhttp/Detail/StreamTransport.hpp>
#include <Preview/Protocols/Xhttp/Detail/Wire.hpp>
#include <Preview/Protocols/Xhttp/Detail/AcceptedTransport.hpp>
#include <Preview/Protocols/Xhttp/Detail/FactoryRetirement.hpp>
#include <Preview/Transport/Encrypted.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace Preview::Xhttp::Detail
{

    struct ClientHeadersEvent final
    {
        std::int32_t StreamId;
        const h2::HeaderList &Headers;
        bool EndStream;
    };

    inline auto CloseClientOwnerOnExecutor(const std::shared_ptr<ClientState> &State) noexcept
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
    inline auto CloseClientOwner(const std::weak_ptr<ClientState> &WeakState) noexcept
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
        return CloseClientOwnerOnExecutor(State);
    }
[[nodiscard]] inline auto WriteClientWire(
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

    [[nodiscard]] inline auto FlushClientFrames(
        const std::shared_ptr<ClientState> &State)
        -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        std::vector<std::byte> Out;
        if (State->Session->Collect(Out) && !Out.empty())
        {
            co_return co_await State->Wire->Write(Out);
        }
        co_return std::expected<void, Preview::Fault::Failure>{};
    }

    inline auto SubmitClientData(
        const std::weak_ptr<ClientState> &WeakState,
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
                const auto Flushed = co_await FlushClientFrames(State);
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
            const auto Flushed = co_await FlushClientFrames(State);
            if (!Flushed) co_return std::unexpected(Flushed.error());
        }
        co_return std::expected<void, Preview::Fault::Failure>{};
    }

    inline auto FinishClientStream(
        const std::weak_ptr<ClientState> &WeakState,
        const std::int32_t StreamId)
        -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        const auto State = WeakState.lock();
        if (!State)
        {
            co_return std::unexpected(Preview::Fault::FromNative(
                std::make_error_code(std::errc::broken_pipe)));
        }
        const auto Status = State->Session->SubmitData(StreamId, {}, true);
        if (Status != h2::SubmitDataStatus::Accepted)
        {
            const auto Code = Status == h2::SubmitDataStatus::Closed
                ? Preview::Fault::Code::ConnectionAborted
                : Preview::Fault::Code::InvalidArgument;
            co_return std::unexpected(Preview::Fault::Failure{Code});
        }
        std::vector<std::byte> Output;
        if (State->Session->Collect(Output) && !Output.empty())
        {
            co_return co_await State->Wire->Write(Output);
        }
        co_return std::expected<void, Preview::Fault::Failure>{};
    }

    inline auto HandleClientHeaders(
        const std::weak_ptr<ClientState> &WeakState,
        const ClientHeadersEvent &Event) -> void
    {
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
        Preview::Fault::Failure Failure;
        if (!Accepted)
        {
            Failure = {Preview::Fault::Code::ProtocolError};
        }
        (void)State->Response->try_send(boost::system::error_code{}, Failure, Accepted);
        if (Event.EndStream)
        {
            State->Transport->NotifyEof();
        }
    }

    inline auto HandleClientData(
        const std::weak_ptr<ClientState> &WeakState,
        const std::int32_t StreamId,
        std::span<const std::byte> Data) -> void
    {
        if (const auto State = WeakState.lock();
            State && StreamId == State->Transport->StreamId_)
        {
            State->Transport->Push(Data);
        }
    }

    inline auto HandleClientClose(
        const std::weak_ptr<ClientState> &WeakState,
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

    inline auto RunClientDriver(std::shared_ptr<ClientState> State)
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
                auto NotifyFailure = Failure;
                if (NotifyFailure.Succeeded())
                {
                    NotifyFailure = {Preview::Fault::Code::IoError};
                }
                State->Transport->NotifyError(Preview::Fault::ToNative(NotifyFailure));
                const auto CloseFailure = CloseClientOwner(std::weak_ptr<ClientState>(State));
                if (Failure.Succeeded() && CloseFailure.Failed()) Failure = CloseFailure;
                if (Failure.Succeeded()) Failure = {Preview::Fault::Code::IoError};
            }
            else
            {
                State->Transport->NotifyEof();
                if (Failure.Succeeded()) Failure = {Preview::Fault::Code::Eof};
            }
        (void)State->Response->try_send(boost::system::error_code{}, Failure, false);
    }

    [[nodiscard]] inline auto MakeClientState(
        Preview::Transport::Encrypted::SharedStream Stream,
        std::shared_ptr<Preview::Memory::BytePool> Bytes) -> std::shared_ptr<ClientState>
    {
        auto State = std::make_shared<ClientState>();
        State->Encrypted = std::make_shared<Preview::Transport::Encrypted>(
            std::move(Stream), std::move(Bytes));
        State->Session = std::make_shared<h2::Session>(State->Encrypted->Executor(), false);
        State->Wire = std::make_shared<WireWriter>(
            State->Encrypted->Executor(),
            [Encrypted = State->Encrypted](std::span<const std::byte> Data)
            { return WriteClientWire(Encrypted, Data); },
            [WeakState = std::weak_ptr<ClientState>(State)]
            { CloseClientOwner(WeakState); });
        const std::weak_ptr<ClientState> WeakState = State;
        State->Transport = std::make_shared<XhttpTransport>(
            XhttpTransport::Options{
                .Executor = State->Encrypted->Executor(),
                .Write = [WeakState](std::int32_t StreamId, std::span<const std::byte> Data)
                { return SubmitClientData(WeakState, StreamId, Data); },
                .Finish = [WeakState](std::int32_t StreamId)
                { return FinishClientStream(WeakState, StreamId); },
                .CloseOwner = [WeakState]() -> Preview::Fault::Failure
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

    [[nodiscard]] inline auto RetireClientState(
        FactoryRetirement<ClientState> &Retirement,
        Preview::Fault::Failure Cause) -> Net::awaitable<Preview::Fault::Failure>
    {
        co_return co_await Retirement.Retire(Cause);
    }

    inline auto CompleteClientDriver(
        const std::shared_ptr<ClientState> &State,
        std::exception_ptr Exception) -> void
    {
        Preview::Fault::Failure Failure;
        if (Exception)
        {
            Failure = FailureFromException(std::move(Exception));
        }
        if (Failure.Failed())
        {
            State->Transport->NotifyError(Preview::Fault::ToNative(Failure));
            (void)CloseClientOwner(std::weak_ptr<ClientState>(State));
            (void)State->Response->try_send(boost::system::error_code{}, Failure, false);
        }
        (void)State->DriverDone->try_send(boost::system::error_code{}, Failure);
    }

    inline auto StartClientDriver(const std::shared_ptr<ClientState> &State) -> void
    {
        Net::co_spawn(
            State->Encrypted->Executor(),
            RunClientDriver(State),
            [State](std::exception_ptr Exception)
            {
                CompleteClientDriver(State, std::move(Exception));
            });
        State->DriverStarted = true;
    }

    /**
     * @brief 同步提交 Stream client 的 HTTP/2 设置与请求头。
     * @param State 持有 HTTP/2 会话和加密传输的状态；不转移所有权。
     * @param Cfg 请求配置；只在本次同步调用中读取。
     * @param Host 请求 authority；只借用到头字段编码完成。
     * @return 成功返回空值；stream 打开失败时保留完整 HTTP/2 Failure。
     * @details 必须在 Session executor 上调用且不可取消。POST 使用 EndStream=false，
     *          因此仅打开请求 stream，不关闭本地发送半边。client factory/retirement owner
     *          负责后续 I/O、传输排空及最终关闭。
     */
    [[nodiscard]] inline auto OpenClientStream(
        const std::shared_ptr<ClientState> &State,
        const Config &Cfg,
        std::string_view Host) -> std::expected<void, Preview::Fault::Failure>
    {
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

    [[nodiscard]] inline auto WaitClientResponse(
        const std::shared_ptr<ClientState> &State,
        FactoryRetirement<ClientState> &Retirement) -> Net::awaitable<FactoryResult>
    {
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
                Retirement, Preview::Fault::Failure{Preview::Fault::Code::Timeout}));
        }
        if (ResponseEc)
        {
            co_return std::unexpected(co_await RetireClientState(
                Retirement, Preview::Fault::FromNative(static_cast<std::error_code>(ResponseEc))));
        }
        const auto [Failure, ResponseAccepted] = std::get<0>(Result);
        if (!ResponseAccepted)
        {
            auto Rejection = Failure;
            if (Rejection.Succeeded())
                Rejection = {Preview::Fault::Code::ProtocolError};
            co_return std::unexpected(co_await RetireClientState(Retirement, Rejection));
        }
        auto AcceptedTransportOwner = std::make_shared<AcceptedTransport<ClientState>>(
            Retirement.shared_from_this(), State->Transport);
        co_return Preview::SharedTransmission{std::move(AcceptedTransportOwner)};
    }

    [[nodiscard]] inline auto ConnectStreamCore(
        ClientConnectRequest Request,
        Preview::Contract::InboundAdmission &Admission,
        FactoryRetirement<ClientState> &Retirement) -> Net::awaitable<FactoryResult>;

    [[nodiscard]] inline auto ConnectStream(
        ClientConnectRequest Request) -> Net::awaitable<FactoryResult>
    {
        auto Prepared = co_await Preview::Contract::InboundAdmission::Prepare(Request.Raw);
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

    [[nodiscard]] inline auto ConnectStreamCore(
        ClientConnectRequest Request,
        Preview::Contract::InboundAdmission &Admission,
        FactoryRetirement<ClientState> &Retirement) -> Net::awaitable<FactoryResult>
    {
        if (!Request.SslContext)
        {
            co_return std::unexpected(co_await Admission.Retire(
                Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument}));
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
                Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument}));
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

} // namespace Preview::Xhttp::Detail
