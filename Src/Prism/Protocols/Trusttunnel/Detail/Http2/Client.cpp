/**
 * @file Client.cpp
 * @brief TrustTunnel HTTP/2 客户端 carrier、CONNECT 请求与响应 owner 实现。
 */

#include <Prism/Protocols/Trusttunnel/Detail/Http2/Client.hpp>

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Trusttunnel/Codec.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/AcceptedClientTransport.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/CarrierOwner.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2/Transport.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2/WireWriter.hpp>
#include <Prism/Protocols/Trusttunnel/Types.hpp>
#include <Prism/Protocols/Trusttunnel/Http2/Client/Types.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2/ClientDriver.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2/ReadCompletion.hpp>
#include <Prism/Transport/Connector.hpp>
#include <Prism/Transport/Encrypted.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <openssl/ssl.h>

#include <array>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>

namespace Prism::Trusttunnel::Detail
{

    auto Http2ClientState::Close() -> Prism::Transmission::ControlResult
    {
        if (!Carrier || IsRetired()) return {};
        return Carrier->Close();
    }

    auto Http2ClientState::Cancel() -> Prism::Transmission::ControlResult
    {
        if (!Carrier || IsRetired()) return {};
        return Carrier->Cancel();
    }

    auto Http2ClientState::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (!Carrier)
        {
            const auto First = Failure.Load();
            if (First.Failed()) co_return std::unexpected(First);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        const auto Drained = co_await Carrier->Drain();
        const bool ExchangeCompleted =
            Transport && Transport->ExchangeComplete();
        if (Carrier->IsRetired())
        {
            (void)Failure.TrySet(Lifecycle->Failure());
            Carrier.reset();
            Transport.reset();
            Wire.reset();
            Encrypted.reset();
            Session.reset();
            Response.reset();
            Retired.store(true, std::memory_order_release);
        }
        else if (!Drained && !(ExchangeCompleted &&
                 CarrierLifecycle::IsTeardownFailure(Drained.error())))
        {
            (void)Failure.TrySet(Drained.error());
        }
        if (!Drained && !(ExchangeCompleted &&
            CarrierLifecycle::IsTeardownFailure(Drained.error())))
            co_return std::unexpected(Drained.error());
        const auto First = Failure.Load();
        if (ExchangeCompleted && CarrierLifecycle::IsTeardownFailure(First))
            co_return std::expected<void, Prism::Fault::Failure>{};
        if (First.Failed()) co_return std::unexpected(First);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto Http2ClientDataWriter::Run(Request Value) -> Net::awaitable<Http2ClientResult>
    {
        const auto Session = Value.Session.lock();
        const auto Wire = Value.Wire.lock();
        if (!Session || !Wire)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ProtocolError});
        }
        std::size_t Offset = 0;
        bool EmptySubmitted = false;
        while (Offset < Value.Data.size() || !EmptySubmitted)
        {
            const auto Count = (std::min)(std::size_t{16U * 1024U}, Value.Data.size() - Offset);
            const auto Chunk = Value.Data.subspan(Offset, Count);
            auto Status = Session->SubmitData(Value.StreamId, Chunk, false);
            while (Status == H2::SubmitDataStatus::Blocked)
            {
                const auto Flushed = co_await FlushHttp2Frames(Session, Wire);
                if (!Flushed) co_return std::unexpected(Flushed.error());
                const auto Writable = co_await Session->AwaitWritable(Value.StreamId, Count);
                if (!Writable) co_return std::unexpected(Writable.error());
                Status = Session->SubmitData(Value.StreamId, Chunk, false);
            }
            if (Status != H2::SubmitDataStatus::Accepted)
            {
                const auto Code = Status == H2::SubmitDataStatus::Closed
                    ? Prism::Fault::Code::ConnectionAborted
                    : Prism::Fault::Code::InvalidArgument;
                co_return std::unexpected(Prism::Fault::Failure{Code});
            }
            Offset += Count;
            EmptySubmitted = true;
            const auto Flushed = co_await FlushHttp2Frames(Session, Wire);
            if (!Flushed) co_return std::unexpected(Flushed.error());
        }
        co_return Http2ClientResult{};
    }

    auto Http2ClientDataWriter::operator()(
        const std::int32_t StreamId,
        const std::span<const std::byte> Data) const -> Net::awaitable<Http2ClientResult>
    {
        return Run(Request{Session, Wire, StreamId, Data});
    }

    auto Http2ClientFinisher::operator()(const std::int32_t StreamId) const
        -> Net::awaitable<Http2ClientResult>
    {
        return Run(Session, Wire, StreamId);
    }

    auto Http2ClientFinisher::Run(
        const std::weak_ptr<H2::Session> &SessionReference,
        const std::weak_ptr<Http2WireWriter> &WireReference,
        const std::int32_t StreamId) -> Net::awaitable<Http2ClientResult>
    {
        const auto Session = SessionReference.lock();
        const auto Wire = WireReference.lock();
        if (!Session || !Wire)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ProtocolError});
        }
        const auto Status = Session->SubmitData(StreamId, {}, true);
        if (Status != H2::SubmitDataStatus::Accepted)
        {
            const auto Code = Status == H2::SubmitDataStatus::Closed
                ? Prism::Fault::Code::ConnectionAborted
                : Prism::Fault::Code::InvalidArgument;
            co_return std::unexpected(Prism::Fault::Failure{Code});
        }
        co_return co_await FlushHttp2Frames(Session, Wire);
    }

    auto HandleHttp2ClientHeaders(Http2ClientHeadersEvent Input) -> void
    {
        if (Input.StreamId != Input.Transport->StreamId_)
        {
            return;
        }
        std::string_view Status;
        for (const auto &Header : Input.Headers)
        {
            if (Header.Name == ":status")
            {
                Status = Header.Value;
                break;
            }
        }
        if (Status == "200")
        {
            const auto Sent = Input.Response->try_send(
                boost::system::error_code{}, Http2ClientResult{});
            if (!Sent)
                Input.Lifecycle->RecordFailure(
                    Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        else
        {
            auto Code = Prism::Fault::Code::ProtocolError;
            if (Status == "407")
            {
                Code = Prism::Fault::Code::AuthFailed;
            }
            else if (Status == "400")
            {
                Code = Prism::Fault::Code::BadMessage;
            }
            const auto Sent = Input.Response->try_send(
                boost::system::error_code{},
                std::unexpected(Prism::Fault::Failure{Code}));
            if (!Sent)
                Input.Lifecycle->RecordFailure(
                    Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
    }

    auto Http2ClientHeadersObserver::operator()(
        const std::int32_t StreamId,
        const H2::HeaderList &Headers,
        const bool) const -> void
    {
        const auto TransportOwner = Transport.lock();
        const auto ResponseOwner = Response.lock();
        const auto LifecycleOwner = Lifecycle.lock();
        if (TransportOwner && ResponseOwner && LifecycleOwner)
        {
            HandleHttp2ClientHeaders(
                Http2ClientHeadersEvent{
                    TransportOwner, ResponseOwner, LifecycleOwner, StreamId, Headers});
        }
    }

    auto HandleHttp2ClientData(
        const std::shared_ptr<Http2Transport> &Transport,
        const std::int32_t StreamId,
        const std::span<const std::byte> Data) -> void
    {
        if (StreamId == Transport->StreamId_)
        {
            Transport->Push(Data);
        }
    }

    auto HandleHttp2ClientClose(
        const std::shared_ptr<Http2Transport> &Transport,
        const std::shared_ptr<CarrierLifecycle> &Lifecycle,
        const H2::StreamReceiveClosure &Closure) -> void
    {
        if (Closure.StreamId == Transport->StreamId_)
        {
            if (Closure.Kind == H2::StreamReceiveClosureKind::Reset)
            {
                auto Code = Prism::Fault::Code::ProtocolError;
                if (Closure.ErrorCode == H2::ErrorNoError)
                {
                    Code = Prism::Fault::Code::ConnectionReset;
                }
                const Prism::Fault::Failure Failure{Code};
                Lifecycle->RecordFailure(Failure);
                Transport->NotifyError(Failure);
            }
            else
            {
                Transport->NotifyEof();
            }
        }
    }

    auto CloseHttp2ClientCarrier(
        const std::shared_ptr<Prism::Transport::Encrypted> &Encrypted,
        const std::shared_ptr<Http2WireWriter> &Wire) -> Http2ClientResult
    {
        Prism::Fault::Failure Failure;
        if (Wire) Wire->Close();
        if (Encrypted)
        {
            const auto Canceled = Encrypted->Cancel();
            if (!Canceled) Failure = Canceled.error();
            const auto Closed = Encrypted->Close();
            if (Failure.Succeeded() && !Closed) Failure = Closed.error();
        }
        if (Failure.Failed()) return std::unexpected(Failure);
        return Http2ClientResult{};
    }

    auto MakeHttp2ClientState(
        const std::shared_ptr<Prism::Transport::Encrypted> &Encrypted)
        -> std::shared_ptr<Http2ClientState>
    {
        auto State = std::make_shared<Http2ClientState>(Encrypted->Executor());
        State->Encrypted = Encrypted;
        State->Session = std::make_shared<H2::Session>(Encrypted->Executor(), false);
        State->Wire = MakeHttp2Wire(Encrypted);
        State->Response = std::make_shared<Http2ResponseChannel>(Encrypted->Executor(), 1);
        State->Transport = std::make_shared<Http2Transport>(
            Http2Transport::Options{
                .Executor = Encrypted->Executor(),
                .Write = Http2ClientDataWriter{State->Session, State->Wire},
                .Finish = Http2ClientFinisher{State->Session, State->Wire},
                // carrier 的最终关闭由 CarrierOwner 统一提交；本层只封止 H2 stream，
                // 避免对同一 Encrypted/Wire 重复下发控制命令。
                .Close = Http2Transport::CloseCb{}});
        State->Session->OnHeaders = Http2ClientHeadersObserver{
            State->Transport, State->Response, State->Lifecycle};
        State->Session->OnData = [Transport = State->Transport](std::int32_t StreamId,
                                                                 std::span<const std::byte> Data)
        { HandleHttp2ClientData(Transport, StreamId, Data); };
        State->Session->OnStreamClose = [Transport = State->Transport,
                                        Lifecycle = State->Lifecycle](
            const H2::StreamReceiveClosure &Closure)
        { HandleHttp2ClientClose(Transport, Lifecycle, Closure); };
        State->Carrier = std::make_shared<CarrierOwner>(
            CarrierOwnerLayers{
                State->Transport, State->Wire, State->Encrypted, State->Lifecycle, {}});
        State->Lifecycle->Transport = State->Transport;
        return State;
    }

    auto RunHttp2ClientDriver(std::shared_ptr<Http2ClientState> State)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        std::array<std::byte, 16384> Buffer{};
        Prism::Fault::Failure Failure;
        while (true)
        {
            const auto Part = co_await State->Encrypted->ReadSome(Buffer);
            const auto Step = co_await ProcessHttp2ReadCompletion(
                Http2ReadCompletion{std::span<const std::byte>(Buffer), Part},
                State->Session, State->Wire);
            if (Step.Terminal)
            {
                const bool LocalClose =
                    State->Lifecycle &&
                    State->Lifecycle->IsLocalCloseCancellation(Step.Failure);
                const bool CleanTeardown = State->Transport &&
                    State->Transport->ExchangeComplete() &&
                    CarrierLifecycle::IsTeardownFailure(Step.Failure);
                Failure = (LocalClose || CleanTeardown)
                    ? Prism::Fault::Failure{} : Step.Failure;
                if (Step.ReadTerminal)
                {
                    State->Transport->NotifyReadTerminal(
                        (LocalClose || CleanTeardown)
                            ? Prism::Fault::Failure{Prism::Fault::Code::Eof} : Failure);
                    const auto Closed = State->Transport->CloseCarrierForReadTerminal();
                    if (Closed.Failed()) State->Lifecycle->RecordFailure(Closed);
                }
                break;
            }
        }
        if (State->Lifecycle && State->Lifecycle->IsLocalCloseCancellation(Failure))
            Failure = {};
        if (Failure.Failed())
        {
            State->Transport->NotifyError(Failure);
            const auto Sent = State->Response->try_send(
                boost::system::error_code{}, std::unexpected(Failure));
            if (!Sent) State->Lifecycle->RecordFailure(Failure);
        }
        else
        {
            State->Transport->NotifyEof();
            const auto Sent = State->Response->try_send(
                boost::system::error_code{},
                std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Eof}));
            if (!Sent)
                State->Lifecycle->RecordFailure(
                    Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        co_return Failure;
    }

    auto Http2ClientDriverCompletion::operator()(
        std::exception_ptr Exception,
        Prism::Fault::Failure Failure) const noexcept -> void
    {
        if (Exception)
            Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::move(Exception));
        if (State->Lifecycle)
        {
            State->Lifecycle->RecordFailure(Failure);
            State->Lifecycle->CompleteDriver();
        }
    }

    auto StartHttp2ClientDriver(std::shared_ptr<Http2ClientState> State)
        -> Prism::Fault::Failure
    {
        if (!State || !State->Lifecycle || !State->Encrypted)
        {
            return {Prism::Fault::Code::InvalidArgument};
        }
        State->Lifecycle->StartDriver();
        const auto Lifecycle = State->Lifecycle;
        try
        {
            Net::co_spawn(
                State->Encrypted->Executor(), RunHttp2ClientDriver(State),
                Http2ClientDriverCompletion{State});
        }
        catch (...)
        {
            const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
            Lifecycle->RecordFailure(Failure);
            Lifecycle->CompleteDriver();
            return Failure;
        }
        return {};
    }

    auto FlushHttp2ClientFrames(const std::shared_ptr<Http2ClientState> &State)
        -> Net::awaitable<Http2ClientResult>
    {
        co_return co_await FlushHttp2Frames(State->Session, State->Wire);
    }

    auto RetireHttp2ClientFactory(
        Prism::Contract::InboundAdmission &Admission,
        const std::shared_ptr<Http2ClientState> &State,
        Prism::Fault::Failure Cause)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        State->Lifecycle->RecordFailure(Cause);
        const auto Retired = co_await State->Drain();
        if (State->IsRetired())
        {
            Admission.Release();
            if (!Retired) co_return Retired.error();
            co_return Cause;
        }
        auto AdmissionCause = Cause;
        if (!Retired) AdmissionCause = Retired.error();
        else if (AdmissionCause.Succeeded())
            AdmissionCause = {Prism::Fault::Code::Blocked};
        const auto Inbound = co_await Admission.Retire(AdmissionCause);
        if (State->IsRetired())
        {
            const auto First = State->Failure.Load();
            if (First.Failed()) co_return First;
        }
        if (!Retired) co_return Retired.error();
        co_return Inbound;
    }

    /** @brief HTTP/2 客户端 TLS 建立的完整冷路径输入。 */
    [[nodiscard]] auto RunHttp2TlsHandshake(
        Prism::Transport::Encrypted::SharedStream Stream)
        -> Net::awaitable<boost::system::error_code>
    {
        boost::system::error_code ErrorCode;
        co_await Stream->async_handshake(Net::ssl::stream_base::client,
                                         Net::redirect_error(Net::use_awaitable, ErrorCode));
        co_return ErrorCode;
    }


    /** @brief 使用同一预预约 owner retire TLS setup/handshake failure 与 recovered raw。 */
    [[nodiscard]] auto RetireHttp2TlsFailure(
        Prism::Contract::InboundAdmission &Admission,
        Prism::Fault::Failure Cause,
        Prism::SharedTransmission Recovered)
        -> Net::awaitable<Http2TlsResult>
    {
        if (Recovered)
        {
            const auto Tracked = Admission.Track(Recovered);
            if (!Tracked && Cause.Succeeded())
            {
                Cause = Tracked.error();
            }
        }
        co_return std::unexpected(co_await Admission.Retire(Cause));
    }

    /**
     * @brief 在 I/O 前已准备 ticket 的前提下建立客户端 TLS/h2 stream。
     * @param Request 按值拥有上游、服务器名和字节池；TLS context 借用到握手返回。
     * @param Admission 与 Raw 同一连接的预预约 owner，失败时在本 helper 内完成真实 retire。
     * @return 唯一 expected stream 结果；失败保留首个 Code/Native，success 由调用方继续接管。
     */
    [[nodiscard]] auto ConnectHttp2Tls(
        Http2TlsClientRequest Request,
        Prism::Contract::InboundAdmission &Admission)
        -> Net::awaitable<Http2TlsResult>
    {
        if (!Request.Raw)
        {
            co_return co_await RetireHttp2TlsFailure(
                Admission,
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument},
                {});
        }
        const auto Tracked = Admission.Track(Request.Raw);
        if (!Tracked)
        {
            co_return co_await RetireHttp2TlsFailure(
                Admission, Tracked.error(), Request.Raw);
        }
        if (!Request.Bytes)
        {
            co_return co_await RetireHttp2TlsFailure(
                Admission,
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument},
                Request.Raw);
        }
        Prism::Transport::Connector Connector(std::move(Request.Raw));
        auto Stream = std::make_shared<Prism::Transport::Encrypted::StreamType>(
            std::move(Connector), Request.SslContext);
        if (!Request.ServerName.empty())
        {
            const auto &Name = Request.ServerName;
            if (SSL_set_tlsext_host_name(Stream->native_handle(), Name.c_str()) != 1)
            {
                auto Recovered = Stream->next_layer().Release();
                co_return co_await RetireHttp2TlsFailure(
                    Admission,
                    Prism::Fault::Failure{Prism::Fault::Code::TlsHsfail},
                    std::move(Recovered));
            }
        }
        constexpr unsigned char Alpn[] = {2, 'h', '2'};
        if (SSL_set_alpn_protos(Stream->native_handle(), Alpn, sizeof(Alpn)) != 0)
        {
            auto Recovered = Stream->next_layer().Release();
            co_return co_await RetireHttp2TlsFailure(
                Admission,
                Prism::Fault::Failure{Prism::Fault::Code::TlsHsfail},
                std::move(Recovered));
        }
        Net::steady_timer Deadline(Stream->get_executor());
        Deadline.expires_after(std::chrono::seconds(30));
        auto DeadlineWait = Deadline.async_wait(Net::use_awaitable);
        const auto Result = co_await (RunHttp2TlsHandshake(Stream) || std::move(DeadlineWait));
        if (Result.index() == 1)
        {
            auto Recovered = Stream->next_layer().Release();
            co_return co_await RetireHttp2TlsFailure(
                Admission,
                Prism::Fault::Failure{
                    Prism::Fault::Code::Timeout,
                    std::make_error_code(std::errc::timed_out)},
                std::move(Recovered));
        }
        const auto HandshakeError = std::get<0>(Result);
        if (HandshakeError)
        {
            auto Recovered = Stream->next_layer().Release();
            co_return co_await RetireHttp2TlsFailure(
                Admission,
                Prism::Fault::FromNative(
                    static_cast<std::error_code>(HandshakeError)),
                std::move(Recovered));
        }
        co_return Stream;
    }
    [[nodiscard]] auto ConnectHttp2Core(
        Http2ConnectParameters Parameters,
        Prism::Contract::InboundAdmission &Admission)
        -> Net::awaitable<std::expected<SharedTransmission, Prism::Fault::Failure>>
    {
        auto StreamResult = co_await ConnectHttp2Tls(
            Http2TlsClientRequest{std::move(Parameters.Upstream), Parameters.SslContext,
                                  std::string(Parameters.ServerName), Parameters.Bytes},
            Admission);
        if (!StreamResult)
        {
            co_return std::unexpected(StreamResult.error());
        }
        auto Stream = std::move(*StreamResult);
        auto State = MakeHttp2ClientState(
            std::make_shared<Prism::Transport::Encrypted>(
                std::move(Stream), std::move(Parameters.Bytes)));
        auto Accepted =
            std::make_shared<AcceptedClientTransport<Http2ClientState>>(State);
        auto Tracked = Admission.Track(
            std::static_pointer_cast<Prism::Transmission>(Accepted));
        if (!Tracked)
            co_return std::unexpected(co_await RetireHttp2ClientFactory(
                Admission, State, Tracked.error()));
        const auto DriverStart = StartHttp2ClientDriver(State);
        if (DriverStart.Failed())
        {
            co_return std::unexpected(co_await RetireHttp2ClientFactory(
                Admission, State, DriverStart));
        }
        State->Session->SendSettings();
        const auto Authority = std::string(Parameters.Target) + ":" + std::to_string(Parameters.Port);
        const auto StreamId = State->Session->OpenStream(
            {{":method", "CONNECT"}, {":authority", Authority},
             {"proxy-authorization", BasicAuth(Parameters.Config.username, Parameters.Config.password)}},
            false);
        if (!StreamId)
        {
            co_return std::unexpected(co_await RetireHttp2ClientFactory(
                Admission, State, StreamId.error()));
        }
        State->Transport->BindStream(*StreamId);
        const auto Flushed = co_await FlushHttp2ClientFrames(State);
        if (!Flushed)
        {
            co_return std::unexpected(co_await RetireHttp2ClientFactory(
                Admission, State, Flushed.error()));
        }
        Net::steady_timer ResponseDeadline(State->Encrypted->Executor());
        ResponseDeadline.expires_after(std::chrono::seconds(30));
        boost::system::error_code ResponseError;
        auto Receive = State->Response->async_receive(
            Net::redirect_error(Net::use_awaitable, ResponseError));
        auto DeadlineWait = ResponseDeadline.async_wait(Net::use_awaitable);
        const auto ResponseResult = co_await (std::move(Receive) || std::move(DeadlineWait));
        if (ResponseResult.index() == 1)
        {
            co_return std::unexpected(co_await RetireHttp2ClientFactory(
                Admission, State,
                Prism::Fault::Failure{Prism::Fault::Code::Timeout,
                                        std::make_error_code(std::errc::timed_out)}));
        }
        const auto Response = std::get<0>(ResponseResult);
        if (ResponseError)
        {
            co_return std::unexpected(co_await RetireHttp2ClientFactory(
                Admission, State,
                Prism::Fault::FromNative(static_cast<std::error_code>(ResponseError))));
        }
        if (!Response)
        {
            co_return std::unexpected(co_await RetireHttp2ClientFactory(
                Admission, State, Response.error()));
        }
        Admission.Release();
        co_return SharedTransmission(std::move(Accepted));
    }
} // namespace Prism::Trusttunnel::Detail
