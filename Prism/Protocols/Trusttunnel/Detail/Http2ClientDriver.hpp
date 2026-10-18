/**
 * @file Http2ClientDriver.hpp
 * @brief TrustTunnel HTTP/2 client 的 driver、accepted state 与真实退休 owner。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Trusttunnel/Codec.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/AcceptedClientTransport.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/CarrierOwner.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2Transport.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2WireWriter.hpp>
#include <Prism/Protocols/Trusttunnel/Http2ClientTypes.hpp>
#include <Prism/Protocols/Trusttunnel/Types.hpp>
#include <Prism/Transport/Encrypted.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <tuple>
#include <utility>

namespace Prism::Trusttunnel::Detail
{
    namespace Net = boost::asio;
    namespace H2 = Prism::Http2;
    using Net::experimental::awaitable_operators::operator||;
    struct Http2TlsClientRequest final
    {
        SharedTransmission Raw;
        Net::ssl::context &SslContext;
        std::string ServerName;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
    };
    using Http2ResponseChannel =
        Net::experimental::channel<void(boost::system::error_code, Http2ClientResult)>;

    struct Http2ClientState final
    {
        explicit Http2ClientState(Net::any_io_executor ExecutorValue)
            : Domain(std::move(ExecutorValue)),
              Lifecycle(std::make_shared<CarrierLifecycle>(Domain))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor { return Domain; }

        [[nodiscard]] auto Close() -> Prism::Transmission::ControlResult
        {
            if (!Carrier || IsRetired()) return {};
            return Carrier->Close();
        }

        [[nodiscard]] auto Cancel() -> Prism::Transmission::ControlResult
        {
            if (!Carrier || IsRetired()) return {};
            return Carrier->Cancel();
        }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (!Carrier)
            {
                const auto First = Failure.Load();
                if (First.Failed()) co_return std::unexpected(First);
                co_return std::expected<void, Prism::Fault::Failure>{};
            }
            const auto Drained = co_await Carrier->Drain();
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
            else if (!Drained)
            {
                (void)Failure.TrySet(Drained.error());
            }
            if (!Drained) co_return std::unexpected(Drained.error());
            const auto First = Failure.Load();
            if (First.Failed()) co_return std::unexpected(First);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool
        {
            return Retired.load(std::memory_order_acquire);
        }

        Net::any_io_executor Domain;
        std::shared_ptr<Prism::Transport::Encrypted> Encrypted;
        std::shared_ptr<H2::Session> Session;
        std::shared_ptr<Http2WireWriter> Wire;
        std::shared_ptr<Http2Transport> Transport;
        std::shared_ptr<Http2ResponseChannel> Response;
        std::shared_ptr<CarrierLifecycle> Lifecycle;
        std::shared_ptr<CarrierOwner> Carrier;
        std::atomic<bool> Retired{false};
        Prism::Fault::FailureState Failure;
    };

    struct Http2ClientDataWriter final
    {
        std::weak_ptr<H2::Session> Session;
        std::weak_ptr<Http2WireWriter> Wire;

        struct Request final
        {
            std::weak_ptr<H2::Session> Session;
            std::weak_ptr<Http2WireWriter> Wire;
            std::int32_t StreamId{0};
            std::span<const std::byte> Data;
        };

        [[nodiscard]] static auto Run(Request Value) -> Net::awaitable<Http2ClientResult>
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

        [[nodiscard]] auto operator()(const std::int32_t StreamId,
                                      const std::span<const std::byte> Data) const
            -> Net::awaitable<Http2ClientResult>
        {
            return Run(Request{Session, Wire, StreamId, Data});
        }
    };

    struct Http2ClientFinisher final
    {
        std::weak_ptr<H2::Session> Session;
        std::weak_ptr<Http2WireWriter> Wire;

        [[nodiscard]] auto operator()(const std::int32_t StreamId) const
            -> Net::awaitable<Http2ClientResult>
        {
            return Run(Session, Wire, StreamId);
        }

        [[nodiscard]] static auto Run(const std::weak_ptr<H2::Session> &SessionReference,
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
    };

    struct Http2ClientHeadersEvent final
    {
        std::shared_ptr<Http2Transport> Transport;
        std::shared_ptr<Http2ResponseChannel> Response;
        std::shared_ptr<CarrierLifecycle> Lifecycle;
        std::int32_t StreamId{0};
        const H2::HeaderList &Headers;
    };

    inline auto HandleHttp2ClientHeaders(Http2ClientHeadersEvent Input) -> void
    {
        if (Input.StreamId != Input.Transport->StreamId_)
        {
            return;
        }
        bool Accepted = false;
        for (const auto &Header : Input.Headers)
        {
            if (Header.Name == ":status" && Header.Value == "200")
            {
                Accepted = true;
            }
        }
        if (Accepted)
        {
            const auto Sent = Input.Response->try_send(
                boost::system::error_code{}, Http2ClientResult{});
            if (!Sent)
                Input.Lifecycle->RecordFailure(
                    Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        else
        {
            const auto Sent = Input.Response->try_send(
                boost::system::error_code{},
                std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::AuthFailed}));
            if (!Sent)
                Input.Lifecycle->RecordFailure(
                    Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
    }

    struct Http2ClientHeadersObserver final
    {
        std::weak_ptr<Http2Transport> Transport;
        std::weak_ptr<Http2ResponseChannel> Response;
        std::weak_ptr<CarrierLifecycle> Lifecycle;

        auto operator()(
            const std::int32_t StreamId, const H2::HeaderList &Headers, const bool) const -> void
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
    };

    inline auto HandleHttp2ClientData(
        const std::shared_ptr<Http2Transport> &Transport,
        const std::int32_t StreamId,
        const std::span<const std::byte> Data) -> void
    {
        if (StreamId == Transport->StreamId_)
        {
            Transport->Push(Data);
        }
    }

    inline auto HandleHttp2ClientClose(
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

    [[nodiscard]] inline auto CloseHttp2ClientCarrier(
        const std::shared_ptr<Prism::Transport::Encrypted> &Encrypted,
        const std::shared_ptr<Http2WireWriter> &Wire)
        -> Http2ClientResult
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

    [[nodiscard]] inline auto MakeHttp2ClientState(
        const std::shared_ptr<Prism::Transport::Encrypted> &Encrypted)
        -> std::shared_ptr<Http2ClientState>
    {
        auto State = std::make_shared<Http2ClientState>(Encrypted->Executor());
        State->Encrypted = Encrypted;
        State->Session = std::make_shared<H2::Session>(Encrypted->Executor(), false);
        State->Wire = MakeHttp2Wire(Encrypted);
        State->Response = std::make_shared<Http2ResponseChannel>(Encrypted->Executor(), 1);
        const auto EncryptedOwner = State->Encrypted;
        const auto WireOwner = State->Wire;
        State->Transport = std::make_shared<Http2Transport>(
            Http2Transport::Options{
                .Executor = Encrypted->Executor(),
                .Write = Http2ClientDataWriter{State->Session, State->Wire},
                .Finish = Http2ClientFinisher{State->Session, State->Wire},
                .Close = [EncryptedOwner, WireOwner]
                { return CloseHttp2ClientCarrier(EncryptedOwner, WireOwner); }});
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
        return State;
    }

    [[nodiscard]] inline auto RunHttp2ClientDriver(
        std::shared_ptr<Http2ClientState> State) -> Net::awaitable<Prism::Fault::Failure>
    {
        std::array<std::byte, 16384> Buffer{};
        Prism::Fault::Failure Failure;
        while (true)
        {
            const auto Part = co_await State->Encrypted->ReadSome(Buffer);
            const auto Read = Part.Bytes;
            if (Part.Failure.Failed())
            {
                if (Part.Failure.Code != Prism::Fault::Code::Eof &&
                    Part.Failure.Code != Prism::Fault::Code::Canceled)
                    Failure = Part.Failure;
                break;
            }
            if (Read == 0) break;
            if (Read > Buffer.size())
            {
                Failure = Prism::Fault::Failure{Prism::Fault::Code::IoError};
                break;
            }
            std::error_code FeedError;
            if (!State->Session->Feed(
                    std::span<const std::byte>(Buffer.data(), Read), FeedError) &&
                FeedError != make_error_code(Prism::Error::NeedMore))
            {
                if (FeedError)
                {
                    Failure = Prism::Fault::FromNative(FeedError);
                }
                else
                {
                    Failure = {Prism::Fault::Code::ProtocolError};
                }
                break;
            }
            const auto Flushed = co_await FlushHttp2Frames(State->Session, State->Wire);
            if (!Flushed)
            {
                Failure = Flushed.error();
                break;
            }
        }
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

    struct Http2ClientDriverCompletion final
    {
        std::shared_ptr<Http2ClientState> State;

        auto operator()(
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
    };

    inline auto StartHttp2ClientDriver(std::shared_ptr<Http2ClientState> State)
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

    [[nodiscard]] inline auto FlushHttp2ClientFrames(const std::shared_ptr<Http2ClientState> &State)
        -> Net::awaitable<Http2ClientResult>
    {
        co_return co_await FlushHttp2Frames(State->Session, State->Wire);
    }

    [[nodiscard]] inline auto RetireHttp2ClientFactory(
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


} // namespace Prism::Trusttunnel::Detail
