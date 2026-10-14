/**
 * @file SplitServerAccept.hpp
 * @brief XHTTP Split 服务端 TLS 与请求流接纳工厂。
 */
#pragma once

#include <Preview/Contract/Ingress/DataPlane.hpp>
#include <Preview/Protocols/Xhttp/Detail/SplitServer.hpp>
#include <Preview/Protocols/Xhttp/Detail/SplitServerWireWriter.hpp>
#include <Preview/Protocols/Xhttp/Detail/AcceptedTransport.hpp>
#include <Preview/Protocols/Xhttp/Detail/FactoryRetirement.hpp>
#include <Preview/Transport/Encrypted.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <chrono>
#include <exception>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>

namespace Preview::Xhttp::Detail
{

    struct SplitServerInitialization final
    {
        std::shared_ptr<SplitServerState> State;
        Config Configuration;
    };

    inline auto InitializeSplitServerState(SplitServerInitialization Request) -> void
    {
        const auto State = std::move(Request.State);
        State->Cfg = std::move(Request.Configuration);
        State->Session = std::make_shared<h2::Session>(State->Encrypted->Executor(), true);
        State->Ready = std::make_shared<SplitReadyChannel>(State->Encrypted->Executor(), 1);
        State->DriverDone = std::make_shared<DriverCompletionChannel>(
            State->Encrypted->Executor(), 1);
        State->Wire = std::make_shared<WireWriter>(
            State->Encrypted->Executor(), SplitServerWireWriter{State->Encrypted});
        const auto WeakState = std::weak_ptr<SplitServerState>(State);
        State->Session->OnHeaders = [WeakState](
            std::int32_t StreamId, const h2::HeaderList &Headers, bool EndStream)
        {
            if (const auto Owner = WeakState.lock())
                HandleSplitServerHeaders(SplitServerHeaderInput{Owner, StreamId, Headers, EndStream});
        };
        State->Session->OnData = [WeakState](std::int32_t StreamId, std::span<const std::byte> Data)
        {
            if (const auto Owner = WeakState.lock())
                HandleSplitServerData(Owner, StreamId, Data);
        };
        State->Session->OnStreamClose = [WeakState](const h2::StreamReceiveClosure &Closure)
        {
            if (const auto Owner = WeakState.lock()) HandleSplitServerClose(Owner, Closure);
        };
        State->Session->SendSettings();
    }

    inline auto CompleteSplitServerDriver(
        const std::shared_ptr<SplitServerState> &State,
        std::exception_ptr Exception) -> void
    {
        if (Exception)
        {
            State->DriverFailure = FailureFromException(std::move(Exception));
            if (State->Transport)
                State->Transport->NotifyError(Preview::Fault::ToNative(State->DriverFailure));
            if (!State->ReadySignaled)
                SignalSplitReady(State, false, State->DriverFailure);
            const auto CloseFailure =
                CloseSplitServerOwner(std::weak_ptr<SplitServerState>(State));
            if (State->DriverFailure.Succeeded() && CloseFailure.Failed())
                State->DriverFailure = CloseFailure;
        }
        const auto Failure = State->DriverFailure;
        if (Failure.Failed() && !State->ReadySignaled)
            SignalSplitReady(State, false, Failure);
        (void)State->DriverDone->try_send(boost::system::error_code{}, Failure);
    }

    inline auto StartSplitServerDriver(const std::shared_ptr<SplitServerState> &State) -> void
    {
        Net::co_spawn(
            State->Encrypted->Executor(), RunSplitServerDriver(State),
            [State](std::exception_ptr Exception)
            {
                CompleteSplitServerDriver(State, std::move(Exception));
            });
        State->DriverStarted = true;
    }

    /** @brief XHTTP Split 服务端接受状态的完整 owning 输入。 */
    struct XhttpSplitAcceptRequest final
    {
        SharedTransmission Raw;
        Net::ssl::context &SslContext;
        Config Configuration;
        std::shared_ptr<Preview::Memory::BytePool> Bytes;
    };

    /** @brief XHTTP Split 服务端 TLS、h2 和上传/下载流匹配编排。 */
    class XhttpSplitAccept final : public std::enable_shared_from_this<XhttpSplitAccept>
    {
    public:
        explicit XhttpSplitAccept(XhttpSplitAcceptRequest Request)
            : Raw_(std::move(Request.Raw)), SslCtx_(Request.SslContext),
              Cfg_(std::move(Request.Configuration)), Bytes_(std::move(Request.Bytes))
        {
        }

        [[nodiscard]] auto Run(Preview::Contract::InboundAdmission &Admission)
            -> Net::awaitable<ServerAcceptResult>
        {
            std::optional<ServerAcceptResult> Outcome;
            std::exception_ptr Fatal;
            try
            {
                Outcome = co_await RunCore(Admission);
            }
            catch (...)
            {
                Fatal = std::current_exception();
            }
            if (Fatal)
            {
                const auto Cause = FailureFromException(std::move(Fatal));
                co_return std::unexpected(
                    co_await RetireFactoryFailure(Admission, Cause));
            }
            co_return std::move(*Outcome);
        }

    private:
        [[nodiscard]] auto RunCore(
            Preview::Contract::InboundAdmission &Admission)
            -> Net::awaitable<ServerAcceptResult>
        {
            if (!Raw_ || !Bytes_)
            {
                co_return std::unexpected(co_await RetireFactoryFailure(Admission,
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument}));
            }
            if (!Cfg_.IsSplit() || !Cfg_.Enabled())
                co_return std::unexpected(co_await RetireFactoryFailure(Admission,
                    Preview::Fault::Failure{Preview::Fault::Code::NotSupported}));

            Retirement_ = FactoryRetirement<SplitServerState>::Prepare(Raw_->Executor());
            auto Handshake = co_await Preview::Transport::Encrypted::SslHandshake(
                {std::move(Raw_), SslCtx_,
                 std::chrono::steady_clock::now() + Preview::Transport::Encrypted::DefaultHandshakeTimeout,
                 std::move(Bytes_)});
            if (Handshake.Failure.Code != Preview::Fault::Code::Success || !Handshake.Stream)
            {
                auto Failure = Handshake.Failure;
                if (Failure.Succeeded()) Failure = {Preview::Fault::Code::TlsHsfail};
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
                        const auto Retired = co_await Retirement_->Retire(Rejected.error());
                        co_return std::unexpected(Retired);
                    }
                }
                if (Handshake.Recovered)
                {
                    const auto Tracked = Admission.Track(Handshake.Recovered);
                    if (!Tracked && Failure.Succeeded()) Failure = Tracked.error();
                }
                co_return std::unexpected(co_await RetireFactoryFailure(Admission, Failure));
            }

            auto State = std::make_shared<SplitServerState>();
            State->Encrypted = std::make_shared<Preview::Transport::Encrypted>(
                std::move(Handshake.Stream), std::move(Handshake.Bytes));
            Retirement_->Attach(State);
            Admission.Release();
            InitializeSplitServerState(SplitServerInitialization{State, Cfg_});
            StartSplitServerDriver(State);

            const auto Flush = co_await FlushSplitSession(State);
            if (!Flush)
                co_return std::unexpected(
                    co_await RetireFactoryFailure(Admission, Flush.error()));

            boost::system::error_code ReadyError;
            Net::steady_timer Deadline(State->Encrypted->Executor());
            Deadline.expires_after(std::chrono::seconds(30));
            auto Wait = State->Ready->async_receive(
                Net::redirect_error(Net::use_awaitable, ReadyError));
            const auto Result = co_await (
                std::move(Wait) || Deadline.async_wait(Net::use_awaitable));
            if (Result.index() == 1)
            {
                co_return std::unexpected(co_await RetireFactoryFailure(Admission,
                    Preview::Fault::Failure{Preview::Fault::Code::Timeout}));
            }
            if (ReadyError)
                co_return std::unexpected(co_await RetireFactoryFailure(Admission,
                    Preview::Fault::FromNative(static_cast<std::error_code>(ReadyError))));
            const auto [Failure, ResponseAccepted] = std::get<0>(Result);
            if (!ResponseAccepted || !State->Transport)
            {
                auto Rejection = Failure;
                if (Rejection.Succeeded())
                    Rejection = {Preview::Fault::Code::ProtocolError};
                co_return std::unexpected(co_await RetireFactoryFailure(Admission, Rejection));
            }
            auto AcceptedTransportOwner = std::make_shared<AcceptedTransport<SplitServerState>>(
                Retirement_, State->Transport);
            Admission.Release();
            co_return ServerAcceptance{
                Preview::SharedTransmission{std::move(AcceptedTransportOwner)},
                std::move(Handshake.Negotiated)};
        }

        [[nodiscard]] auto RetireFactoryFailure(
            Preview::Contract::InboundAdmission &Admission,
            Preview::Fault::Failure Cause)
            -> Net::awaitable<Preview::Fault::Failure>
        {
            Cause = co_await Admission.Retire(Cause);
            if (Retirement_) Cause = co_await Retirement_->Retire(Cause);
            co_return Cause;
        }

    private:
        SharedTransmission Raw_;
        Net::ssl::context &SslCtx_;
        Config Cfg_;
        std::shared_ptr<Preview::Memory::BytePool> Bytes_;
        std::shared_ptr<FactoryRetirement<SplitServerState>> Retirement_;
    };

} // namespace Preview::Xhttp::Detail
