/**
 * @file SplitServerAccept.cpp
 * @brief SplitServerAccept.hpp 非模板 owner 实现。
 */
#include <Prism/Protocols/Xhttp/Detail/SplitServerAccept.hpp>

namespace Prism::Xhttp::Detail
{
    auto InitializeSplitServerState(SplitServerInitialization Request) -> void{
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

    auto CompleteSplitServerDriver(
        const std::shared_ptr<SplitServerState> &State,
        std::exception_ptr Exception) -> void{
        if (Exception)
        {
            State->DriverFailure = FailureFromException(std::move(Exception));
            if (State->Transport)
                State->Transport->NotifyError(Prism::Fault::ToNative(State->DriverFailure));
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

    auto StartSplitServerDriver(const std::shared_ptr<SplitServerState> &State) -> void{
        Net::co_spawn(
            State->Encrypted->Executor(), RunSplitServerDriver(State),
            [State](std::exception_ptr Exception)
            {
                CompleteSplitServerDriver(State, std::move(Exception));
            });
        State->DriverStarted = true;
    }

        [[nodiscard]] auto XhttpSplitAccept::Run(Prism::Contract::InboundAdmission &Admission)
            -> Net::awaitable<ServerAcceptResult>{
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

    XhttpSplitAccept::XhttpSplitAccept(XhttpSplitAcceptRequest Request)
            : Raw_(std::move(Request.Raw)), SslCtx_(Request.SslContext),
              Cfg_(std::move(Request.Configuration)), Bytes_(std::move(Request.Bytes)){
        }

    [[nodiscard]] auto XhttpSplitAccept::RunCore(
            Prism::Contract::InboundAdmission &Admission)
            -> Net::awaitable<ServerAcceptResult>{
            if (!Raw_ || !Bytes_)
            {
                co_return std::unexpected(co_await RetireFactoryFailure(Admission,
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument}));
            }
            if (!Cfg_.IsSplit() || !Cfg_.Enabled())
                co_return std::unexpected(co_await RetireFactoryFailure(Admission,
                    Prism::Fault::Failure{Prism::Fault::Code::NotSupported}));

            Retirement_ = FactoryRetirement<SplitServerState>::Prepare(Raw_->Executor());
            auto Handshake = co_await Prism::Transport::Encrypted::SslHandshake(
                {std::move(Raw_), SslCtx_,
                 std::chrono::steady_clock::now() + Prism::Transport::Encrypted::DefaultHandshakeTimeout,
                 std::move(Bytes_)});
            if (Handshake.Failure.Code != Prism::Fault::Code::Success || !Handshake.Stream)
            {
                auto Failure = Handshake.Failure;
                if (Failure.Succeeded()) Failure = {Prism::Fault::Code::TlsHsfail};
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
            State->Encrypted = std::make_shared<Prism::Transport::Encrypted>(
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
                    Prism::Fault::Failure{Prism::Fault::Code::Timeout}));
            }
            if (ReadyError)
                co_return std::unexpected(co_await RetireFactoryFailure(Admission,
                    Prism::Fault::FromNative(static_cast<std::error_code>(ReadyError))));
            const auto [Failure, ResponseAccepted] = std::get<0>(Result);
            if (!ResponseAccepted || !State->Transport)
            {
                auto Rejection = Failure;
                if (Rejection.Succeeded())
                    Rejection = {Prism::Fault::Code::ProtocolError};
                co_return std::unexpected(co_await RetireFactoryFailure(Admission, Rejection));
            }
            auto AcceptedTransportOwner = std::make_shared<AcceptedTransport<SplitServerState>>(
                Retirement_, State->Transport);
            Admission.Release();
            co_return ServerAcceptance{
                Prism::SharedTransmission{std::move(AcceptedTransportOwner)},
                std::move(Handshake.Negotiated)};
        }

    [[nodiscard]] auto XhttpSplitAccept::RetireFactoryFailure(
            Prism::Contract::InboundAdmission &Admission,
            Prism::Fault::Failure Cause)
            -> Net::awaitable<Prism::Fault::Failure>{
            Cause = co_await Admission.Retire(Cause);
            if (Retirement_) Cause = co_await Retirement_->Retire(Cause);
            co_return Cause;
        }

} // namespace Prism::Xhttp::Detail
