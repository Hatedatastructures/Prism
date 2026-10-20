/**
 * @file GrpcEndpoint.cpp
 * @brief Gun gRPC endpoint metadata 与 stream accept 的编译单元。
 */
#include <Prism/Protocols/Gun/Grpc.hpp>
#include <Prism/Protocols/Gun/Gun.hpp>

#include <Prism/Protocols/Gun/Detail/GrpcStreamFactory.hpp>
#include <Prism/Protocols/Gun/Detail/GrpcStreamActivity.hpp>
#include <Prism/Protocols/Gun/Detail/GrpcStreamDriver.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <exception>
#include <memory>
#include <new>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Gun::Grpc
{
    auto MakeRequestHeaders(const std::string_view Path, const std::string_view Authority)
        -> H2::HeaderList
    {
        return {{":method", "POST"}, {":scheme", "http"}, {":path", std::string(Path)},
            {":authority", std::string(Authority)}, {"content-type", "application/grpc"},
            {"te", "trailers"}};
    }

    auto ParseRequestHeaders(const H2::HeaderList &Headers) -> std::optional<RequestHeaders>
    {
        RequestHeaders Result;
        bool MethodOk = false;
        bool SchemeOk = false;
        for (const auto &Header : Headers)
        {
            if (Header.Name == ":method")
            {
                MethodOk = Header.Value == "POST";
            }
            else if (Header.Name == ":scheme")
            {
                SchemeOk = Header.Value == "http" || Header.Value == "https";
            }
            else if (Header.Name == ":path")
            {
                Result.Path = Header.Value;
            }
            else if (Header.Name == ":authority")
            {
                Result.Authority = Header.Value;
            }
            else if (Header.Name == "content-type")
            {
                Result.ContentType = Header.Value;
            }
            else if (Header.Name == "te")
            {
                Result.Te = Header.Value;
            }
        }
        if (!MethodOk || !SchemeOk || Result.Path.empty() || Result.Authority.empty() ||
            !std::string_view(Result.ContentType).starts_with("application/grpc") ||
            (!Result.Te.empty() && Result.Te != "trailers"))
        {
            return std::nullopt;
        }
        return Result;
    }

    auto MakeResponseHeaders() -> H2::HeaderList
    {
        return {{":status", "200"}, {"content-type", "application/grpc"},
            {"grpc-encoding", "identity"}, {"grpc-accept-encoding", "identity"}};
    }

    auto MakeResponseTrailers(const std::uint32_t Status) -> H2::HeaderList
    {
        return {{"grpc-status", std::to_string(Status)}, {"grpc-message", {}}};
    }

    auto StreamTransport::Accept(Prism::SharedTransmission Lower, Config ConfigValue)
        -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
    {
        co_return co_await Detail::StreamFactory::Accept(std::move(Lower), std::move(ConfigValue));
    }
}

namespace Prism::Gun::Grpc::Detail
{
    auto ProcessGrpcReadCompletion(
        Prism::Http2::Session &Session,
        const GrpcReadCompletion &Completion) -> GrpcReadStep
    {
        const auto &Read = Completion.Result;
        if (Read.Bytes > Completion.Buffer.size())
        {
            return {true, Prism::Fault::Failure{Prism::Fault::Code::IoError}};
        }

        Prism::Fault::Failure ProcessingFailure;
        if (Read.Bytes != 0U)
        {
            std::error_code Error;
            if (!Session.Feed(Completion.Buffer.first(Read.Bytes), Error) || Error)
            {
                ProcessingFailure = Error
                    ? Prism::Fault::FromNative(Error)
                    : Prism::Fault::Failure{Prism::Fault::Code::ProtocolError};
            }
        }
        if (ProcessingFailure.Failed())
        {
            return {true, ProcessingFailure};
        }
        if (Read.Failure.Failed())
        {
            return {true, Read.Failure, true};
        }
        if (Read.Bytes == 0U)
        {
            return {true, Prism::Fault::Failure{Prism::Fault::Code::Eof}};
        }
        return {};
    }

    GrpcStreamActivity::State::State(
        boost::asio::any_io_executor Executor,
        GrpcStreamActivityLayers Layers)
        : Storage(Prism::Executor::ContextOwner::Storage(Executor)),
          Reclaimer(std::make_shared<Prism::Executor::ExecutorReclaimer>(
              boost::asio::make_strand(std::move(Executor)))),
          Drivers(Reclaimer), Executor(Reclaimer->Executor()),
          Front(std::move(Layers.Front)), Child(std::move(Layers.Child)),
          Receipt(std::move(Layers.Receipt))
    {
    }

    GrpcStreamActivity::GrpcStreamActivity(
        boost::asio::any_io_executor Executor,
        GrpcStreamActivityLayers Layers)
        : State_(std::make_shared<State>(std::move(Executor), std::move(Layers)))
    {
    }

    auto GrpcStreamActivity::StartDriver() noexcept -> bool
    {
        return State_->Drivers.Enter();
    }

    auto GrpcStreamActivity::RecordFailure(Prism::Fault::Failure Failure) noexcept -> void
    {
        if (Failure.Failed()) (void)State_->Failure.TrySet(Failure);
    }

    auto GrpcStreamActivity::CompleteDriver(Prism::Fault::Failure Failure) noexcept -> void
    {
        if (Failure.Failed()) (void)State_->Failure.TrySet(Failure);
        State_->Drivers.Leave();
    }

    auto GrpcStreamActivity::Seal() noexcept -> void
    {
        if (State_->Sealed.exchange(true, std::memory_order_acq_rel)) return;
        State_->Drivers.Seal();
        State_->Front->Seal();
        State_->Child->Seal();
    }

    auto GrpcStreamActivity::Drain()
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Result = co_await DrainState(State_);
        if (IsRetired())
        {
            State_->Storage->Collect();
        }
        else
        {
            RequestRetirement();
        }
        co_return Result;
    }

    auto GrpcStreamActivity::RequestRetirement() -> void
    {
        if (IsRetired() || State_->RetryScheduled.exchange(true, std::memory_order_acq_rel))
            return;
        const auto Self = shared_from_this();
        State_->Storage->Retain(Self);
        const auto Posted = State_->Reclaimer->Post(RetryCommand{Self});
        if (!Posted)
        {
            State_->RetryScheduled.store(false, std::memory_order_release);
            RecordFailure(Posted.error());
            State_->Storage->Retain(Self);
        }
    }

    auto GrpcStreamActivity::RetryCompletion::operator()(
        std::exception_ptr Exception,
        std::expected<void, Prism::Fault::Failure> Result) const noexcept -> void
    {
        Owner->State_->RetryScheduled.store(false, std::memory_order_release);
        if (Exception)
        {
            Owner->RecordFailure(
                Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::move(Exception)));
            Owner->State_->Storage->Retain(Owner);
        }
        else if (!Result)
        {
            Owner->State_->Storage->Retain(Owner);
        }
        else
        {
            Owner->State_->Storage->Collect();
        }
    }

    auto GrpcStreamActivity::RetryOnExecutor()
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Result = co_await Drain();
        if (IsRetired()) co_return std::expected<void, Prism::Fault::Failure>{};
        if (!Result) co_return std::unexpected(Result.error());
        co_return std::unexpected(
            Prism::Fault::Failure{Prism::Fault::Code::Blocked});
    }

    auto GrpcStreamActivity::StartRetry() noexcept -> void
    {
        if (IsRetired())
        {
            State_->RetryScheduled.store(false, std::memory_order_release);
            return;
        }
        const auto Self = shared_from_this();
        try
        {
            boost::asio::co_spawn(
                State_->Reclaimer->Executor(), RetryOnExecutor(), RetryCompletion{Self});
        }
        catch (...)
        {
            State_->RetryScheduled.store(false, std::memory_order_release);
            RecordFailure(
                Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception()));
            State_->Storage->Retain(Self);
        }
    }

    auto GrpcStreamActivity::DrainState(std::shared_ptr<State> Value)
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await boost::asio::this_coro::throw_if_cancelled(false);
        co_await boost::asio::this_coro::reset_cancellation_state(
            boost::asio::disable_cancellation());
        const auto CloseDispatch = co_await Value->Receipt->AwaitCloseDispatch();
        if (!CloseDispatch) (void)Value->Failure.TrySet(CloseDispatch.error());
        // Drain 本身也封止该 owner；不能只封止三个子对象，否则 IsRetired 永远为 false。
        Value->Sealed.store(true, std::memory_order_release);
        Value->Drivers.Seal();
        Value->Front->Seal();
        Value->Child->Seal();

        const auto Driver = co_await Value->Drivers.Drain();
        if (!Driver) (void)Value->Failure.TrySet(Driver.error());
        const auto Child = co_await Value->Child->Drain();
        if (!Child) (void)Value->Failure.TrySet(Child.error());

        if (!Value->Child->IsRetired() || Value->Drivers.Active() != 0 ||
            Value->Drivers.IsBlocked())
        {
            auto Failure = Value->Failure.Load();
            if (Failure.Succeeded()) Failure = {Prism::Fault::Code::Blocked};
            co_return std::unexpected(Failure);
        }

        Value->Receipt->ConfirmExternalClose();
        const auto Front = co_await Value->Front->Drain();
        if (!Front) (void)Value->Failure.TrySet(Front.error());
        if (!Value->Front->IsRetired())
        {
            auto Failure = Value->Failure.Load();
            if (Failure.Succeeded()) Failure = {Prism::Fault::Code::Blocked};
            co_return std::unexpected(Failure);
        }

        const auto Failure = Value->Failure.Load();
        if (Failure.Failed()) co_return std::unexpected(Failure);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }
}

namespace Prism::Gun::Grpc::Detail
{
    auto GrpcStreamActivity::RetryCommand::operator()() noexcept -> void
    {
        Owner->StartRetry();
    }

    auto GrpcStreamDriver::StartRead(const std::shared_ptr<StreamTransport> &Owner) -> void
    {
        if (!Owner->Activity_->StartDriver())
        {
            const Prism::Fault::Failure Failure{Prism::Fault::Code::Blocked};
            Owner->RecordFailure(Failure);
            Owner->SignalReady(Failure);
            return;
        }
        try
        {
            Net::co_spawn(Owner->Executor(), Owner->ReadLoop(),
                [Owner](std::exception_ptr Exception)
                { Complete(Owner, std::move(Exception)); });
        }
        catch (...)
        {
            const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
            Owner->RecordFailure(Failure);
            Owner->SignalReady(Failure);
            Owner->Activity_->CompleteDriver(Failure);
        }
    }

    auto GrpcStreamDriver::StartWrite(const std::shared_ptr<StreamTransport> &Owner) -> void
    {
        if (!Owner->Activity_->StartDriver())
        {
            const Prism::Fault::Failure Failure{Prism::Fault::Code::Blocked};
            Owner->RecordFailure(Failure);
            Owner->SignalReady(Failure);
            return;
        }
        try
        {
            Net::co_spawn(Owner->Executor(), Owner->WriteLoop(),
                [Owner](std::exception_ptr Exception)
                { Complete(Owner, std::move(Exception)); });
        }
        catch (...)
        {
            const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
            Owner->RecordFailure(Failure);
            Owner->SignalReady(Failure);
            Owner->Activity_->CompleteDriver(Failure);
        }
    }

    auto GrpcStreamDriver::Complete(
        const std::shared_ptr<StreamTransport> &Owner,
        std::exception_ptr Exception) noexcept -> void
    {
        if (Exception)
        {
            const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::move(Exception));
            Owner->RecordFailure(Failure);
            Owner->SignalReady(Failure);
        }
        Owner->Activity_->CompleteDriver(Owner->Activity_->Failure());
    }

    auto StreamFactory::Accept(
        Prism::SharedTransmission Lower,
        Config ConfigValue)
        -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
    {
        if (!Lower)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }

        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Lower);
        if (!Prepared)
        {
            co_return std::unexpected(Prepared.error());
        }
        auto Admission = std::move(*Prepared);
        std::shared_ptr<StreamTransport> Self;
        std::exception_ptr ConstructionFailure;
        try
        {
            Self = std::shared_ptr<StreamTransport>(
                new StreamTransport(Lower, std::move(ConfigValue)));
        }
        catch (...)
        {
            ConstructionFailure = std::current_exception();
        }
        if (ConstructionFailure)
        {
            const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::move(ConstructionFailure));
            co_return std::unexpected(co_await Admission.Retire(Failure));
        }

        Prism::SharedTransmission Owner = Self;
        const auto Tracked = Admission.Track(Owner);
        if (!Tracked)
        {
            co_return std::unexpected(co_await Admission.Retire(Tracked.error()));
        }

        GrpcStreamDriver::StartRead(Self);
        GrpcStreamDriver::StartWrite(Self);
        if (Self->ReadySignaled_ &&
            (!Self->ReadyOk_ || Self->Closed_ || Self->ResetReceived_ ||
                Self->ProcessingFailure_.Failed()))
        {
            auto StartFailure = Self->ProcessingFailure_.Failed()
                ? Self->ProcessingFailure_
                : Self->Activity_->Failure();
            if (!StartFailure.Failed())
                StartFailure = {Prism::Fault::Code::ProtocolError};
            co_return std::unexpected(co_await Self->RetireFailure(
                std::move(Admission), StartFailure));
        }

        boost::system::error_code Error;
        co_await Self->Ready_.async_receive(
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error || !Self->ReadyOk_ || Self->Closed_ || Self->ResetReceived_ ||
            Self->ProcessingFailure_.Failed())
        {
            auto Failure = Self->ProcessingFailure_.Failed()
                ? Self->ProcessingFailure_
                : Self->Activity_->Failure();
            if (!Failure.Failed())
            {
                if (Error)
                {
                    Failure = Prism::Fault::FromNative(
                        static_cast<std::error_code>(Error));
                }
                else
                {
                    Failure = {Prism::Fault::Code::ProtocolError};
                }
            }
            co_return std::unexpected(co_await Self->RetireFailure(
                std::move(Admission), Failure));
        }

        Admission.Release();
        co_return std::expected<Prism::SharedTransmission, Prism::Fault::Failure>(
            std::move(Self));
    }

    StreamTransport::StreamTransport(Prism::SharedTransmission Lower, Config ConfigValue)
        : Prism::Transmission(Net::make_strand(Lower->Executor())),
          Lower_(std::move(Lower)), Config_(std::move(ConfigValue)),
          Session_(std::make_shared<H2::Session>(Prism::Transmission::Executor(), true)),
          Ready_(Prism::Transmission::Executor(), 1),
          RxNotify_(Prism::Transmission::Executor(), 1),
          WriteNotify_(Prism::Transmission::Executor(), 8), Decoder_(Config_.MaxMessageBytes)
    {
        Activity_ = std::make_shared<GrpcStreamActivity>(
            Prism::Transmission::Executor(), GrpcStreamActivityLayers{
                Prism::Transmission::Activity(), Lower_->Activity(), CloseReceipt()});
        Session_->OnHeaders = [this](const std::int32_t StreamId,
                                      const H2::HeaderList &Headers, const bool EndStream)
        { HandleHeaders(StreamId, Headers, EndStream); };
        Session_->OnData = [this](const std::int32_t StreamId,
                                   const std::span<const std::byte> Data)
        { HandleData(StreamId, Data); };
        Session_->OnStreamClose = [this](const H2::StreamReceiveClosure &Closure)
        { HandleStreamClose(Closure); };
    }

    auto StreamTransport::StartRead(std::span<std::byte> Buffer, Completion Handler) -> void
    {
        Initiate<ReadWork>(GrpcRead{
            std::static_pointer_cast<StreamTransport>(Transmission::shared_from_this()), Buffer},
            std::move(Handler));
    }

    auto StreamTransport::StartWrite(
        std::span<const std::byte> Buffer, Completion Handler) -> void
    {
        Initiate<WriteWork>(GrpcWrite{
            std::static_pointer_cast<StreamTransport>(Transmission::shared_from_this()), Buffer},
            std::move(Handler));
    }

    auto StreamTransport::StartWriteShutdown(Completion Handler) -> void
    {
        Prism::Fault::Failure Failure;
        if (Closed_)
        {
            Failure = Activity_->Failure();
            if (Failure.Succeeded()) Failure = {Prism::Fault::Code::Canceled};
        }
        else if (ReadTerminal_ && ReadTerminal_->Code != Prism::Fault::Code::Eof)
        {
            Failure = *ReadTerminal_;
        }
        else if (WriterFailed_)
        {
            Failure = WriterFailure_;
        }
        else if (StreamId_ <= 0)
        {
            Failure = {Prism::Fault::Code::ProtocolError};
        }
        else if (!LocalEnded_)
        {
            const auto Trailers = Session_->SubmitHeaders(
                StreamId_, MakeResponseTrailers(0), true);
            if (!Trailers)
            {
                Failure = Trailers.error();
            }
            else
            {
                LocalEnded_ = true;
                LocalEndFlushPending_ = true;
            }
        }
        if (Failure.Failed())
        {
            RecordFailure(Failure);
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), Prism::IoResult{0, Failure});
            return;
        }
        if (LocalEndFlushed_)
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), Prism::IoResult{});
            return;
        }
        PendingWriteShutdowns_.push_back(std::move(Handler));
        // 满队列时已有通知足以唤醒 writer；完成只发生在相应 Flush 结束后。
        (void)WriteNotify_.try_send(boost::system::error_code{});
    }

    auto StreamTransport::OnClose() -> ControlResult
    {
        if (Closed_)
        {
            return {};
        }
        Closed_ = true;
        auto PendingFailure = Activity_->Failure();
        if (PendingFailure.Succeeded())
        {
            PendingFailure = {Prism::Fault::Code::Canceled};
        }
        CompleteWriteShutdowns(PendingFailure);
        // 下层 Close 仍要取得自己的控制预约；先封止 child 会把该预约拒绝，
        // 并让下层挂起读无法完成。
        const auto Result = Lower_->Close();
        if (!Result)
        {
            RecordFailure(Result.error());
        }
        Activity_->Seal();
        Ready_.close();
        RxNotify_.close();
        WriteNotify_.close();
        return Result;
    }

    auto StreamTransport::OnCancel() -> ControlResult
    {
        if (ReadInFlight_)
        {
            CancelPendingRead_ = true;
        }
        auto ExpectedReadState = PublicReadState::Active;
        (void)PublicReadState_.compare_exchange_strong(
            ExpectedReadState, PublicReadState::Canceled,
            std::memory_order_acq_rel, std::memory_order_acquire);
        const auto Result = Lower_->Cancel();
        if (!Result)
        {
            RecordFailure(Result.error());
        }
        (void)RxNotify_.try_send(boost::system::error_code{});
        (void)WriteNotify_.try_send(boost::system::error_code{});
        return Result;
    }

    auto StreamTransport::SignalReady(Prism::Fault::Failure Failure) -> void
    {
        if (Failure.Failed())
        {
            RecordFailure(Failure);
        }
        if (ReadySignaled_)
        {
            return;
        }
        ReadyOk_ = Failure.Succeeded();
        ReadySignaled_ = true;
        (void)Ready_.try_send(boost::system::error_code{});
    }

    auto StreamTransport::RetireFailure(
        Prism::Contract::InboundAdmission Admission,
        Prism::Fault::Failure Cause)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        RecordFailure(Cause);
        const auto Canceled = Cancel();
        if (!Canceled) RecordFailure(Canceled.error());
        const auto Closed = Close();
        if (!Closed) RecordFailure(Closed.error());
        const auto Drained = co_await Activity_->Drain();
        if (!Drained) RecordFailure(Drained.error());
        co_return co_await Admission.Retire(Activity_->Failure());
    }

    auto StreamTransport::ReadPartial(std::span<std::byte> Buffer, std::error_code &Error)
        -> Net::awaitable<std::size_t>
    {
        Error.clear();
        auto ExpectedReadState = PublicReadState::Idle;
        if (!PublicReadState_.compare_exchange_strong(
                ExpectedReadState, PublicReadState::Active,
                std::memory_order_acq_rel, std::memory_order_acquire))
        {
            Error = Prism::Fault::ToNative(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            co_return 0;
        }
        co_await Net::dispatch(Executor(), Net::use_awaitable);
        while (!Closed_ && !RemoteEnded_ && !ReadTerminal_ && RxQueue_.empty())
        {
            if (PublicReadState_.load(std::memory_order_acquire) ==
                PublicReadState::Canceled)
            {
                if (RxQueue_.empty() && !ReadTerminal_)
                {
                    PublicReadState_.store(PublicReadState::Idle, std::memory_order_release);
                    Error = Prism::Fault::ToNative(
                        Prism::Fault::Failure{Prism::Fault::Code::Canceled});
                    co_return 0;
                }
                break;
            }
            RxNotify_.reset();
            if (PublicReadState_.load(std::memory_order_acquire) ==
                PublicReadState::Canceled)
            {
                if (RxQueue_.empty() && !ReadTerminal_)
                {
                    PublicReadState_.store(PublicReadState::Idle, std::memory_order_release);
                    Error = Prism::Fault::ToNative(
                        Prism::Fault::Failure{Prism::Fault::Code::Canceled});
                    co_return 0;
                }
                break;
            }
            boost::system::error_code NotifyError;
            co_await RxNotify_.async_receive(Net::redirect_error(Net::use_awaitable, NotifyError));
            if (NotifyError && Closed_)
            {
                const auto ReadState = PublicReadState_.exchange(
                    PublicReadState::Idle, std::memory_order_acq_rel);
                if (ReadState == PublicReadState::Canceled)
                {
                    Error = Prism::Fault::ToNative(
                        Prism::Fault::Failure{Prism::Fault::Code::Canceled});
                }
                co_return 0;
            }
        }
        if (RxQueue_.empty())
        {
            if (ReadTerminal_)
            {
                (void)PublicReadState_.exchange(
                    PublicReadState::Idle, std::memory_order_acq_rel);
                Error = Prism::Fault::ToNative(*ReadTerminal_);
                co_return 0;
            }
            const auto Failure = Activity_->Failure();
            if (Failure.Failed())
            {
                (void)PublicReadState_.exchange(
                    PublicReadState::Idle, std::memory_order_acq_rel);
                Error = Prism::Fault::ToNative(Failure);
                co_return 0;
            }
            const auto ReadState = PublicReadState_.exchange(
                PublicReadState::Idle, std::memory_order_acq_rel);
            if (ReadState == PublicReadState::Canceled)
            {
                Error = Prism::Fault::ToNative(
                    Prism::Fault::Failure{Prism::Fault::Code::Canceled});
            }
            co_return 0;
        }
        auto &Front = RxQueue_.front();
        const auto Count = (std::min)(Buffer.size(), Front.size() - RxOffset_);
        std::memcpy(Buffer.data(), Front.data() + RxOffset_, Count);
        RxOffset_ += Count;
        if (RxOffset_ == Front.size())
        {
            RxQueue_.pop_front();
            RxOffset_ = 0;
        }
        const auto ReadState = PublicReadState_.exchange(
            PublicReadState::Idle, std::memory_order_acq_rel);
        if (ReadState == PublicReadState::Canceled)
        {
            Error = Prism::Fault::ToNative(
                Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }
        co_return Count;
    }

    auto StreamTransport::WritePartial(
        std::span<const std::byte> Buffer, std::error_code &Error)
        -> Net::awaitable<std::size_t>
    {
        Error.clear();
        co_await Net::dispatch(Executor(), Net::use_awaitable);
        const bool TerminalWrite = ReadTerminal_ &&
            ReadTerminal_->Code != Prism::Fault::Code::Eof;
        if (Closed_ || !ReadyOk_ || StreamId_ <= 0 || TerminalWrite || WriterFailed_)
        {
            auto Failure = Activity_->Failure();
            if (TerminalWrite) Failure = *ReadTerminal_;
            else if (WriterFailed_) Failure = WriterFailure_;
            if (Failure.Failed())
            {
                Error = Prism::Fault::ToNative(Failure);
            }
            else
            {
                Error = std::make_error_code(std::errc::broken_pipe);
            }
            co_return 0;
        }
        std::vector<std::byte> Payload;
        if (TunEnvelope_)
            Payload = EncodeTunMessage(Buffer);
        else
            Payload.assign(Buffer.begin(), Buffer.end());
        const auto Message = EncodeMessage(Payload);
        if (Message.empty() && !Buffer.empty())
        {
            Error = Prism::Fault::ToNative(
                Prism::Fault::Failure{Prism::Fault::Code::OversizedMsg});
            co_return 0;
        }
        std::size_t Offset = 0;
        while (Offset < Message.size())
        {
            const auto Count = (std::min)(std::size_t{16U * 1024U}, Message.size() - Offset);
            const auto Chunk = std::span<const std::byte>(Message).subspan(Offset, Count);
            auto Status = Session_->SubmitData(StreamId_, Chunk, false);
            while (Status == H2::SubmitDataStatus::Blocked)
            {
                (void)WriteNotify_.try_send(boost::system::error_code{});
                const auto Writable = co_await Session_->AwaitWritable(StreamId_, Count);
                if (!Writable)
                {
                    Error = Prism::Fault::ToNative(Writable.error());
                    RecordFailure(Writable.error());
                    RecordControlFailure(Close());
                    co_return 0;
                }
                Status = Session_->SubmitData(StreamId_, Chunk, false);
            }
            if (Status != H2::SubmitDataStatus::Accepted)
            {
                auto Failure = Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument};
                if (Status == H2::SubmitDataStatus::Closed)
                {
                    Failure = {Prism::Fault::Code::ConnectionAborted};
                }
                Error = Prism::Fault::ToNative(Failure);
                RecordFailure(Failure);
                RecordControlFailure(Close());
                co_return 0;
            }
            Offset += Count;
            (void)WriteNotify_.try_send(boost::system::error_code{});
        }
        co_return Buffer.size();
    }

    auto StreamTransport::HandleHeaders(
        const std::int32_t StreamId,
        const H2::HeaderList &Headers,
        const bool EndStream) -> void
    {
        const auto Request = ParseRequestHeaders(Headers);
        if (StreamId_ > 0 || EndStream)
        {
            const auto Reset = Session_->ResetStream(StreamId, H2::ErrorProtocol);
            if (!Reset)
            {
                RecordFailure(Reset.error());
                RecordControlFailure(Close());
            }
            return;
        }
        if (!Request || Request->Path != Config_.Path)
        {
            const auto Response = Session_->SubmitHeaders(
                StreamId, {{":status", "415"}, {"content-type", "application/grpc"}}, false);
            const auto Trailers = Session_->SubmitHeaders(
                StreamId, MakeResponseTrailers(12), true);
            if (!Response || !Trailers)
            {
                auto Failure = Prism::Fault::Failure{};
                if (!Response) Failure = Response.error();
                else Failure = Trailers.error();
                RecordFailure(Failure);
                RecordControlFailure(Close());
                SignalReady(Failure);
                return;
            }
            SignalReady({Prism::Fault::Code::ProtocolError});
            return;
        }
        StreamId_ = StreamId;
        const auto SubmitResult = Session_->SubmitHeaders(StreamId, MakeResponseHeaders(), false);
        if (!SubmitResult)
            SignalReady(SubmitResult.error());
        else
            SignalReady({});
        (void)WriteNotify_.try_send(boost::system::error_code{});
    }

    auto StreamTransport::HandleData(
        const std::int32_t StreamId,
        const std::span<const std::byte> Data) -> void
    {
        if (StreamId != StreamId_)
        {
            return;
        }
        std::vector<std::vector<std::byte>> Messages;
        if (!Decoder_.Feed(Data, Messages))
        {
            const Prism::Fault::Failure Failure{
                Prism::Fault::Code::ProtocolError};
            ProcessingFailure_ = Failure;
            RecordFailure(Failure);
            if (Session_->ResetStream(StreamId, H2::ErrorProtocol))
            {
                RemoteEnded_ = true;
            }
            else
            {
                RecordControlFailure(Close());
            }
            (void)RxNotify_.try_send(boost::system::error_code{});
            return;
        }
        for (auto &Message : Messages)
        {
            if (auto TunMessage = DecodeTunMessage(Message))
            {
                TunEnvelope_ = true;
                RxQueue_.push_back(std::move(*TunMessage));
            }
            else
            {
                RxQueue_.push_back(std::move(Message));
            }
        }
        if (!Messages.empty())
        {
            (void)RxNotify_.try_send(boost::system::error_code{});
        }
    }

    auto StreamTransport::HandleStreamClose(const H2::StreamReceiveClosure &Closure) -> void
    {
        if (Closure.StreamId != StreamId_)
        {
            return;
        }
        if (Closure.Kind == H2::StreamReceiveClosureKind::EndStream)
        {
            RemoteEnded_ = true;
            ReadTerminal_ = Prism::Fault::Failure{Prism::Fault::Code::Eof};
            (void)RxNotify_.try_send(boost::system::error_code{});
            return;
        }
        auto Code = Prism::Fault::Code::ProtocolError;
        if (Closure.ErrorCode == H2::ErrorNoError)
            Code = Prism::Fault::Code::ConnectionReset;
        const Prism::Fault::Failure Failure{Code};
        ReadTerminal_ = Failure;
        RemoteEnded_ = true;
        ResetReceived_ = true;
        RecordFailure(Failure);
        // 关闭专属下层并停止驱动；wrapper 保留准入以先交完已解码队列。
        RecordControlFailure(Lower_->Close());
        (void)RxNotify_.try_send(boost::system::error_code{});
        (void)WriteNotify_.try_send(boost::system::error_code{});
    }

    auto StreamTransport::CompleteWriteShutdowns(
        const Prism::Fault::Failure Failure) -> void
    {
        auto Pending = std::move(PendingWriteShutdowns_);
        PendingWriteShutdowns_.clear();
        for (auto &Handler : Pending)
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), Prism::IoResult{0, Failure});
        }
    }

    auto StreamTransport::Flush() -> Net::awaitable<Prism::Fault::Failure>
    {
        std::vector<std::byte> Output;
        if (!Session_->Collect(Output) || Output.empty())
        {
            co_return Prism::Fault::Failure{};
        }
        std::size_t Offset = 0;
        while (Offset < Output.size())
        {
            const auto Part = co_await Lower_->WriteSome(
                std::span<const std::byte>(Output).subspan(Offset));
            const auto Written = Part.Bytes;
            if (Part.Failure.Failed())
            {
                co_return Part.Failure;
            }
            if (Written > Output.size() - Offset)
            {
                co_return Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument};
            }
            if (Written == 0U)
            {
                co_return Prism::Fault::Failure{Prism::Fault::Code::WouldBlock};
            }
            Offset += Written;
        }
        co_return Prism::Fault::Failure{};
    }

    auto StreamTransport::ReadLoop() -> Net::awaitable<void>
    {
        Session_->SendSettings();
        (void)WriteNotify_.try_send(boost::system::error_code{});
        std::array<std::byte, 16384> Buffer{};
        while (!Closed_ && Lower_->IsOpen())
        {
            ReadInFlight_ = true;
            const auto Part = co_await Lower_->ReadSome(Buffer);
            ReadInFlight_ = false;
            const auto Step = ProcessGrpcReadCompletion(
                *Session_, GrpcReadCompletion{std::span<const std::byte>(Buffer), Part});
            if (Closed_)
            {
                co_return;
            }
            if (ProcessingFailure_.Failed())
            {
                SignalReady(ProcessingFailure_);
                RecordControlFailure(Close());
                co_return;
            }
            const bool CancelRequested = std::exchange(CancelPendingRead_, false);
            if (CancelRequested &&
                (Step.Failure.Code == Prism::Fault::Code::Canceled ||
                 Step.Failure.Native == std::errc::operation_canceled))
            {
                (void)WriteNotify_.try_send(boost::system::error_code{});
                continue;
            }
            if (Step.Terminal)
            {
                if (Step.LowerTerminal && ReadySignaled_ && ReadyOk_)
                {
                    ReadTerminal_ = Step.Failure;
                    if (Step.Failure.Code != Prism::Fault::Code::Eof)
                    {
                        RecordFailure(Step.Failure);
                    }
                    (void)RxNotify_.try_send(boost::system::error_code{});
                    (void)WriteNotify_.try_send(boost::system::error_code{});
                    co_return;
                }
                SignalReady(Step.Failure);
                if (!Step.LowerTerminal || !ReadyOk_)
                {
                    RecordControlFailure(Close());
                }
                co_return;
            }
            if (RemoteEnded_)
            {
                (void)WriteNotify_.try_send(boost::system::error_code{});
                co_return;
            }
            (void)WriteNotify_.try_send(boost::system::error_code{});
        }
        if (!Closed_)
        {
            SignalReady({Prism::Fault::Code::Eof});
            RecordControlFailure(Close());
        }
    }

    auto StreamTransport::WriteLoop() -> Net::awaitable<void>
    {
        while (!Closed_)
        {
            boost::system::error_code Error;
            co_await WriteNotify_.async_receive(Net::redirect_error(Net::use_awaitable, Error));
            if (Error || Closed_)
            {
                co_return;
            }
            if (RemoteEnded_ && ReadTerminal_ &&
                ReadTerminal_->Code != Prism::Fault::Code::Eof)
            {
                CompleteWriteShutdowns(*ReadTerminal_);
                co_return;
            }
            const bool FlushesLocalEnd = LocalEndFlushPending_;
            const auto Failure = co_await Flush();
            if (Failure.Failed())
            {
                const auto ShutdownFailure = ReadTerminal_ &&
                    ReadTerminal_->Code != Prism::Fault::Code::Eof
                    ? *ReadTerminal_
                    : Failure;
                CompleteWriteShutdowns(ShutdownFailure);
                SignalReady(Failure);
                if (ReadTerminal_)
                {
                    WriterFailure_ = Failure;
                    WriterFailed_ = true;
                    RecordFailure(Failure);
                }
                else
                {
                    RecordControlFailure(Close());
                }
                co_return;
            }
            if (FlushesLocalEnd)
            {
                LocalEndFlushPending_ = false;
                LocalEndFlushed_ = true;
                CompleteWriteShutdowns({});
            }
        }
    }

    auto StreamTransport::RecordFailure(const Prism::Fault::Failure Failure) noexcept -> void
    {
        if (Failure.Failed())
        {
            // 同一首因由 accepted activity owner 统一保存。
            if (Activity_) Activity_->RecordFailure(Failure);
        }
    }

    auto StreamTransport::RecordControlFailure(
        const Prism::Transmission::ControlResult &Result) noexcept -> void
    {
        if (!Result) RecordFailure(Result.error());
    }
}

namespace Prism::Gun
{
    auto Connect(ConnectRequest Request)
        -> Net::awaitable<std::expected<SharedConn, Prism::Fault::Failure>>
    {
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Request.Upstream);
        if (!Prepared) co_return std::unexpected(Prepared.error());
        auto Admission = std::move(*Prepared);

        std::exception_ptr Fatal;
        try
        {
            auto Connection = std::make_shared<Conn<>>(
                std::move(Request.Upstream), std::move(Request.Configuration));
            auto Tracked = Admission.Track(
                std::static_pointer_cast<Prism::Transmission>(Connection));
            if (!Tracked)
                co_return std::unexpected(co_await Admission.Retire(Tracked.error()));

            const auto Handshake = co_await Connection->WriteHandshake(Request.Host);
            if (!Handshake)
                co_return std::unexpected(co_await Admission.Retire(Handshake.error()));
            Admission.Release();
            co_return SharedConn(std::move(Connection));
        }
        catch (const std::bad_alloc &)
        {
            Fatal = std::current_exception();
        }
        co_return std::unexpected(co_await Admission.Retire(
            Prism::Contract::InboundAdmission::ExceptionFailure(std::move(Fatal))));
    }

    auto Accept(SharedTransmission Upstream, Config Configuration)
        -> Net::awaitable<std::expected<AcceptResult, Prism::Fault::Failure>>
    {
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Upstream);
        if (!Prepared) co_return std::unexpected(Prepared.error());
        auto Admission = std::move(*Prepared);

        std::exception_ptr Fatal;
        try
        {
            auto Connection = std::make_shared<Conn<>>(
                std::move(Upstream), std::move(Configuration));
            auto Tracked = Admission.Track(
                std::static_pointer_cast<Prism::Transmission>(Connection));
            if (!Tracked)
                co_return std::unexpected(co_await Admission.Retire(Tracked.error()));

            std::string Host;
            const auto Handshake = co_await Connection->ReadHandshake(Host);
            if (!Handshake)
                co_return std::unexpected(co_await Admission.Retire(Handshake.error()));
            Admission.Release();
            co_return AcceptResult{std::move(Host), SharedConn(std::move(Connection))};
        }
        catch (const std::bad_alloc &)
        {
            Fatal = std::current_exception();
        }
        co_return std::unexpected(co_await Admission.Retire(
            Prism::Contract::InboundAdmission::ExceptionFailure(std::move(Fatal))));
    }
}
