/**
 * @file Http2Accept.cpp
 * @brief TrustTunnel HTTP/2 服务端准入与认证实现。
 */

#include <Prism/Protocols/Trusttunnel/Detail/Http2Accept.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2ReadCompletion.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/WireAuthBinding.hpp>
#include <Prism/Protocols/Trusttunnel/Http2Server.hpp>

#include <Prism/Contract/Ingress/InboundAdmission.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <utility>

namespace Prism::Trusttunnel::Detail
{
    auto CarrierOwner::RetryCommand::operator()() noexcept -> void
    {
        Owner->StartRetry();
    }

    CarrierLifecycle::CarrierLifecycle(Net::any_io_executor Executor)
        : Closed(std::make_shared<CarrierClosedChannel>(std::move(Executor), 1)),
          DrainGate(std::make_shared<CarrierDrainGate>(Closed->get_executor(), 1))
    {
        (void)DrainGate->try_send(boost::system::error_code{});
    }

    auto CarrierLifecycle::RecordFailure(const Prism::Fault::Failure Value) noexcept -> void
    {
        if (const auto Exchange = Transport.lock();
            Exchange && Exchange->ExchangeComplete() && IsTeardownFailure(Value))
            return;
        // Closing 后的 Canceled/operation_aborted 是本端关闭唤醒在途 I/O 的结果；
        // 真实 Native 失败（包括非取消类别）仍按首因保存。
        if (IsLocalCloseCancellation(Value)) return;
        if (Value.Failed())
        {
            // TrySet 的 bool 仅表示首因竞争胜者，不影响同一 lifecycle 的关闭回执。
            (void)FirstFailure.TrySet(Value);
        }
    }

    auto CarrierLifecycle::StartDriver() noexcept -> void
    {
        DriverStarted.store(true, std::memory_order_release);
    }

    auto CarrierLifecycle::CompleteDriver() noexcept -> void
    {
        DriverCompleted.store(true, std::memory_order_release);
        (void)Closed->try_send(boost::system::error_code{});
    }

    auto CarrierLifecycle::WaitDriver()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        while (DriverStarted.load(std::memory_order_acquire) &&
               !DriverCompleted.load(std::memory_order_acquire))
        {
            boost::system::error_code Error;
            co_await Closed->async_receive(Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                RecordFailure(Prism::Fault::FromNative(static_cast<std::error_code>(Error)));
                break;
            }
        }
        const auto First = Failure();
        if (First.Failed()) co_return std::unexpected(First);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    CarrierOwner::CarrierOwner(CarrierOwnerLayers Layers)
        : Transport(std::move(Layers.Transport)), Wire(std::move(Layers.Wire)),
          Encrypted(std::move(Layers.Encrypted)), Lifecycle(std::move(Layers.Lifecycle)),
          Binding(std::move(Layers.Binding)),
          Storage_(Prism::Executor::ContextOwner::Storage(Executor())),
          Reclaimer_(std::make_shared<Prism::Executor::ExecutorReclaimer>(
              Net::make_strand(Executor())))
    {
    }

    auto CarrierOwner::RetryCompletion::operator()(
        std::exception_ptr Exception,
        std::expected<void, Prism::Fault::Failure> Result) const noexcept -> void
    {
        Owner->RetryScheduled_.store(false, std::memory_order_release);
        if (Exception)
        {
            Owner->Lifecycle->RecordFailure(
                Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::move(Exception)));
            Owner->Storage_->Retain(Owner);
        }
        else if (!Result)
        {
            Owner->Storage_->Retain(Owner);
        }
        else
        {
            Owner->Storage_->Collect();
        }
    }

    auto CarrierOwner::Close() -> Prism::Transmission::ControlResult
    {
        if (!Lifecycle)
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        if (IsRetired()) return {};
        Lifecycle->Closing.store(true, std::memory_order_release);
        Prism::Transmission::ControlResult Result{};
        if (Transport)
        {
            const auto Closed = Transport->Close();
            RecordControlFailure(Closed);
            if (!Closed) Result = std::unexpected(Closed.error());
        }
        if (Wire) Wire->Close();
        if (Encrypted)
        {
            const auto Canceled = Encrypted->Cancel();
            RecordControlFailure(Canceled);
            if (Result && !Canceled) Result = std::unexpected(Canceled.error());
            const auto Closed = Encrypted->Close();
            RecordControlFailure(Closed);
            if (Result && !Closed) Result = std::unexpected(Closed.error());
        }
        if (!Result && Lifecycle->IsLocalCloseCancellation(Result.error()))
            return {};
        return Result;
    }

    auto CarrierOwner::Cancel() -> Prism::Transmission::ControlResult
    {
        if (!Lifecycle)
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        if (IsRetired()) return {};
        Lifecycle->Closing.store(true, std::memory_order_release);
        Prism::Transmission::ControlResult Result{};
        if (Transport)
        {
            const auto Canceled = Transport->Cancel();
            RecordControlFailure(Canceled);
            if (!Canceled) Result = std::unexpected(Canceled.error());
        }
        if (Encrypted)
        {
            const auto Canceled = Encrypted->Cancel();
            RecordControlFailure(Canceled);
            if (Result && !Canceled) Result = std::unexpected(Canceled.error());
        }
        if (!Result && Lifecycle->IsLocalCloseCancellation(Result.error()))
            return {};
        return Result;
    }

    auto CarrierOwner::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (!Lifecycle)
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        co_await Net::dispatch(Executor(), Net::use_awaitable);
        boost::system::error_code GateError;
        co_await Lifecycle->DrainGate->async_receive(
            Net::redirect_error(Net::use_awaitable, GateError));
        if (GateError)
        {
            Lifecycle->RecordFailure(
                Prism::Fault::FromNative(static_cast<std::error_code>(GateError)));
            RequestRetirement();
            co_return std::unexpected(Lifecycle->Failure());
        }
        struct DrainRelease final
        {
            std::shared_ptr<CarrierDrainGate> Gate;
            ~DrainRelease() noexcept
            {
                if (Gate) (void)Gate->try_send(boost::system::error_code{});
            }
        } Release{Lifecycle->DrainGate};
        if (Lifecycle->Retired.load(std::memory_order_acquire))
        {
            const auto First = Lifecycle->Failure();
            if (First.Failed()) co_return std::unexpected(First);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        bool Complete = true;
        const auto Closed = Close();
        if (!Closed) Lifecycle->RecordFailure(Closed.error());
        const auto Driver = co_await Lifecycle->WaitDriver();
        if (!Driver) Lifecycle->RecordFailure(Driver.error());
        if (Lifecycle->DriverStarted.load(std::memory_order_acquire) &&
            !Lifecycle->DriverCompleted.load(std::memory_order_acquire))
            Complete = false;
        // 三层退出互相依赖：driver 可能仍持有 TLS 读预约。必须先无条件推进每一层，
        // 再用各自真实回执汇总；短路会留下未关闭的 Wire/TLS 并让根一直挂起。
        const bool TransportDrained = co_await DrainTransport();
        const bool WireDrained = co_await DrainWire();
        const bool EncryptedDrained = co_await DrainEncrypted();
        Lifecycle->TransportDrained.store(TransportDrained, std::memory_order_release);
        Lifecycle->WireDrained.store(WireDrained, std::memory_order_release);
        Lifecycle->EncryptedDrained.store(EncryptedDrained, std::memory_order_release);
        Complete = TransportDrained && WireDrained && EncryptedDrained && Complete;
        const bool ExchangeCompleted =
            Transport && Transport->ExchangeComplete();
        Lifecycle->LayersDrained.store(Complete, std::memory_order_release);
        if (Complete) Retire();
        if (!Complete)
        {
            Lifecycle->RecordFailure(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            RequestRetirement();
        }
        const auto First = Lifecycle->Failure();
        if (Lifecycle->IsLocalCloseCancellation(First))
            co_return std::expected<void, Prism::Fault::Failure>{};
        if (ExchangeCompleted && CarrierLifecycle::IsTeardownFailure(First))
            co_return std::expected<void, Prism::Fault::Failure>{};
        if (First.Failed()) co_return std::unexpected(First);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto CarrierOwner::RequestRetirement() -> void
    {
        if (IsRetired() || RetryScheduled_.exchange(true, std::memory_order_acq_rel))
            return;
        const auto Self = shared_from_this();
        Storage_->Retain(Self);
        const auto Posted = Reclaimer_->Post(RetryCommand{Self});
        if (!Posted)
        {
            RetryScheduled_.store(false, std::memory_order_release);
            Lifecycle->RecordFailure(Posted.error());
            Storage_->Retain(Self);
        }
    }

    auto CarrierOwner::WriteShutdown(Prism::Transmission::Completion Handler) -> void
    {
        if (!Transport)
        {
            Prism::Transmission::PostResult(
                Executor(),
                std::move(Handler),
                Prism::IoResult{0, {Prism::Fault::Code::IoError}});
            return;
        }
        Transport->WriteShutdown(std::move(Handler));
    }

    auto CarrierOwner::RecordControlFailure(
        const Prism::Transmission::ControlResult &Result) noexcept -> void
    {
        // 本地 Close/Cancel 或被封止控制命令返回的 Canceled 只表示命令被接管/已取消，
        // 不是数据面失败；真实 Native 失败仍保留。
        if (Lifecycle && !Result && !Lifecycle->IsLocalCloseCancellation(Result.error()))
            Lifecycle->RecordFailure(Result.error());
    }

    auto CarrierOwner::DrainTransport() -> Net::awaitable<bool>
    {
        if (!Transport) co_return true;
        const auto Activity = Transport->Activity();
        if (!Activity)
        {
            Lifecycle->RecordFailure(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            co_return false;
        }
        const auto Drained = co_await Activity->Drain();
        if (!Drained) Lifecycle->RecordFailure(Drained.error());
        Lifecycle->TransportActivityRetired.store(
            Activity->IsRetired(), std::memory_order_release);
        Lifecycle->TransportOpen.store(Transport->IsOpen(), std::memory_order_release);
        const bool Complete = Activity->IsRetired() && !Transport->IsOpen();
        if (!Complete)
            Lifecycle->RecordFailure(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        co_return Complete;
    }

    auto CarrierOwner::DrainWire() -> Net::awaitable<bool>
    {
        if (!Wire) co_return true;
        const auto Drained = co_await Wire->Drain();
        if (!Drained) Lifecycle->RecordFailure(Drained.error());
        const bool Complete = Wire->IsRetired();
        if (!Complete)
            Lifecycle->RecordFailure(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        co_return Complete;
    }

    auto CarrierOwner::DrainEncrypted() -> Net::awaitable<bool>
    {
        if (!Encrypted) co_return true;
        const auto Activity = Encrypted->Activity();
        if (!Activity)
        {
            Lifecycle->RecordFailure(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            co_return false;
        }
        const auto Drained = co_await Activity->Drain();
        if (!Drained) Lifecycle->RecordFailure(Drained.error());
        Lifecycle->EncryptedActivityRetired.store(
            Activity->IsRetired(), std::memory_order_release);
        Lifecycle->EncryptedOpen.store(Encrypted->IsOpen(), std::memory_order_release);
        const bool Complete = Activity->IsRetired() && !Encrypted->IsOpen();
        if (!Complete)
            Lifecycle->RecordFailure(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        co_return Complete;
    }

    auto CarrierOwner::Retire() noexcept -> void
    {
        Transport.reset();
        Wire.reset();
        Encrypted.reset();
        Lifecycle->DriverState.reset();
        Binding.reset();
        Lifecycle->Retired.store(true, std::memory_order_release);
        Storage_->Collect();
    }

    auto CarrierOwner::RetryOnExecutor()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Drained = co_await Drain();
        if (IsRetired()) co_return std::expected<void, Prism::Fault::Failure>{};
        if (!Drained) co_return std::unexpected(Drained.error());
        co_return std::unexpected(
            Prism::Fault::Failure{Prism::Fault::Code::Blocked});
    }

    auto CarrierOwner::StartRetry() noexcept -> void
    {
        if (IsRetired())
        {
            RetryScheduled_.store(false, std::memory_order_release);
            return;
        }
        const auto Self = shared_from_this();
        try
        {
            Net::co_spawn(
                Reclaimer_->Executor(), RetryOnExecutor(), RetryCompletion{Self});
        }
        catch (...)
        {
            RetryScheduled_.store(false, std::memory_order_release);
            Lifecycle->RecordFailure(
                Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception()));
            Storage_->Retain(Self);
        }
    }

    auto RetireHttp2HandshakeFailure(
        Prism::Contract::InboundAdmission &Admission,
        Prism::Transport::Encrypted::HandshakeResult Handshake)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        auto Failure = Handshake.Failure;
        if (Failure.Succeeded())
        {
            Failure = {Prism::Fault::Code::TlsHsfail};
        }

        if (Handshake.Stream)
        {
            auto Owner = std::make_shared<Prism::Transport::Encrypted>(
                std::move(Handshake.Stream), std::move(Handshake.Bytes));
            auto Child = std::static_pointer_cast<Prism::Transmission>(Owner);
            const auto Tracked = Admission.Track(Child);
            if (!Tracked)
            {
                Prism::Contract::ProtocolDataPlane Plane;
                Plane.Root = Prism::Contract::StreamDataPlane{std::move(Child), {}};
                const auto Rejected = co_await Admission.Reject(std::move(Plane), Failure);
                Owner.reset();
                co_return Rejected.error();
            }
        }
        else if (Handshake.Recovered)
        {
            const auto Tracked = Admission.Track(Handshake.Recovered);
            if (!Tracked)
            {
                Prism::Contract::ProtocolDataPlane Plane;
                Plane.Root = Prism::Contract::StreamDataPlane{
                    std::move(Handshake.Recovered), {}};
                const auto Rejected = co_await Admission.Reject(std::move(Plane), Failure);
                co_return Rejected.error();
            }
        }

        co_return co_await Admission.Retire(Failure);
    }

    auto WaitHttp2ServerReady(
        const std::shared_ptr<Http2ReadyChannel> &Ready,
        Net::any_io_executor Executor) -> Net::awaitable<Http2ServerResult>
    {
        Net::steady_timer Deadline(std::move(Executor));
        Deadline.expires_after(std::chrono::seconds(30));
        boost::system::error_code ReadyError;
        auto Wait = Ready->async_receive(Net::redirect_error(Net::use_awaitable, ReadyError));
        auto DeadlineWait = Deadline.async_wait(Net::use_awaitable);
        const auto Result = co_await (std::move(Wait) || std::move(DeadlineWait));
        if (Result.index() == 1)
        {
            co_return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::Timeout, std::make_error_code(std::errc::timed_out)});
        }
        if (ReadyError)
        {
            co_return std::unexpected(Prism::Fault::FromNative(
                static_cast<std::error_code>(ReadyError)));
        }
        co_return std::get<0>(Result);
    }

    auto Http2ServerDataWriter::operator()(
        const std::int32_t StreamId,
        const std::span<const std::byte> Data) const -> Net::awaitable<Http2ServerResult>
    {
        return Run({Session, Wire, StreamId, Data});
    }

    auto Http2ServerDataWriter::Run(Http2ServerDataRequest Value)
        -> Net::awaitable<Http2ServerResult>
    {
        std::size_t Offset = 0;
        bool EmptySubmitted = false;
        while (Offset < Value.Data.size() || !EmptySubmitted)
        {
            const auto Count = (std::min)(std::size_t{16U * 1024U}, Value.Data.size() - Offset);
            const auto Chunk = Value.Data.subspan(Offset, Count);
            auto Status = Value.Session->SubmitData(Value.StreamId, Chunk, false);
            while (Status == H2::SubmitDataStatus::Blocked)
            {
                const auto Flushed = co_await FlushHttp2Frames(Value.Session, Value.Wire);
                if (!Flushed) co_return std::unexpected(Flushed.error());
                const auto Writable = co_await Value.Session->AwaitWritable(Value.StreamId, Count);
                if (!Writable) co_return std::unexpected(Writable.error());
                Status = Value.Session->SubmitData(Value.StreamId, Chunk, false);
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
            const auto Flushed = co_await FlushHttp2Frames(Value.Session, Value.Wire);
            if (!Flushed) co_return std::unexpected(Flushed.error());
        }
        co_return Http2ServerResult{};
    }

    auto Http2ServerFinisher::operator()(const std::int32_t StreamId) const
        -> Net::awaitable<Http2ServerResult>
    {
        return Run({Session, Wire, StreamId});
    }

    auto Http2ServerFinisher::Run(Http2ServerFinishRequest Value)
        -> Net::awaitable<Http2ServerResult>
    {
        const auto Status = Value.Session->SubmitData(Value.StreamId, {}, true);
        if (Status != H2::SubmitDataStatus::Accepted)
        {
            const auto Code = Status == H2::SubmitDataStatus::Closed
                ? Prism::Fault::Code::ConnectionAborted
                : Prism::Fault::Code::InvalidArgument;
            co_return std::unexpected(Prism::Fault::Failure{Code});
        }
        co_return co_await FlushHttp2Frames(Value.Session, Value.Wire);
    }

    auto Http2Accept::Run(Prism::Contract::InboundAdmission &Admission)
        -> Net::awaitable<std::expected<Http2Accepted, Prism::Fault::Failure>>
    {
        if (!Binding_ || !Bytes_)
        {
            co_return std::unexpected(co_await Admission.Retire(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument}));
        }
        auto Handshake = co_await Prism::Transport::Encrypted::SslHandshake(
            {std::move(Raw_), SslContext_,
             std::chrono::steady_clock::now() + Prism::Transport::Encrypted::DefaultHandshakeTimeout,
             std::move(Bytes_)});
        if (Handshake.Failure.Failed() || !Handshake.Stream)
        {
            const auto Failure = co_await RetireHttp2HandshakeFailure(
                Admission, std::move(Handshake));
            co_return std::unexpected(Failure);
        }
        auto Encrypted = std::make_shared<Prism::Transport::Encrypted>(
            std::move(Handshake.Stream), std::move(Handshake.Bytes));
        const auto Tracked = Admission.Track(
            std::static_pointer_cast<Prism::Transmission>(Encrypted));
        if (!Tracked)
        {
            Prism::Contract::ProtocolDataPlane Plane;
            Plane.Root = Prism::Contract::StreamDataPlane{Encrypted, {}};
            const auto Rejected = co_await Admission.Reject(
                std::move(Plane), Tracked.error());
            co_return std::unexpected(Rejected.error());
        }
        const auto Prepared = co_await PrepareServerDriver(
            Encrypted, Admission, std::move(Binding_));
        if (!Prepared) co_return std::unexpected(Prepared.error());
        const auto Driver = *Prepared;
        const auto Owner = Driver->Carrier;
        const auto Ready = Driver->Ready;
        const auto Target = Driver->Target;
        Http2ServerResult ReadyResult;
        Prism::Fault::Failure ReadyException;
        try
        {
            ReadyResult = co_await WaitHttp2ServerReady(
                Ready, Encrypted->Executor());
        }
        catch (...)
        {
            ReadyException = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
        }
        if (ReadyException.Failed())
            co_return std::unexpected(co_await RetireServerFailure(
                Admission, Owner, ReadyException));
        if (!ReadyResult)
        {
            co_return std::unexpected(co_await RetireServerFailure(
                Admission, Owner, ReadyResult.error()));
        }
        auto Accepted = AuthenticatedTransport::CreateForHandshake(Owner, *Target);
        if (!Accepted)
            co_return std::unexpected(co_await RetireServerFailure(
                Admission, Owner,
                Prism::Fault::Failure{Prism::Fault::Code::ProtocolError}));
        Admission.Release();
        co_return Http2Accepted{*Target, std::move(Accepted)};
    }

    auto Http2Accept::RetireServerFailure(
        Prism::Contract::InboundAdmission &Admission,
        const std::shared_ptr<CarrierOwner> &Owner,
        Prism::Fault::Failure Cause)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        Owner->Lifecycle->RecordFailure(Cause);
        const auto Drained = co_await Owner->Drain();
        if (Owner->IsRetired())
        {
            Admission.Release();
            const auto First = Owner->Lifecycle->Failure();
            if (First.Failed()) co_return First;
            co_return Cause;
        }

        auto AdmissionCause = Cause;
        if (AdmissionCause.Succeeded() && !Drained)
            AdmissionCause = Drained.error();
        const auto Inbound = co_await Admission.Retire(AdmissionCause);
        const auto First = Owner->Lifecycle->Failure();
        if (First.Failed()) co_return First;
        if (!Drained) co_return Drained.error();
        co_return Inbound;
    }

    auto Http2Accept::PrepareServerDriver(
        std::shared_ptr<Prism::Transport::Encrypted> Encrypted,
        Prism::Contract::InboundAdmission &Admission,
        SharedWireAuthBinding Binding)
        -> Net::awaitable<std::expected<
            std::shared_ptr<Http2DriverParameters>, Prism::Fault::Failure>>
    {
        auto Session = std::make_shared<H2::Session>(Encrypted->Executor(), true);
        auto Wire = MakeHttp2Wire(Encrypted);
        auto Ready = std::make_shared<Http2ReadyChannel>(Encrypted->Executor(), 1);
        auto Target = std::make_shared<std::string>();
        auto Transport = std::make_shared<Http2Transport>(Http2Transport::Options{
            .Executor = Encrypted->Executor(),
            .Write = Http2ServerDataWriter{Session, Wire},
            .Finish = Http2ServerFinisher{Session, Wire},
            .Close = Http2Transport::CloseCb{}});
        auto Lifecycle = std::make_shared<CarrierLifecycle>(Encrypted->Executor());
        auto Owner = std::make_shared<CarrierOwner>(CarrierOwnerLayers{
            Transport, Wire, Encrypted, Lifecycle, Binding});
        Lifecycle->Transport = Transport;
        auto Driver = std::make_shared<Http2DriverParameters>(Http2DriverParameters{
            Session, Wire, Transport, Encrypted, Ready, Target, std::move(Binding),
            Lifecycle, Owner});
        Lifecycle->DriverState = Driver;
        const std::weak_ptr<Http2DriverParameters> WeakDriver = Driver;
        Session->OnHeaders = [WeakDriver](
            std::int32_t StreamId, const H2::HeaderList &Headers, bool)
        {
            if (const auto Value = WeakDriver.lock())
                Http2Accept::HandleHeaders(*Value, StreamId, Headers);
        };
        Session->OnData = [WeakDriver](
            std::int32_t StreamId, std::span<const std::byte> Data)
        {
            if (const auto Value = WeakDriver.lock())
                Http2Accept::HandleData(*Value, StreamId, Data);
        };
        Session->OnStreamClose = [WeakDriver](
            const Prism::Http2::StreamReceiveClosure &Closure)
        {
            if (const auto Value = WeakDriver.lock())
                Http2Accept::HandleStreamClose(*Value, Closure);
        };

        Session->SendSettings();
        Http2ServerResult SettingsFlushed;
        Prism::Fault::Failure SettingsException;
        try
        {
            SettingsFlushed = co_await FlushHttp2Frames(Session, Wire);
        }
        catch (...)
        {
            SettingsException = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
        }
        if (SettingsException.Failed())
            co_return std::unexpected(co_await RetireServerFailure(
                Admission, Owner, SettingsException));
        if (!SettingsFlushed)
            co_return std::unexpected(co_await RetireServerFailure(
                Admission, Owner, SettingsFlushed.error()));

        const auto DriverStart = StartDriver(Driver);
        if (DriverStart.Failed())
            co_return std::unexpected(co_await RetireServerFailure(
                Admission, Owner, DriverStart));
        co_return Driver;
    }

    auto Http2Accept::HandleHeaders(Http2DriverParameters &Parameters, std::int32_t StreamId,
                              const H2::HeaderList &Headers) -> void
    {
        if (Parameters.Transport->StreamId_ >= 0)
        {
            return;
        }
        bool IsConnect = false;
        std::string_view Authority;
        std::string_view Authorization;
        for (const auto &Header : Headers)
        {
            if (Header.Name == ":method" && Header.Value == "CONNECT")
            {
                IsConnect = true;
            }
            else if (Header.Name == ":authority")
            {
                Authority = Header.Value;
            }
            else if (Header.Name == "proxy-authorization")
            {
                Authorization = Header.Value;
            }
        }
        Prism::Fault::Failure Failure;
        const char *Status = nullptr;
        if (!IsConnect || Authority.empty())
        {
            Failure = {Prism::Fault::Code::BadMessage};
            Status = "400";
        }
        else if (!VerifyBasicAuth(
                     Authorization, Parameters.Binding->Configuration.username,
                     Parameters.Binding->Configuration.password))
        {
            Failure = {Prism::Fault::Code::AuthFailed};
            Status = "407";
        }
        if (Failure.Failed())
        {
            const auto HeaderResult = Parameters.Session->SubmitHeaders(
                StreamId, {{":status", Status}}, true);
            if (!HeaderResult)
            {
                Failure = HeaderResult.error();
                Parameters.Lifecycle->RecordFailure(Failure);
            }
            Parameters.PendingReady = std::unexpected(Failure);
            return;
        }
        *Parameters.Target = std::string(Authority);
        Parameters.Transport->SetAuthority(*Parameters.Target);
        Parameters.Transport->BindStream(StreamId);
        const auto HeaderResult = Parameters.Session->SubmitHeaders(
            StreamId, {{":status", "200"}}, false);
        if (!HeaderResult)
        {
            const auto Failure = HeaderResult.error();
            Parameters.Lifecycle->RecordFailure(Failure);
            Parameters.PendingReady = std::unexpected(Failure);
            return;
        }
        Parameters.PendingReady = Http2ServerResult{};
    }

    auto Http2Accept::PublishReady(Http2DriverParameters &Parameters, Http2ServerResult Result)
        -> void
    {
        if (Parameters.ReadyPublished) return;
        Parameters.ReadyPublished = true;
        const auto Sent = Parameters.Ready->try_send(
            boost::system::error_code{}, std::move(Result));
        if (!Sent)
        {
            Parameters.Lifecycle->RecordFailure(
                Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
    }

    auto Http2Accept::PublishPendingReady(Http2DriverParameters &Parameters) -> void
    {
        if (!Parameters.PendingReady || Parameters.ReadyPublished) return;
        auto Result = std::move(*Parameters.PendingReady);
        Parameters.PendingReady.reset();
        PublishReady(Parameters, std::move(Result));
    }

    auto Http2Accept::HandleData(Http2DriverParameters &Parameters, std::int32_t StreamId,
                           std::span<const std::byte> Data) -> void
    {
        if (StreamId == Parameters.Transport->StreamId_)
        {
            Parameters.Transport->Push(Data);
        }
    }

    auto Http2Accept::HandleStreamClose(
        Http2DriverParameters &Parameters,
        const Prism::Http2::StreamReceiveClosure &Closure) -> void
    {
        if (Closure.StreamId == Parameters.Transport->StreamId_)
        {
            if (Closure.Kind == H2::StreamReceiveClosureKind::Reset)
            {
                auto Code = Prism::Fault::Code::ProtocolError;
                if (Closure.ErrorCode == H2::ErrorNoError)
                {
                    Code = Prism::Fault::Code::ConnectionReset;
                }
                const Prism::Fault::Failure Failure{Code};
                Parameters.Lifecycle->RecordFailure(Failure);
                Parameters.Transport->NotifyError(Failure);
            }
            else
            {
                Parameters.Transport->NotifyEof();
            }
        }
    }

    auto Http2Accept::FinishDriver(
        const std::shared_ptr<Http2DriverParameters> &Driver,
        const Prism::Fault::Failure FailureValue) -> void
    {
        if (!Driver)
        {
            return;
        }
        const bool LocalClose =
            Driver->Lifecycle && Driver->Lifecycle->IsLocalCloseCancellation(FailureValue);
        const bool CleanTeardown = Driver->Transport &&
            Driver->Transport->ExchangeComplete() &&
            CarrierLifecycle::IsTeardownFailure(FailureValue);
        const auto Failure = (LocalClose || CleanTeardown)
            ? Prism::Fault::Failure{} : FailureValue;
        const bool KeepWriteSide = Failure.Code == Prism::Fault::Code::Eof &&
            Driver->Transport &&
            Driver->Transport->ReadHalfClosed();
        if (Driver->Lifecycle) Driver->Lifecycle->RecordFailure(Failure);
        if (Driver->Session)
        {
            Driver->Session->OnHeaders = {};
            Driver->Session->OnData = {};
            Driver->Session->OnStreamClose = {};
        }
        if (Driver->Transport)
        {
            if (LocalClose)
                Driver->Transport->NotifyEof();
            else if (Failure.Failed())
                Driver->Transport->NotifyError(Failure);
            else
                Driver->Transport->NotifyEof();
            if (!Driver->Transport->DrainTerminalPending())
            {
                const auto Closed = Driver->Transport->Close();
                if (!Closed && Driver->Lifecycle)
                    Driver->Lifecycle->RecordFailure(Closed.error());
            }
        }
        // 原始读 EOF 只结束 peer 写方向；保留 wire/TLS 供上层写完反向响应。
        if (!KeepWriteSide && Driver->Wire)
        {
            Driver->Wire->Close();
        }
        if (!KeepWriteSide && Driver->Encrypted)
        {
            const auto Closed = Driver->Encrypted->Close();
            if (!Closed && Driver->Lifecycle)
                Driver->Lifecycle->RecordFailure(Closed.error());
        }
        PublishPendingReady(*Driver);
        if (Driver->Ready && !Driver->ReadyPublished)
        {
            auto ReadyFailure = Failure;
            if (ReadyFailure.Succeeded())
                ReadyFailure = {Prism::Fault::Code::Eof};
            PublishReady(*Driver, std::unexpected(ReadyFailure));
        }
        Driver->Binding.reset();
        Driver->Target.reset();
        Driver->Ready.reset();
        Driver->Lifecycle.reset();
        Driver->Transport.reset();
        Driver->Wire.reset();
        Driver->Session.reset();
        Driver->Encrypted.reset();
    }

    auto Http2Accept::DriverCompletion::operator()(std::exception_ptr Exception) -> void
    {
        if (Exception && Driver)
        {
            const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::move(Exception));
            if (Lifecycle) Lifecycle->RecordFailure(Failure);
            Http2Accept::FinishDriver(Driver, Failure);
        }
        Driver.reset();
        if (Lifecycle) Lifecycle->CompleteDriver();
    }

    auto Http2Accept::StartDriver(const std::shared_ptr<Http2DriverParameters> &Driver)
        -> Prism::Fault::Failure
    {
        if (!Driver || !Driver->Encrypted)
        {
            return {Prism::Fault::Code::InvalidArgument};
        }
        const auto Lifecycle = Driver->Lifecycle;
        if (Lifecycle) Lifecycle->StartDriver();
        auto CompletionDriver = Driver;
        try
        {
            Net::co_spawn(
                Driver->Encrypted->Executor(), RunDriver(Driver),
                DriverCompletion{Lifecycle, std::move(CompletionDriver)});
        }
        catch (...)
        {
            const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
            if (Lifecycle) Lifecycle->RecordFailure(Failure);
            FinishDriver(Driver, Failure);
            if (Lifecycle) Lifecycle->CompleteDriver();
            return Failure;
        }
        return {};
    }

    auto Http2Accept::RunDriver(std::shared_ptr<Http2DriverParameters> Driver)
        -> Net::awaitable<void>
    {
        std::array<std::byte, 16384> Buffer{};
        Prism::Fault::Failure Failure;
        while (true)
        {
            const auto Part = co_await Driver->Encrypted->ReadSome(Buffer);
            const auto Step = co_await ProcessHttp2ReadCompletion(
                Http2ReadCompletion{std::span<const std::byte>(Buffer), Part},
                Driver->Session, Driver->Wire);
            PublishPendingReady(*Driver);
            if (Step.Terminal)
            {
                const bool LocalClose =
                    Driver->Lifecycle &&
                    Driver->Lifecycle->IsLocalCloseCancellation(Step.Failure);
                const bool CleanTeardown = Driver->Transport &&
                    Driver->Transport->ExchangeComplete() &&
                    CarrierLifecycle::IsTeardownFailure(Step.Failure);
                Failure = (LocalClose || CleanTeardown)
                    ? Prism::Fault::Failure{} : Step.Failure;
                if (Step.ReadTerminal)
                {
                    Driver->Transport->NotifyReadTerminal(
                        (LocalClose || CleanTeardown)
                            ? Prism::Fault::Failure{Prism::Fault::Code::Eof} : Failure);
                }
                break;
            }
        }
        FinishDriver(Driver, Failure);
    }
} // namespace Prism::Trusttunnel::Detail

namespace Prism::Trusttunnel
{
    auto AcceptHttp2(Http2AcceptRequest Request)
        -> Net::awaitable<std::expected<Http2Accepted, Prism::Fault::Failure>>
    {
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Request.Raw);
        if (!Prepared)
        {
            co_return std::unexpected(Prepared.error());
        }
        auto Admission = std::move(*Prepared);
        std::optional<std::expected<Http2Accepted, Prism::Fault::Failure>> Result;
        std::exception_ptr Exception;
        try
        {
            auto Handler = std::make_shared<Detail::Http2Accept>(std::move(Request));
            Result.emplace(co_await Handler->Run(Admission));
        }
        catch (...)
        {
            Exception = std::current_exception();
        }
        if (Exception)
        {
            const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::move(Exception));
            co_return std::unexpected(co_await Admission.Retire(Failure));
        }
        co_return std::move(*Result);
    }
}
