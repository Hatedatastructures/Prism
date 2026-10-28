/**
 * @file Session.cpp
 * @brief 会话编排与 admission/relay 生命周期。
 */
#include <Prism/Runtime/Session.hpp>

#include <Prism/Account/Authenticator.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>
#include <Prism/Foundation/Utility/Diagnose/FieldKey.hpp>
#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <Prism/Lifecycle/Task/State.hpp>
#include <Prism/Runtime/ActiveTransports.hpp>
#include <Prism/Runtime/Middleware/Builtin/Dial.hpp>
#include <Prism/Runtime/Middleware/Builtin/Pad.hpp>
#include <Prism/Runtime/Middleware/Builtin/Relay.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Runtime/Middleware/Pipeline.hpp>
#include <Prism/Runtime/Recognition/Recognition.hpp>
#include <Prism/Runtime/Session/Control.hpp>
#include <Prism/Runtime/Session/Services.hpp>
#include <Prism/Runtime/Session/Trace/Ring.hpp>
#include <Prism/Runtime/CarrierDomain.hpp>
#include <Prism/Runtime/Session/ClosePolicy.hpp>
#include <Prism/Runtime/Session/DataPlaneRelay.hpp>
#include <Prism/Runtime/Session/RecognitionAdmission.hpp>
#include <Prism/Runtime/Session/RecognitionLogging.hpp>
#include <Prism/Runtime/Session/RunContext.hpp>
#include <Prism/Transport/NativeTls.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <algorithm>
#include <chrono>
#include <exception>
#include <format>
#include <new>
#include <system_error>
#include <utility>
#include <variant>

namespace Prism::Runtime::Detail
{
    RecognitionLatencyScope::RecognitionLatencyScope(
        std::shared_ptr<Prism::Foundation::RecognitionLatencySink> Sink,
        Prism::Foundation::RecognitionLatencySample Sample) noexcept
        : Sink_(std::move(Sink)), Sample_(Sample)
    {
        if (Sink_) Started_ = Clock::now();
    }

    RecognitionLatencyScope::~RecognitionLatencyScope() noexcept
    {
        if (!Sink_) return;
        const auto Elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            Clock::now() - Started_).count();
        Sample_.DurationMicroseconds = Elapsed > 0 ? static_cast<std::uint64_t>(Elapsed) : 0U;
        Sink_->ReportRecognitionLatency(Sample_);
    }
}

namespace Prism::Runtime
{
    using SessionLogState = SessionSupport::SessionLogState;

    auto SessionRunContext::ReleaseCarrierViews() noexcept -> void
    {
        Inbound.reset();
        Recognition.transport.reset();
        Context.Outbound.reset();
        Context.DataPlane.PostDial = {};
        std::visit([](auto& Root) { Root.Transport.reset(); }, Context.DataPlane.Root);
        if (auto* Datagram = Context.DataPlane.Datagram()) Datagram->Session.reset();
        if (auto* Mux = Context.DataPlane.Mux()) Mux->Session.reset();
    }

    Session::Session(SessionOptions Options)
        : Opts_(std::move(Options)), Services_(Opts_.Services), Control_(Opts_.Control),
          Active_(std::make_shared<ActiveTransports>())
    {
        if (!Control_) Control_ = std::make_shared<SessionControl>();
    }

    Session::~Session()
    {
        if (!Drained_.load(std::memory_order_acquire) && DeferredCleanup_)
            DeferredCleanup_->RequestRetirement();
    }

    auto Session::Control() const noexcept -> std::shared_ptr<SessionControl>
    {
        return Control_;
    }

    auto Session::Services() const noexcept -> SharedSessionServices
    {
        return Services_;
    }

    auto Session::SetGenerationUseLease(Prism::Foundation::GenerationUseLease Value) noexcept -> bool
    {
        if (!Value || GenerationUse_) return false;
        GenerationUse_ = std::move(Value);
        return true;
    }

    auto Session::SetDeferredCleanup(std::shared_ptr<Prism::Executor::ClosingResource> Value) -> void
    {
        DeferredCleanup_ = std::move(Value);
    }

    auto Session::SetRegistration(SessionRegistry::Registration Value) -> void
    {
        Registration_ = std::move(Value);
    }

    auto Session::SetTraceWriter(std::shared_ptr<SessionTraceWriter> Value) noexcept -> void
    {
        TraceWriter_ = std::move(Value);
    }

    auto Session::Cancel() -> std::expected<void, Prism::Fault::Failure>
    {
        return Control_->Cancel();
    }

    auto Session::Close() -> std::expected<void, Prism::Fault::Failure>
    {
        return Control_->CloseOnce();
    }

    auto Session::Run(Prism::SharedTransmission Inbound)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        Drained_.store(false, std::memory_order_release);
        if (TraceWriter_)
        {
            TraceWriter_->SetTaskIdentity(Control_->CurrentIdentity());
            TraceWriter_->Record(SessionTraceStage::SessionStarted);
        }
        co_await Net::this_coro::throw_if_cancelled(false);
        const auto LogState = std::make_shared<SessionLogState>();
        Prism::Fault::Failure Result;
        auto CancellationReasonAtRunCompletion = SessionCancellationReason::None;
        try
        {
            Result = co_await RunCore(std::move(Inbound), LogState);
            CancellationReasonAtRunCompletion = Control_->CancellationReason();
        }
        catch (const boost::system::system_error& Error)
        {
            Result = Prism::Fault::FromNative(static_cast<std::error_code>(Error.code()));
            CancellationReasonAtRunCompletion = Control_->CancellationReason();
        }
        catch (const std::system_error& Error)
        {
            Result = Prism::Fault::FromNative(Error.code());
            CancellationReasonAtRunCompletion = Control_->CancellationReason();
        }
        catch (const std::bad_alloc&)
        {
            Result = Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable,
                std::make_error_code(std::errc::not_enough_memory)};
            CancellationReasonAtRunCompletion = Control_->CancellationReason();
        }
        catch (...)
        {
            Result = Prism::Fault::Failure{Prism::Fault::Code::GenericError};
            CancellationReasonAtRunCompletion = Control_->CancellationReason();
        }
        LogState->FinalCode = Result.Code;
        const auto Closed = SessionClosePolicy::CloseAndLog({Control_, Active_, LogState});
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        const auto Delivered = co_await Control_->AwaitDelivery();
        using Net::experimental::awaitable_operators::operator&&;
        const auto [Retired, AdmissionRetirement] = co_await (
            Active_->Finalize() && DrainAdmissionOwner());
        if (!Closed)
        {
            RecordClosed(Closed.error());
            co_return Closed.error();
        }
        if (!Delivered)
        {
            RecordClosed(Delivered.error());
            co_return Delivered.error();
        }
        if (!Retired)
        {
            RecordClosed(Retired.error());
            co_return Retired.error();
        }
        if (AdmissionRetirement.Failed() && !Result.Failed())
        {
            RecordClosed(AdmissionRetirement);
            co_return AdmissionRetirement;
        }
        const auto ChildTasksDrained = co_await Control_->Drain();
        if (!ChildTasksDrained)
        {
            RecordClosed(ChildTasksDrained.error());
            co_return ChildTasksDrained.error();
        }
        Drained_.store(true, std::memory_order_release);
        const auto FinalCancellationReason = Control_->CancellationReason();
        const auto FinalResult = Result.Code == Prism::Fault::Code::Canceled &&
            CancellationReasonAtRunCompletion == SessionCancellationReason::Shutdown &&
            FinalCancellationReason == SessionCancellationReason::Shutdown
                ? Prism::Fault::Failure{}
                : Result;
        RecordClosed(FinalResult);
        co_return FinalResult;
    }

    auto Session::DrainAdmissionOwner() -> Net::awaitable<Prism::Fault::Failure>
    {
        auto Owner = std::move(AdmissionOwner_);
        if (!Owner) co_return Prism::Fault::Failure{};
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        try
        {
            const auto Drained = co_await Owner->Drain();
            if (!Drained) co_return Drained.error();
        }
        catch (...)
        {
            co_return Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
        }
        co_return Prism::Fault::Failure{};
    }

    auto Session::IsDrained() const noexcept -> bool
    {
        return Drained_.load(std::memory_order_acquire);
    }

    auto Session::RunCore(Prism::SharedTransmission Inbound,
        const std::shared_ptr<SessionSupport::SessionLogState>& LogState)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        Net::any_io_executor SessionExecutor;
        if (Inbound) SessionExecutor = Inbound->Executor();
        if (Inbound)
        {
            co_await Net::dispatch(SessionExecutor, Net::use_awaitable);
            (void)Control_->Bind(SessionExecutor);
        }
        if (!Inbound) co_return Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument};
        const auto Domain = CarrierDomain::Create(Inbound->Executor(), Inbound->Activity());
        if (!Domain) co_return Domain.error();
        auto Stored = Active_->StoreInbound(std::move(Inbound), *Domain);
        if (!Stored) co_return Stored.error();
        Inbound = std::move(*Stored);
        if (!Services_) co_return Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument};

        const auto RelayIdleTimeout = Services_->RelayIdleTimeout;
        const auto AcceptProtocol = Services_->AcceptProtocol;
        const auto Profile = Services_->Profile;
        const auto ResolveCandidate = Services_->ResolveCandidate;
        auto* Pad = Services_->Pad.get();
        const auto Dial = Services_->Dial;
        const auto Traffic = Services_->Traffic;
        const auto RecognitionLatency = Services_->RecognitionLatency;
        auto Trace = Services_->ProcessContext;
        const auto Identity = Control_->CurrentIdentity();
        if (TraceWriter_) TraceWriter_->SetTaskIdentity(Identity);
        if (Identity.WorkerId)
            Trace = Trace.With(Prism::Diagnose::Fields::Worker, Identity.WorkerId);
        if (Identity.SessionId)
            Trace = Trace.With(Prism::Diagnose::Fields::Session, Identity.SessionId);
        if (Identity.TaskId && (!Identity.SessionId ||
            Identity.TaskId.Value() != Identity.SessionId.Value()))
            Trace = Trace.With(Prism::Diagnose::Fields::Task, Identity.TaskId);
        if (Identity.Generation && Identity.Generation.Value() > 1U)
            Trace = Trace.With(Prism::Diagnose::Fields::Generation, Identity.Generation);
        LogState->Trace = Trace;

        auto Cancellation = std::make_shared<SessionCancellationChannel>(SessionExecutor, 1);
        SessionRunContext Run;
        Run.Services = Services_;
        Run.Registration = &Registration_;
        Run.Control = Control_;
        Run.TraceWriter = TraceWriter_;
        Run.Active = Active_;
        Run.LogState = LogState;
        Run.Cancellation = Cancellation;
        Run.Executor = SessionExecutor;
        Run.RelayIdleTimeout = RelayIdleTimeout;
        Run.AcceptProtocol = AcceptProtocol;
        Run.Profile = Profile;
        Run.ResolveCandidate = ResolveCandidate;
        Run.Pad = Pad;
        Run.Dial = Dial;
        Run.Traffic = Traffic;
        Run.RecognitionLatency = RecognitionLatency;
        Run.SourceIp = Opts_.SourceIp;
        Run.Inbound = std::move(Inbound);
        Run.Logger = SessionSupport::SessionLogWriter{LogState, Profile};
        Run.Context.FirstTransfer = TraceWriter_;
        const auto Installed = SessionClosePolicy::InstallCancelHook(
            SessionCancellationRequest{Control_, Active_, LogState, Cancellation, SessionExecutor});
        if (!Installed) co_return Installed.error();

        Prism::Fault::Failure AdmissionError;
        {
            Detail::RecognitionLatencyScope Measure(Run.RecognitionLatency,
                Prism::Foundation::RecognitionLatencySample{
                    .Generation = Identity.Generation,
                    .Worker = Identity.WorkerId,
                    .Session = Identity.SessionId});
            AdmissionError = co_await SessionRecognitionAdmission::Run(Run);
        }
        AdmissionOwner_ = std::move(Run.Context.DataPlane.AdmissionOwner);
        if (AdmissionError.Failed())
        {
            Run.ReleaseCarrierViews();
            co_return Prism::Fault::Failure{AdmissionError};
        }
        const auto RelayFailure = co_await SessionDataPlaneRelay::Run(Run);
        Run.ReleaseCarrierViews();
        co_return RelayFailure;
    }

    auto Session::RecordClosed(const Prism::Fault::Failure& Failure) noexcept -> void
    {
        if (TraceWriter_) TraceWriter_->Record(SessionTraceStage::SessionClosed, Failure.Code);
    }
}
