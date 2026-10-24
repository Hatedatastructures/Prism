/** @file RecognitionConfig.cpp @brief 识别控制与清理辅助实现。 */
#include <Prism/Runtime/Recognition/Detail/RecognitionConfig.hpp>

#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <system_error>
#include <utility>

namespace Prism::Recognition::detail
{
    auto IsCancellationError(const std::error_code& Error) noexcept -> bool
    {
        return Error == std::make_error_code(std::errc::operation_canceled) ||
            Prism::Fault::ToCode(Error) == Prism::Fault::Code::Canceled;
    }

    auto WaitUntil(const RecognitionControl::Clock::time_point Deadline)
        -> Net::awaitable<RecognitionControlEvent>
    {
        const auto Executor = co_await Net::this_coro::executor;
        Net::steady_timer Timer(Executor);
        Timer.expires_at(Deadline);
        co_await Timer.async_wait(Net::use_awaitable);
        co_return RecognitionControlEvent::TimedOut;
    }

    auto WaitForControl(
        Net::awaitable<RecognitionControlEvent> Wait,
        RecognitionControl::CancelFn Cancel,
        std::shared_ptr<ControlInvocationState> State)
        -> Net::awaitable<RecognitionControlEvent>
    {
        const auto Event = co_await std::move(Wait);
        if (Cancel)
        {
            State->Invoked = true;
            try
            {
                Cancel();
            }
            catch (...)
            {
                State->Failure = std::current_exception();
                throw;
            }
        }
        co_return Event;
    }

    auto WaitForControlSource(
        RecognitionControl::WaitFn Caller,
        const RecognitionControl::Clock::time_point Deadline)
        -> Net::awaitable<RecognitionControlEvent>
    {
        if (Caller && Deadline != RecognitionControl::Clock::time_point::max())
        {
            auto CallerWait = Caller();
            auto DeadlineWait = WaitUntil(Deadline);
            using Net::experimental::awaitable_operators::operator||;
            auto Race = co_await (std::move(CallerWait) || std::move(DeadlineWait));
            if (Race.index() == 0)
            {
                co_return std::get<0>(Race);
            }
            co_return std::get<1>(Race);
        }
        if (Caller)
        {
            co_return co_await Caller();
        }
        co_return co_await WaitUntil(Deadline);
    }

    namespace
    {
        auto CaptureCleanupFailure(std::exception_ptr& Failure,
            const Prism::Fault::Failure& Cause) -> void
        {
            if (Failure) return;
            try
            {
                throw std::system_error(Prism::Fault::ToNative(Cause));
            }
            catch (...)
            {
                Failure = std::current_exception();
            }
        }

        struct CleanupSubmission final
        {
            std::exception_ptr Failure;
            bool CloseAccepted{false};
            bool DrainRequired{false};
        };

        auto SubmitTransportCleanup(SharedTransmission Transport) -> CleanupSubmission
        {
            CleanupSubmission Result;
            if (!Transport) return Result;

            bool Open = true;
            try
            {
                Open = Transport->IsOpen();
            }
            catch (...)
            {
                Result.Failure = std::current_exception();
            }
            if (!Open && !Result.Failure)
            {
                Result.DrainRequired = true;
                return Result;
            }

            try
            {
                const auto Cancel = Transport->Cancel();
                if (!Cancel) CaptureCleanupFailure(Result.Failure, Cancel.error());
            }
            catch (...)
            {
                if (!Result.Failure) Result.Failure = std::current_exception();
            }
            try
            {
                const auto Close = Transport->Close();
                Result.CloseAccepted = static_cast<bool>(Close);
                Result.DrainRequired = Result.CloseAccepted;
                if (!Close) CaptureCleanupFailure(Result.Failure, Close.error());
            }
            catch (...)
            {
                if (!Result.Failure) Result.Failure = std::current_exception();
            }
            return Result;
        }
    }

    auto RequestTransportCleanup(SharedTransmission Transport) -> std::exception_ptr
    {
        return SubmitTransportCleanup(std::move(Transport)).Failure;
    }

    auto CleanupTransport(SharedTransmission Transport) -> Net::awaitable<std::exception_ptr>
    {
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        auto Submission = SubmitTransportCleanup(Transport);
        if (!Transport || !Submission.DrainRequired)
        {
            co_return Submission.Failure;
        }

        const auto Activity = Transport->Activity();
        if (!Activity)
        {
            CaptureCleanupFailure(Submission.Failure,
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            co_return Submission.Failure;
        }

        try
        {
            const auto Drained = co_await Activity->Drain();
            if (!Drained) CaptureCleanupFailure(Submission.Failure, Drained.error());
        }
        catch (...)
        {
            if (!Submission.Failure) Submission.Failure = std::current_exception();
        }
        co_return Submission.Failure;
    }

    auto InvokeCancel(const RecognitionControl& Control) -> void
    {
        if (Control.CancelTransport)
        {
            Control.CancelTransport();
        }
    }

    auto ContainsTransport(
        const SharedTransmission& Outer,
        const SharedTransmission& Target) noexcept -> bool
    {
        if (!Outer || !Target)
        {
            return false;
        }
        auto* Current = Outer.get();
        while (Current)
        {
            if (Current == Target.get())
            {
                return true;
            }
            // 本段在入站 executor 同步遍历，借用不跨挂起或最终退休。
            Current = Current->NextLayer();
        }
        return false;
    }

    auto CleanupTransports(CleanupTransportsRequest Request)
        -> Net::awaitable<std::exception_ptr>
    {
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        const bool Aliased = Request.Returned && Request.Inbound &&
            (Request.Returned.get() == Request.Inbound.get() ||
                ContainsTransport(Request.Returned, Request.Inbound) ||
                ContainsTransport(Request.Inbound, Request.Returned));
        auto Failure = co_await CleanupTransport(std::move(Request.Returned));
        if (!Aliased)
        {
            const auto InboundFailure = co_await CleanupTransport(std::move(Request.Inbound));
            Failure = Failure ? Failure : InboundFailure;
        }
        co_return Failure;
    }

    auto RethrowCleanupFailure(std::exception_ptr Failure) -> void
    {
        if (Failure)
        {
            std::rethrow_exception(std::move(Failure));
        }
    }

    auto ArmedCancellation::operator()() -> void
    {
        std::exception_ptr Failure;
        if (Cancel)
        {
            try
            {
                Cancel();
            }
            catch (...)
            {
                Failure = std::current_exception();
            }
        }
        const auto CleanupFailure = RequestTransportCleanup(Inbound);
        Failure = Failure ? Failure : CleanupFailure;
        RethrowCleanupFailure(std::move(Failure));
    }

    auto ArmCancellation(
        RecognitionControl::CancelFn Cancel,
        const SharedTransmission& Inbound) -> RecognitionControl::CancelFn
    {
        return ArmedCancellation{std::move(Cancel), Inbound};
    }

    auto ArmControl(
        RecognitionControl& Control,
        const SharedTransmission& Inbound,
        const RecognitionControl::Clock::time_point Deadline) -> bool
    {
        Control.Deadline = Deadline;
        if (Control.Wait && (!Control.WaitCancellationSafe || !Control.CancelTransport))
        {
            return false;
        }
        if (Control.Cancelled && !Control.Wait && !Control.IsCancelled())
        {
            return false;
        }
        if (Control.CancelTransport)
        {
            Control.CancelTransport = ArmCancellation(std::move(Control.CancelTransport), Inbound);
        }
        else if (!Control.Wait || Deadline != RecognitionControl::Clock::time_point::max())
        {
            Control.CancelTransport = ArmCancellation({}, Inbound);
        }
        return true;
    }

    auto SetResultStatus(ResultStatusRequest Request) -> void
    {
        auto& Result = *Request.Result;
        const auto Status = Request.Status;
        const auto& Error = Request.Error;
        const auto Polluted = Request.Polluted;
        Result.Status = Status;
        Result.Error = Error;
        Result.Polluted = Result.Polluted || Polluted || Status == RecognitionStatus::Polluted;
        if (IsCancellationError(Error))
        {
            Result.Status = RecognitionStatus::IoError;
            Result.Cancelled = true;
        }
        Result.success = Result.Status == RecognitionStatus::Accepted && !Result.Polluted;
    }

    auto SetControlStatus(RecognizeResult& Result, const RecognitionControlEvent Event) -> void
    {
        if (Event == RecognitionControlEvent::Cancelled)
        {
            SetResultStatus(ResultStatusRequest{&Result, RecognitionStatus::IoError,
                std::make_error_code(std::errc::operation_canceled)});
            Result.FaultCode = Prism::Fault::Code::Canceled;
            Result.Cancelled = true;
            return;
        }
        SetResultStatus(ResultStatusRequest{&Result, RecognitionStatus::TimedOut,
            std::make_error_code(std::errc::timed_out)});
        Result.FaultCode = Prism::Fault::Code::Timeout;
    }
}
