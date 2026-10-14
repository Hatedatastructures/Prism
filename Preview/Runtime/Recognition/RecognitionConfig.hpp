/**
 * @file RecognitionConfig.hpp
 * @brief Recognition control, result, and transport cleanup contracts.
 */

#pragma once

#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Runtime/Recognition/Profile.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace Preview::Recognition
{

    namespace Net = boost::asio;

    /**
     * @enum RecognitionControlEvent
     * @brief Caller-owned asynchronous recognition stop event.
     */
    enum class RecognitionControlEvent : std::uint8_t
    {
        Cancelled,
        TimedOut,
    };

    struct RecognizeResult;

    /**
     * @struct RecognitionControl
     * @brief Caller-owned cancellation and total-deadline checks.
     * @details The coordinator computes one effective total deadline and uses
     *          a fresh internal timer for each in-flight operation without
     *          resetting that deadline per candidate. A caller that owns a
     *          timer can expose its state via Cancelled and Deadline. Wait must
     *          be a repeatable factory; WaitCancellationSafe declares that the
     *          factory cooperates with CancelTransport so every losing race can
     *          complete.
     */
    struct RecognitionControl
    {
        using Clock = std::chrono::steady_clock;
        using WaitFn = std::function<Net::awaitable<RecognitionControlEvent>()>;
        using CancelFn = std::function<void()>;

        Clock::time_point Deadline{Clock::time_point::max()};
        std::function<bool()> Cancelled{};
        WaitFn Wait{};
        CancelFn CancelTransport{};
        // Wait 必须可重复创建，并能在取消钩子触发后收口。
        bool WaitCancellationSafe{false};

        [[nodiscard]] auto IsCancelled() const -> bool
        {
            return Cancelled && Cancelled();
        }

        [[nodiscard]] auto IsExpired(Clock::time_point Now = Clock::now()) const noexcept -> bool
        {
            return Deadline != Clock::time_point::max() && Now >= Deadline;
        }
    };

    struct ControlRaceRequest
    {
        RecognitionControl Control;
        RecognitionControl::Clock::time_point Deadline{RecognitionControl::Clock::time_point::max()};
    };

    namespace detail
    {

        template <typename T>
        struct ControlRaceResult
        {
            T Value{};
            RecognitionControlEvent Event{RecognitionControlEvent::Cancelled};
            bool Controlled{false};
        };

        template <typename T>
        struct OperationState
        {
            explicit OperationState(Net::any_io_executor Executor)
                : Completion(Executor, 1), Joined(std::move(Executor), 1)
            {
            }

            std::optional<T> Value;
            std::exception_ptr Failure;
            Net::experimental::channel<void(boost::system::error_code)> Completion;
            Net::experimental::channel<void(boost::system::error_code)> Joined;
        };

        struct ControlInvocationState final
        {
            bool Invoked{false};
            std::exception_ptr Failure;
        };

        template <typename T>
        auto RunOperation(Net::awaitable<T> Operation, std::shared_ptr<OperationState<T>> State)
            -> Net::awaitable<void>
        {
            try
            {
                State->Value = co_await std::move(Operation);
            }
            catch (...)
            {
                State->Failure = std::current_exception();
            }
            (void)State->Completion.try_send(boost::system::error_code{});
            (void)State->Joined.try_send(boost::system::error_code{});
        }

        template <typename T>
        auto JoinOperation(std::shared_ptr<OperationState<T>> State) -> Net::awaitable<void>
        {
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            (void)co_await State->Joined.async_receive(Net::use_awaitable);
        }

        [[nodiscard]] inline auto IsCancellationError(const std::error_code& Error) noexcept -> bool
        {
            return Error == std::make_error_code(std::errc::operation_canceled) ||
                Preview::Fault::ToCode(Error) == Preview::Fault::Code::Canceled;
        }

        template <typename Result>
        inline auto NormalizeCandidateStatus(Result& Candidate) -> void
        {
            if (IsCancellationError(Candidate.Error))
            {
                Candidate.Status = RecognitionStatus::IoError;
            }
        }

        [[nodiscard]] inline auto WaitUntil(RecognitionControl::Clock::time_point Deadline)
            -> Net::awaitable<RecognitionControlEvent>
        {
            const auto Executor = co_await Net::this_coro::executor;
            Net::steady_timer Timer(Executor);
            Timer.expires_at(Deadline);
            co_await Timer.async_wait(Net::use_awaitable);
            co_return RecognitionControlEvent::TimedOut;
        }

        [[nodiscard]] inline auto WaitForControl(Net::awaitable<RecognitionControlEvent> Wait,
            RecognitionControl::CancelFn Cancel, std::shared_ptr<ControlInvocationState> State)
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

        [[nodiscard]] inline auto WaitForControlSource(RecognitionControl::WaitFn Caller,
            RecognitionControl::Clock::time_point Deadline) -> Net::awaitable<RecognitionControlEvent>
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

        inline auto CleanupTransport(SharedTransmission Transport) -> std::exception_ptr;

        template <typename T>
        auto CleanupOperationValue(T& Value) -> std::exception_ptr;

        template <typename T>
        [[nodiscard]] auto AwaitWithControl(Net::awaitable<T> Operation, ControlRaceRequest Request)
            -> Net::awaitable<ControlRaceResult<T>>
        {
            ControlRaceResult<T> Result;
            if (!Request.Control.Wait && Request.Deadline == RecognitionControl::Clock::time_point::max())
            {
                Result.Value = co_await std::move(Operation);
                co_return Result;
            }

            const auto Executor = co_await Net::this_coro::executor;
            auto State = std::make_shared<OperationState<T>>(Executor);
            Net::co_spawn(Executor, RunOperation(std::move(Operation), State), Net::detached);
            auto ControlState = std::make_shared<ControlInvocationState>();
            auto Source = WaitForControlSource(Request.Control.Wait, Request.Deadline);
            auto Wait = WaitForControl(std::move(Source), Request.Control.CancelTransport, ControlState);
            using Net::experimental::awaitable_operators::operator||;
            bool OperationCompleted = false;
            bool RethrowAfterJoin = false;
            std::exception_ptr Failure;
            try
            {
                auto Race = co_await (State->Completion.async_receive(Net::use_awaitable) || std::move(Wait));
                if (Race.index() == 0)
                {
                    OperationCompleted = true;
                    // operator|| 等待首个成功分支；取消回调已失败时，迟到的 completion
                    // 仍会成功，必须保留此前的首个控制异常并先 join，不能返回成功值。
                    if (ControlState->Failure || State->Failure)
                    {
                        Failure = ControlState->Failure ? ControlState->Failure : State->Failure;
                        RethrowAfterJoin = true;
                    }
                    else
                    {
                        if (State->Value)
                        {
                            Result.Value = std::move(*State->Value);
                        }
                        co_return Result;
                    }
                }
                else
                {
                    Result.Event = std::get<1>(Race);
                    Result.Controlled = true;
                }
            }
            catch (...)
            {
                Failure = ControlState->Failure ? ControlState->Failure : std::current_exception();
                RethrowAfterJoin = true;
            }

            if (RethrowAfterJoin)
            {
                if (!OperationCompleted && !ControlState->Invoked && Request.Control.CancelTransport)
                {
                    ControlState->Invoked = true;
                    try
                    {
                        Request.Control.CancelTransport();
                    }
                    catch (...)
                    {
                        Failure = Failure ? Failure : std::current_exception();
                    }
                }
                std::exception_ptr JoinFailure;
                try
                {
                    co_await JoinOperation(State);
                }
                catch (...)
                {
                    JoinFailure = std::current_exception();
                }
                Failure = Failure ? Failure : JoinFailure;
                if (State->Value)
                {
                    const auto ValueFailure = CleanupOperationValue(*State->Value);
                    Failure = Failure ? Failure : ValueFailure;
                    State->Value.reset();
                }
                std::rethrow_exception(Failure);
            }

            co_await JoinOperation(State);
            if (State->Value)
            {
                Result.Value = std::move(*State->Value);
            }
            co_return Result;
        }

        inline auto InvokeCancel(const RecognitionControl& Control) -> void
        {
            if (Control.CancelTransport)
            {
                Control.CancelTransport();
            }
        }

        inline auto CleanupTransport(SharedTransmission Transport) -> std::exception_ptr
        {
            if (!Transport)
            {
                return {};
            }

            std::exception_ptr Failure;
            bool Open = true;
            try
            {
                Open = Transport->IsOpen();
            }
            catch (...)
            {
                Failure = std::current_exception();
            }
            if (!Open && !Failure)
            {
                return {};
            }
            try
            {
                Transport->Cancel();
            }
            catch (...)
            {
                Failure = Failure ? Failure : std::current_exception();
            }
            try
            {
                Transport->Close();
            }
            catch (...)
            {
                Failure = Failure ? Failure : std::current_exception();
            }
            return Failure;
        }

        template <typename T>
        auto CleanupOperationValue(T& Value) -> std::exception_ptr
        {
            if constexpr (requires { Value.Transport; })
            {
                return CleanupTransport(std::move(Value.Transport));
            }
            return {};
        }

        [[nodiscard]] inline auto ContainsTransport(const SharedTransmission& Outer,
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

        struct CleanupTransportsRequest
        {
            SharedTransmission Returned;
            SharedTransmission Inbound;
        };

        inline auto CleanupTransports(CleanupTransportsRequest Request) -> std::exception_ptr
        {
            const bool Aliased = Request.Returned && Request.Inbound &&
                (Request.Returned.get() == Request.Inbound.get() ||
                    ContainsTransport(Request.Returned, Request.Inbound) ||
                    ContainsTransport(Request.Inbound, Request.Returned));
            auto Failure = CleanupTransport(std::move(Request.Returned));
            if (!Aliased)
            {
                const auto InboundFailure = CleanupTransport(std::move(Request.Inbound));
                Failure = Failure ? Failure : InboundFailure;
            }
            return Failure;
        }

        inline auto RethrowCleanupFailure(std::exception_ptr Failure) -> void
        {
            if (Failure)
            {
                std::rethrow_exception(std::move(Failure));
            }
        }

        struct ArmedCancellation final
        {
            RecognitionControl::CancelFn Cancel;
            SharedTransmission Inbound;

            auto operator()() -> void
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
                const auto CleanupFailure = CleanupTransport(Inbound);
                Failure = Failure ? Failure : CleanupFailure;
                RethrowCleanupFailure(std::move(Failure));
            }
        };

        inline auto ArmCancellation(RecognitionControl::CancelFn Cancel,
            const SharedTransmission& Inbound) -> RecognitionControl::CancelFn
        {
            return ArmedCancellation{std::move(Cancel), Inbound};
        }

        inline auto ArmControl(RecognitionControl& Control, const SharedTransmission& Inbound,
            RecognitionControl::Clock::time_point Deadline) -> bool
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

    } // namespace detail

    /**
     * @struct RecognizeResult
     * @brief 已编译 Profile 的候选、载体和取消结果。
     * @details 识别结果由接入阶段消费，协议工厂随后产生唯一正式数据面。
     */
    struct RecognizeResult
    {
        Preview::Contract::ProtocolType detected{Preview::Contract::ProtocolType::Unknown};
        SharedTransmission transport;
        std::vector<std::byte> preread;
        std::string scheme;
        bool success{false};

        RecognitionMode Mode{RecognitionMode::Configured};
        RecognitionStatus Status{RecognitionStatus::NoMatch};
        CandidateId Candidate{InvalidCandidate};
        std::string CandidateName;
        std::error_code Error{};
        bool Polluted{false};
        bool Cancelled{false};
        std::size_t ProbeBytes{0};
        std::uint16_t CryptoTrials{0};
        Preview::Fault::Code FaultCode{Preview::Fault::Code::Success};
        boost::system::error_code NativeError{};
        CarrierMetadata Carrier{};
    };

    struct ResultStatusRequest
    {
        RecognizeResult* Result{nullptr};
        RecognitionStatus Status{RecognitionStatus::NoMatch};
        std::error_code Error{};
        bool Polluted{false};
    };

    namespace detail
    {

        inline auto SetResultStatus(ResultStatusRequest Request) -> void
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

        inline auto SetControlStatus(RecognizeResult& Result, RecognitionControlEvent Event) -> void
        {
            if (Event == RecognitionControlEvent::Cancelled)
            {
                SetResultStatus(ResultStatusRequest{&Result, RecognitionStatus::IoError,
                    std::make_error_code(std::errc::operation_canceled)});
                Result.FaultCode = Preview::Fault::Code::Canceled;
                Result.Cancelled = true;
                return;
            }
            SetResultStatus(ResultStatusRequest{&Result, RecognitionStatus::TimedOut,
                std::make_error_code(std::errc::timed_out)});
            Result.FaultCode = Preview::Fault::Code::Timeout;
        }

    } // namespace detail

} // namespace Preview::Recognition
