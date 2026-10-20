/** @file Runtime/Recognition/Detail/RecognitionConfig.hpp @brief 识别控制协调器的私有协程与清理实现。 */
#pragma once

#include <Prism/Runtime/Recognition/RecognitionConfig.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <exception>
#include <memory>
#include <optional>
#include <utility>
#include <variant>

namespace Prism::Recognition
{
    namespace detail
    {

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

        [[nodiscard]] auto IsCancellationError(const std::error_code& Error) noexcept -> bool;

        template <typename Result>
        inline auto NormalizeCandidateStatus(Result& Candidate) -> void
        {
            if (IsCancellationError(Candidate.Error))
            {
                Candidate.Status = RecognitionStatus::IoError;
            }
        }

        [[nodiscard]] auto WaitUntil(RecognitionControl::Clock::time_point Deadline)
            -> Net::awaitable<RecognitionControlEvent>;

        [[nodiscard]] auto WaitForControl(Net::awaitable<RecognitionControlEvent> Wait,
            RecognitionControl::CancelFn Cancel, std::shared_ptr<ControlInvocationState> State)
            -> Net::awaitable<RecognitionControlEvent>;

        [[nodiscard]] auto WaitForControlSource(RecognitionControl::WaitFn Caller,
            RecognitionControl::Clock::time_point Deadline) -> Net::awaitable<RecognitionControlEvent>;

        auto RequestTransportCleanup(SharedTransmission Transport) -> std::exception_ptr;
        auto CleanupTransport(SharedTransmission Transport) -> Net::awaitable<std::exception_ptr>;

        template <typename T>
        auto CleanupOperationValue(T& Value) -> Net::awaitable<std::exception_ptr>;

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
                    const auto ValueFailure = co_await CleanupOperationValue(*State->Value);
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

        auto InvokeCancel(const RecognitionControl& Control) -> void;

        template <typename T>
        auto CleanupOperationValue(T& Value) -> Net::awaitable<std::exception_ptr>
        {
            if constexpr (requires { Value.Transport; })
            {
                co_return co_await CleanupTransport(std::move(Value.Transport));
            }
            co_return std::exception_ptr{};
        }

        [[nodiscard]] auto ContainsTransport(const SharedTransmission& Outer,
            const SharedTransmission& Target) noexcept -> bool;

        struct CleanupTransportsRequest
        {
            SharedTransmission Returned;
            SharedTransmission Inbound;
        };

        auto CleanupTransports(CleanupTransportsRequest Request)
            -> Net::awaitable<std::exception_ptr>;

        auto RethrowCleanupFailure(std::exception_ptr Failure) -> void;

        struct ArmedCancellation final
        {
            RecognitionControl::CancelFn Cancel;
            SharedTransmission Inbound;

            auto operator()() -> void;
        };

        auto ArmCancellation(RecognitionControl::CancelFn Cancel,
            const SharedTransmission& Inbound) -> RecognitionControl::CancelFn;

        auto ArmControl(RecognitionControl& Control, const SharedTransmission& Inbound,
            RecognitionControl::Clock::time_point Deadline) -> bool;


        auto SetResultStatus(ResultStatusRequest Request) -> void;

        auto SetControlStatus(RecognizeResult& Result, RecognitionControlEvent Event) -> void;

    } // namespace detail
} // namespace Prism::Recognition
