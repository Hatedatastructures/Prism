/**
 * @file BoundedOperation.hpp
 * @brief 应用停机阶段的有界 typed drain owner。
 * @details 同一关闭操作持有原控制 ContextOwner、串行 executor、deadline timer、取消信号与
 *          typed completion。timeout 只发出取消并返回未完成；在途协程和 context 由 completion
 *          handler 与失败运行时 owner 保持，不能把超时伪造成 drain 完成。
 */
#pragma once

#include <Prism/Application/Startup/Detail/RuntimeState.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include <chrono>
#include <exception>
#include <expected>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace Prism::Application::Shutdown::ShutdownOperation
{
    namespace Net = boost::asio;
    using DrainOutcome = std::expected<void, Prism::Fault::Failure>;

    enum class Signal : unsigned char
    {
        Operation,
        Deadline,
    };

    /** @brief 一次拥有型应用 drain、截止时间与原控制上下文。 */
    struct Request final
    {
        std::shared_ptr<Prism::Application::Application::RuntimeState> RuntimePin;
        std::chrono::steady_clock::time_point Deadline;
        Net::awaitable<DrainOutcome> Operation;
    };

    /** @brief 原操作是否真实完成及其正式 typed 结果。 */
    struct WaitResult final
    {
        bool Completed{false};
        DrainOutcome Outcome{};
    };

    /** @brief 持有所有定时器与回调使用的进程控制 context。 */
    struct State final
    {
        using SignalChannel = Net::experimental::channel<
            void(boost::system::error_code, Signal)>;

        State(std::shared_ptr<Prism::Application::Application::RuntimeState> RuntimeValue,
            const std::chrono::steady_clock::time_point DeadlineValue)
            : RuntimePin(std::move(RuntimeValue)), ContextPin(RuntimePin->ControlContext),
              Serial(ContextPin->Io.get_executor()), Timer(Serial), Events(Serial, 2),
              Deadline(DeadlineValue)
        {
        }

        std::shared_ptr<Prism::Application::Application::RuntimeState> RuntimePin;
        std::shared_ptr<Prism::Executor::ContextOwner> ContextPin;
        Net::strand<Net::any_io_executor> Serial;
        Net::steady_timer Timer;
        SignalChannel Events;
        Net::cancellation_signal Cancellation;
        std::chrono::steady_clock::time_point Deadline;
        DrainOutcome Outcome{};
        bool DeadlineFinished{false};
        bool OperationFinished{false};
        bool TimedOut{false};
        bool DeadlineCancelRequested{false};
    };

    /** @brief 只在尚无首因时记录 typed failure。 */
    inline auto RecordFailure(State &Owner, const Prism::Fault::Failure FailureValue) noexcept -> void
    {
        if (Owner.Outcome)
        {
            Owner.Outcome = std::unexpected(FailureValue);
        }
    }

    /** @brief 从异常边界保留原生 cause；其它不可恢复异常归类为 Blocked。 */
    [[nodiscard]] inline auto FailureFromException(const std::exception_ptr &ExceptionValue) noexcept
        -> Prism::Fault::Failure
    {
        if (!ExceptionValue)
        {
            return {Prism::Fault::Code::Blocked};
        }
        try
        {
            std::rethrow_exception(ExceptionValue);
        }
        catch (const boost::system::system_error &Error)
        {
            return Prism::Fault::FromNative(static_cast<std::error_code>(Error.code()));
        }
        catch (const std::system_error &Error)
        {
            return Prism::Fault::FromNative(Error.code());
        }
        catch (...)
        {
            return {Prism::Fault::Code::Blocked};
        }
    }

    /** @brief 首失败优先；同时把原异常交给当前 control context 的 fatal owner。 */
    inline auto RecordException(State &Owner, const std::exception_ptr ExceptionValue) noexcept -> void
    {
        RecordFailure(Owner, FailureFromException(ExceptionValue));
        Owner.ContextPin->Fatal->Publish(ExceptionValue);
    }

    /** @brief 保留 timer 的原 native error，并通知应用唯一 fatal owner。 */
    inline auto RecordNativeError(State &Owner, const boost::system::error_code Error) noexcept -> void
    {
        RecordFailure(Owner,
            Prism::Fault::FromNative(static_cast<std::error_code>(Error)));
        try
        {
            throw boost::system::system_error(Error);
        }
        catch (...)
        {
            Owner.ContextPin->Fatal->Publish(std::current_exception());
        }
    }

    /** @brief 保存内部 channel 交付错误，避免等待协程把丢失通知视作成功。 */
    inline auto RecordSignalFailure(State &Owner) noexcept -> void
    {
        RecordFailure(Owner, Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        try
        {
            throw std::runtime_error("关闭完成通知被拒绝");
        }
        catch (...)
        {
            Owner.ContextPin->Fatal->Publish(std::current_exception());
        }
    }

    /** @brief 在原串行执行域通知唯一等待协程。 */
    inline auto Notify(State &Owner, const Signal Value) noexcept -> void
    {
        try
        {
            if (!Owner.Events.try_send(boost::system::error_code{}, Value))
            {
                RecordSignalFailure(Owner);
            }
        }
        catch (...)
        {
            RecordException(Owner, std::current_exception());
        }
    }

    /** @brief 到期或原生错误完成；只在截止时间真实到达时发送取消。 */
    inline auto OnDeadline(
        const std::shared_ptr<State> &Owner,
        const boost::system::error_code Error) noexcept -> void
    {
        Owner->DeadlineFinished = true;
        const bool ExpectedCancel = Error == Net::error::operation_aborted && Owner->DeadlineCancelRequested;
        if (Error && !ExpectedCancel)
        {
            RecordNativeError(*Owner, Error);
        }
        else if (!Error && !Owner->OperationFinished)
        {
            Owner->TimedOut = true;
            RecordFailure(*Owner, Prism::Fault::Failure{
                Prism::Fault::Code::Timeout, std::make_error_code(std::errc::timed_out)});
        }
        Notify(*Owner, Signal::Deadline);
    }

    /** @brief 本 shutdown deadline 主动取消产生的 operation_aborted 不升级为 Fatal。 */
    [[nodiscard]] inline auto IsExpectedTimeoutCancellation(
        const std::exception_ptr &ExceptionValue) noexcept -> bool
    {
        if (!ExceptionValue)
        {
            return false;
        }
        try
        {
            std::rethrow_exception(ExceptionValue);
        }
        catch (const boost::system::system_error &Error)
        {
            return Error.code() == Net::error::operation_aborted;
        }
        catch (const std::system_error &Error)
        {
            return Error.code() == std::make_error_code(std::errc::operation_canceled);
        }
        catch (...)
        {
            return false;
        }
    }

    /** @brief 原操作退栈后保存 typed 结果，再取消 deadline 并发送完成事件。 */
    inline auto OnOperationComplete(
        const std::shared_ptr<State> &Owner,
        const std::exception_ptr ExceptionValue,
        DrainOutcome Outcome) noexcept -> void
    {
        Owner->OperationFinished = true;
        if (ExceptionValue)
        {
            if (Owner->TimedOut && IsExpectedTimeoutCancellation(ExceptionValue))
            {
                RecordFailure(*Owner, FailureFromException(ExceptionValue));
            }
            else
            {
                RecordException(*Owner, ExceptionValue);
            }
        }
        else if (!Outcome && Owner->Outcome)
        {
            Owner->Outcome = std::unexpected(Outcome.error());
        }
        Owner->DeadlineCancelRequested = true;
        try
        {
            Owner->Timer.cancel();
        }
        catch (...)
        {
            RecordException(*Owner, std::current_exception());
        }
        Notify(*Owner, Signal::Operation);
    }

    /** @brief 投递原 drain；同步启动失败保留异常并取消已登记的 deadline。 */
    [[nodiscard]] inline auto StartOperation(
        const std::shared_ptr<State> &Owner,
        Net::awaitable<DrainOutcome> Operation) noexcept -> bool
    {
        try
        {
            Net::co_spawn(Owner->Serial, std::move(Operation),
                Net::bind_cancellation_slot(Owner->Cancellation.slot(),
                    [Owner](std::exception_ptr ExceptionValue, DrainOutcome Outcome) noexcept
                    {
                        OnOperationComplete(Owner, std::move(ExceptionValue), std::move(Outcome));
                    }));
            return true;
        }
        catch (...)
        {
            RecordException(*Owner, std::current_exception());
            Owner->DeadlineCancelRequested = true;
            try
            {
                Owner->Timer.cancel();
            }
            catch (...)
            {
                RecordException(*Owner, std::current_exception());
            }
            return false;
        }
    }

    /** @brief 启动截止 timer；启动失败保留实际异常且不启动 drain。 */
    [[nodiscard]] inline auto StartDeadline(const std::shared_ptr<State> &Owner) noexcept -> bool
    {
        try
        {
            Owner->Timer.expires_at(Owner->Deadline);
            Owner->Timer.async_wait([Owner](const boost::system::error_code Error) noexcept
            {
                OnDeadline(Owner, Error);
            });
            return true;
        }
        catch (...)
        {
            RecordException(*Owner, std::current_exception());
            return false;
        }
    }

    /** @brief 等待 deadline completion；额外 post 确认 timer handler 已真实退栈。 */
    [[nodiscard]] inline auto WaitForDeadlineRetirement(const std::shared_ptr<State> &Owner)
        -> Net::awaitable<bool>
    {
        while (!Owner->DeadlineFinished)
        {
            boost::system::error_code Error;
            const auto Event = co_await Owner->Events.async_receive(
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                RecordNativeError(*Owner, Error);
                co_return false;
            }
            if (Event == Signal::Deadline)
            {
                break;
            }
        }
        try
        {
            co_await Net::post(Owner->Serial, Net::use_awaitable);
            co_return true;
        }
        catch (...)
        {
            RecordException(*Owner, std::current_exception());
            co_return false;
        }
    }

    /** @brief 在唯一串行域协调操作和 deadline；超时保留未完成的子协程。 */
    [[nodiscard]] inline auto Run(
        const std::shared_ptr<State> &Owner,
        Net::awaitable<DrainOutcome> Operation) -> Net::awaitable<WaitResult>
    {
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        if (!StartDeadline(Owner))
        {
            co_return WaitResult{false, Owner->Outcome};
        }
        const bool Started = StartOperation(Owner, std::move(Operation));
        if (Started)
        {
            boost::system::error_code Error;
            const auto FirstEvent = co_await Owner->Events.async_receive(
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                RecordNativeError(*Owner, Error);
            }
            else if (FirstEvent == Signal::Deadline && Owner->TimedOut)
            {
                Owner->Cancellation.emit(Net::cancellation_type::all);
            }
        }
        bool DeadlineRetired = false;
        if (!Owner->DeadlineFinished)
        {
            DeadlineRetired = co_await WaitForDeadlineRetirement(Owner);
        }
        else
        {
            try
            {
                co_await Net::post(Owner->Serial, Net::use_awaitable);
                DeadlineRetired = true;
            }
            catch (...)
            {
                RecordException(*Owner, std::current_exception());
            }
        }
        if (!Started || !Owner->OperationFinished || !DeadlineRetired)
        {
            co_return WaitResult{false, Owner->Outcome};
        }
        co_return WaitResult{true, Owner->Outcome};
    }

    /**
     * @brief 在应用 RuntimeState 上有界等待 typed drain。
     * @param RequestValue 按值持有 RuntimeState、共同 deadline 与 typed drain 协程。
     * @return 原 operation 的 typed Failure；timeout 只表示 drain 未完成。
     * @note State 中 ContextPin 先于所有 executor 与 timer owner；deadline completion 后经过同 Serial fence。
     */
    [[nodiscard]] inline auto Await(Request RequestValue) -> Net::awaitable<WaitResult>
    {
        if (!RequestValue.RuntimePin || !RequestValue.RuntimePin->ControlContext)
        {
            co_return WaitResult{false, std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked})};
        }
        auto Owner = std::make_shared<State>(
            std::move(RequestValue.RuntimePin), RequestValue.Deadline);
        try
        {
            co_return co_await Net::co_spawn(
                Owner->Serial, Run(Owner, std::move(RequestValue.Operation)), Net::use_awaitable);
        }
        catch (...)
        {
            const auto ExceptionValue = std::current_exception();
            const auto Cause = FailureFromException(ExceptionValue);
            Owner->ContextPin->Fatal->Publish(ExceptionValue);
            co_return WaitResult{false, std::unexpected(Cause)};
        }
    }

} // namespace Prism::Application::Shutdown::ShutdownOperation
