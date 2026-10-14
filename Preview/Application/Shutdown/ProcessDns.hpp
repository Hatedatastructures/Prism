/**
 * @file ProcessDns.hpp
 * @brief 应用进程级 DNS Resolver 的有界停机 owner。
 * @details Resolver 的 timer 与 completion 由私有串行 executor 驱动；ContextPin
 *          先于 executor、deadline timer 和 resolver 引用声明。deadline handler 的 retired
 *          通知后再切一次同一 Serial，确保 handler 真实退栈后才释放关闭 owner。
 */

#pragma once

#include <Preview/Application/RuntimeState.hpp>
#include <Preview/Application/Shutdown/BoundedOperation.hpp>
#include <Preview/Foundation/Executor/ContextOwner.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>

#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/system/system_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <exception>
#include <expected>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace Preview::Application::Shutdown::Detail
{

    namespace Net = boost::asio;

    /** @brief Resolver 是否真实完成及其唯一 typed 结果。 */
    struct ProcessDnsShutdownResult final
    {
        bool ResolverCompleted{false};
        ShutdownOperation::DrainOutcome Outcome{};
    };

    /** @brief 持有进程 ContextOwner、Resolver 与关闭 deadline 操作至真实回调退栈。 */
    struct ProcessDnsShutdownState final
    {
        using Signal = Net::experimental::channel<
            void(boost::system::error_code, ProcessDnsShutdownResult)>;
        using RetiredSignal = Net::experimental::channel<void(boost::system::error_code)>;

        ProcessDnsShutdownState(
            std::shared_ptr<Preview::Application::Application::RuntimeState> RuntimeValue,
            std::shared_ptr<Preview::Network::Dns::Resolver> ResolverValue,
            const std::chrono::steady_clock::time_point DeadlineValue)
            : RuntimePin(std::move(RuntimeValue)), ContextPin(RuntimePin->ControlContext),
              ResolverOwner(std::move(ResolverValue)), Serial(ContextPin->Io.get_executor()),
              DeadlineTimer(Serial), Completion(Serial, 1), DeadlineRetired(Serial, 1)
        {
            DeadlineTimer.expires_at(DeadlineValue);
        }

        /** @brief 进程运行时与其 control context 均先于 executor 和 timer 销毁。 */
        std::shared_ptr<Preview::Application::Application::RuntimeState> RuntimePin;
        std::shared_ptr<Preview::Executor::ContextOwner> ContextPin;
        std::shared_ptr<Preview::Network::Dns::Resolver> ResolverOwner;
        Net::strand<Net::any_io_executor> Serial;
        Net::steady_timer DeadlineTimer;
        Signal Completion;
        RetiredSignal DeadlineRetired;
        Net::cancellation_signal Cancellation;
        bool DeadlineWaitStarted{false};
        bool DeadlineExpired{false};
        bool CompletionSent{false};
    };

    /**
     * @brief 只允许首次完成结果入队，并保留 deadline timer 的 native cancel cause。
     * @param State 拥有原 executor 与待退栈 operation 的私有状态。
     * @param Result Resolver 的完成结果或 shutdown deadline。
     * @return 无；结果按值交给等待协程。
     */
    inline auto CompleteProcessDnsShutdown(
        const std::shared_ptr<ProcessDnsShutdownState> &State,
        ProcessDnsShutdownResult Result) noexcept -> void
    {
        if (State->CompletionSent)
        {
            return;
        }
        State->CompletionSent = true;
        try
        {
            State->DeadlineTimer.cancel();
        }
        catch (const boost::system::system_error &Exception)
        {
            if (Result.Outcome)
            {
                Result.Outcome = std::unexpected(Preview::Fault::FromNative(
                    static_cast<std::error_code>(Exception.code())));
            }
            State->ContextPin->Fatal->Publish(std::current_exception());
        }
        catch (...)
        {
            const auto ExceptionValue = std::current_exception();
            if (Result.Outcome)
            {
                Result.Outcome = std::unexpected(
                    ShutdownOperation::FailureFromException(ExceptionValue));
            }
            State->ContextPin->Fatal->Publish(ExceptionValue);
        }
        if (!Result.Outcome)
        {
            (void)State->RuntimePin->RecordShutdownFailure(Result.Outcome.error());
        }
        if (!State->Completion.try_send(boost::system::error_code{}, std::move(Result)))
        {
            const Preview::Fault::Failure Cause{Preview::Fault::Code::Blocked};
            (void)State->RuntimePin->RecordShutdownFailure(Cause);
            try
            {
                throw std::runtime_error("DNS停机完成通知被拒绝");
            }
            catch (...)
            {
                State->ContextPin->Fatal->Publish(std::current_exception());
            }
        }
    }

    /**
     * @brief 维护 owner 到达关闭 deadline 后返回 typed timeout，保留仍在途的真实 owner。
     * @param State 持有 deadline、Resolver 与 ContextOwner 的关闭状态。
     * @param Error deadline timer 的完成错误；取消完成不触发 timeout。
     * @return 无；timeout 结果交由关闭协程消费。
     */
    inline auto OnProcessDnsShutdownDeadline(
        const std::shared_ptr<ProcessDnsShutdownState> &State,
        const boost::system::error_code Error) noexcept -> void
    {
        if (Error == Net::error::operation_aborted)
        {
            if (!State->DeadlineRetired.try_send(boost::system::error_code{}))
            {
                (void)State->RuntimePin->RecordShutdownFailure(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                try
                {
                    throw std::runtime_error("DNS deadline退栈通知被拒绝");
                }
                catch (...)
                {
                    State->ContextPin->Fatal->Publish(std::current_exception());
                }
            }
            return;
        }
        ProcessDnsShutdownResult Result;
        if (Error)
        {
            Result.Outcome = std::unexpected(Preview::Fault::FromNative(
                static_cast<std::error_code>(Error)));
        }
        else
        {
            State->DeadlineExpired = true;
            Result.Outcome = std::unexpected(Preview::Fault::Failure{
                Preview::Fault::Code::Timeout, std::make_error_code(std::errc::timed_out)});
        }
        (void)State->RuntimePin->RecordShutdownFailure(Result.Outcome.error());
        if (Error)
        {
            try
            {
                throw boost::system::system_error(Error);
            }
            catch (...)
            {
                State->ContextPin->Fatal->Publish(std::current_exception());
            }
        }
        CompleteProcessDnsShutdown(State, std::move(Result));
        State->Cancellation.emit(Net::cancellation_type::all);
        if (!State->DeadlineRetired.try_send(boost::system::error_code{}))
        {
            (void)State->RuntimePin->RecordShutdownFailure(
                Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            try
            {
                throw std::runtime_error("DNS deadline退栈通知被拒绝");
            }
            catch (...)
            {
                State->ContextPin->Fatal->Publish(std::current_exception());
            }
        }
    }

    /**
     * @brief 记录 Resolver completion；非预期异常只进入 ContextOwner 的 FatalState。
     * @param State 仍持有关闭操作全部真实 owner 的状态。
     * @param Exception 不可恢复异常；空值表示正常 typed completion。
     * @param Outcome Resolver 的 typed 关闭结果。
     * @return 无；结果交给 shutdown wait channel。
     */
    inline auto OnProcessDnsShutdownComplete(
        const std::shared_ptr<ProcessDnsShutdownState> &State,
        std::exception_ptr Exception,
        std::expected<void, Preview::Fault::Failure> Outcome) noexcept -> void
    {
        if (Exception)
        {
            if (State->DeadlineExpired &&
                ShutdownOperation::IsExpectedTimeoutCancellation(Exception))
            {
                return;
            }
            const auto Cause = ShutdownOperation::FailureFromException(Exception);
            (void)State->RuntimePin->RecordShutdownFailure(Cause);
            State->ContextPin->Fatal->Publish(std::move(Exception));
            CompleteProcessDnsShutdown(
                State, ProcessDnsShutdownResult{true, std::unexpected(Cause)});
            return;
        }
        if (!Outcome)
        {
            (void)State->RuntimePin->RecordShutdownFailure(Outcome.error());
            CompleteProcessDnsShutdown(
                State, ProcessDnsShutdownResult{true, std::unexpected(Outcome.error())});
            return;
        }
        CompleteProcessDnsShutdown(State, ProcessDnsShutdownResult{true, {}});
    }

    /**
     * @brief 在私有串行 executor 上驱动 deadline 与 Resolver 的真实关闭 completion。
     * @param State 持有 ContextPin、Resolver、timer 和 completion channel。
     * @return Resolver 是否真实完成及其唯一 typed 结果。
     */
    [[nodiscard]] inline auto WaitForProcessDnsShutdown(
        const std::shared_ptr<ProcessDnsShutdownState> &State)
        -> Net::awaitable<ProcessDnsShutdownResult>
    {
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        try
        {
            State->DeadlineTimer.async_wait([State](const boost::system::error_code Error)
            {
                OnProcessDnsShutdownDeadline(State, Error);
            });
            State->DeadlineWaitStarted = true;
            Net::co_spawn(
                State->Serial, State->ResolverOwner->Shutdown(),
                Net::bind_cancellation_slot(State->Cancellation.slot(),
                    [State](std::exception_ptr Exception,
                        std::expected<void, Preview::Fault::Failure> Outcome)
                    {
                        OnProcessDnsShutdownComplete(
                            State, std::move(Exception), std::move(Outcome));
                    }));
        }
        catch (...)
        {
            const auto ExceptionValue = std::current_exception();
            const auto Cause = ShutdownOperation::FailureFromException(ExceptionValue);
            (void)State->RuntimePin->RecordShutdownFailure(Cause);
            State->ContextPin->Fatal->Publish(ExceptionValue);
            CompleteProcessDnsShutdown(
                State, ProcessDnsShutdownResult{false, std::unexpected(Cause)});
            if (!State->DeadlineWaitStarted &&
                !State->DeadlineRetired.try_send(boost::system::error_code{}))
            {
                (void)State->RuntimePin->RecordShutdownFailure(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                try
                {
                    throw std::runtime_error("DNS deadline退栈通知被拒绝");
                }
                catch (...)
                {
                    State->ContextPin->Fatal->Publish(std::current_exception());
                }
            }
        }

        boost::system::error_code ReceiveError;
        auto Result = co_await State->Completion.async_receive(
            Net::redirect_error(Net::use_awaitable, ReceiveError));
        boost::system::error_code RetireError;
        co_await State->DeadlineRetired.async_receive(
            Net::redirect_error(Net::use_awaitable, RetireError));
        // Deadline handler 与本等待协程共用 Serial；额外 post 构成显式退栈 fence。
        co_await Net::post(State->Serial, Net::use_awaitable);
        if (ReceiveError)
        {
            Result.ResolverCompleted = false;
            if (Result.Outcome)
            {
                Result.Outcome = std::unexpected(Preview::Fault::FromNative(
                    static_cast<std::error_code>(ReceiveError)));
            }
            (void)State->RuntimePin->RecordShutdownFailure(Result.Outcome.error());
            try
            {
                throw boost::system::system_error(ReceiveError);
            }
            catch (...)
            {
                State->ContextPin->Fatal->Publish(std::current_exception());
            }
        }
        if (RetireError)
        {
            if (Result.Outcome)
            {
                Result.Outcome = std::unexpected(Preview::Fault::FromNative(
                    static_cast<std::error_code>(RetireError)));
            }
            (void)State->RuntimePin->RecordShutdownFailure(Result.Outcome.error());
            try
            {
                throw boost::system::system_error(RetireError);
            }
            catch (...)
            {
                State->ContextPin->Fatal->Publish(std::current_exception());
            }
        }
        co_return Result;
    }

    /**
     * @brief 停止进程 resolver 并保留其首个 typed shutdown failure。
     * @param Runtime 持有进程资源与 control ContextOwner 的运行时。
     * @param Deadline 与其它应用 owner 共用的 shutdown 截止时间。
     * @return Resolver 完成时返回 success；失败返回原 Native cause 或 Timeout。
     */
    [[nodiscard]] inline auto DrainProcessDnsResolver(
        const std::shared_ptr<Preview::Application::Application::RuntimeState> &Runtime,
        const std::chrono::steady_clock::time_point Deadline)
        -> Net::awaitable<ShutdownOperation::DrainOutcome>
    {
        if (!Runtime->DnsResolver)
        {
            co_return ShutdownOperation::DrainOutcome{};
        }
        auto State = std::make_shared<ProcessDnsShutdownState>(
            Runtime, Runtime->DnsResolver, Deadline);
        try
        {
            const auto Result = co_await Net::co_spawn(
                State->Serial, WaitForProcessDnsShutdown(State), Net::use_awaitable);
            if (!Result.Outcome)
            {
                co_return std::unexpected(Result.Outcome.error());
            }
            if (Result.ResolverCompleted)
            {
                co_return ShutdownOperation::DrainOutcome{};
            }
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
        catch (...)
        {
            const auto ExceptionValue = std::current_exception();
            const auto Cause = ShutdownOperation::FailureFromException(ExceptionValue);
            const auto StoredCause = Runtime->RecordShutdownFailure(Cause);
            State->ContextPin->Fatal->Publish(ExceptionValue);
            co_return std::unexpected(StoredCause);
        }
    }

} // namespace Preview::Application::Shutdown::Detail
