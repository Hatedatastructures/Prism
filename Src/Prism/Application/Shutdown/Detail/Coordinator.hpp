/**
 * @file Coordinator.hpp
 * @brief Prism 应用关闭 gate 与唯一 typed 终态回执。
 * @details 结果状态、回执 timer 和关闭通知只在真实 ShutdownCoordinator strand 上访问。
 * 所有异步入口按值持有运行状态至协程退栈，不能借用 completion handler 中的共享指针。
 */
#pragma once

#include <Prism/Application/Startup/Detail/RuntimeState.hpp>
#include <Prism/Application/Shutdown/Detail/BoundedOperation.hpp>
#include <Prism/Application/Shutdown/Detail/Failure.hpp>
#include <Prism/Application/Shutdown/Detail/Types.hpp>

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include <cstddef>
#include <exception>
#include <limits>
#include <memory>
#include <system_error>
#include <utility>

namespace Prism::Application::Shutdown
{

    namespace Net = boost::asio;

    inline auto RequestShutdownContextStop(
        const std::shared_ptr<Application::RuntimeState> &State) noexcept -> void;
    inline auto OnShutdownDriverComplete(
        const std::shared_ptr<Application::RuntimeState> &State,
        const std::exception_ptr ExceptionValue) noexcept -> void;

    /** @brief 协调 strand 上执行 shutdown result 操作的实现细节。 */
    namespace Detail
    {

        inline constexpr auto ShutdownObserverClosedMask = std::size_t{1} <<
            (std::numeric_limits<std::size_t>::digits - 1);

        /** @brief 读取已登记但尚未退休的 observer 数。 */
        [[nodiscard]] inline auto ShutdownObserverCount(
            const std::shared_ptr<Application::RuntimeState> &State) noexcept -> std::size_t
        {
            return State->ShutdownObserverCount.load(std::memory_order_acquire) &
                ~ShutdownObserverClosedMask;
        }

        /** @brief 广播关闭前原子登记 observer；关闭后直接读取已发布结果。 */
        [[nodiscard]] inline auto TryReserveShutdownObserver(
            const std::shared_ptr<Application::RuntimeState> &State) noexcept -> bool
        {
            auto Count = State->ShutdownObserverCount.load(std::memory_order_acquire);
            while ((Count & ShutdownObserverClosedMask) == 0U)
            {
                if (State->ShutdownObserverCount.compare_exchange_weak(
                    Count, Count + 1U, std::memory_order_acq_rel))
                {
                    return true;
                }
            }
            return false;
        }

        /** @brief 将 timer/native 异常记入唯一首因和 Fatal owner。 */
        inline auto RecordCoordinatorException(
            const std::shared_ptr<Application::RuntimeState> &State,
            const std::exception_ptr ExceptionValue) noexcept -> Prism::Fault::Failure
        {
            const auto Cause = ShutdownOperation::FailureFromException(ExceptionValue);
            const auto StoredCause = State->RecordShutdownFailure(Cause);
            State->ControlContext->Fatal->Publish(ExceptionValue);
            return StoredCause;
        }

        /** @brief 在协调 strand 上释放一个结果观察者并唤醒 stop fence。 */
        inline auto ReleaseShutdownObserver(
            const std::shared_ptr<Application::RuntimeState> &State) noexcept -> void
        {
            const auto Previous = State->ShutdownObserverCount.fetch_sub(1, std::memory_order_acq_rel);
            if ((Previous & ~ShutdownObserverClosedMask) != 1U ||
                State->ShutdownResultStatus.load(std::memory_order_acquire) !=
                    ShutdownResultStage::Published ||
                State->ShutdownObserverCancellationFailed)
            {
                return;
            }
            try
            {
                State->ShutdownObserversRetiredTimer.cancel();
            }
            catch (...)
            {
                State->ShutdownObserverCancellationFailed = true;
                (void)RecordCoordinatorException(State, std::current_exception());
                RequestShutdownContextStop(State);
            }
        }

        /** @brief 在 ShutdownCoordinator executor 上等待结果并退休其 timer handler。 */
        [[nodiscard]] inline auto ObserveOnCoordinator(
            std::shared_ptr<Application::RuntimeState> State)
            -> Net::awaitable<ShutdownOutcome>
        {
            if (State->ShutdownResultStatus.load(std::memory_order_acquire) ==
                    ShutdownResultStage::Published &&
                State->ShutdownResult)
            {
                ReleaseShutdownObserver(State);
                co_return *State->ShutdownResult;
            }
            boost::system::error_code Error;
            try
            {
                co_await State->ShutdownResultTimer.async_wait(
                    Net::redirect_error(Net::use_awaitable, Error));
            }
            catch (...)
            {
                const auto StoredCause = RecordCoordinatorException(State, std::current_exception());
                ReleaseShutdownObserver(State);
                co_return std::unexpected(StoredCause);
            }
            if (State->ShutdownResultStatus.load(std::memory_order_acquire) ==
                    ShutdownResultStage::Published &&
                State->ShutdownResult)
            {
                const auto Result = *State->ShutdownResult;
                ReleaseShutdownObserver(State);
                co_return Result;
            }
            auto Cause = Prism::Fault::Failure{Prism::Fault::Code::Blocked};
            if (Error)
            {
                Cause = Prism::Fault::FromNative(static_cast<std::error_code>(Error));
                try
                {
                    throw boost::system::system_error(Error);
                }
                catch (...)
                {
                    State->ControlContext->Fatal->Publish(std::current_exception());
                }
            }
            const auto StoredCause = State->RecordShutdownFailure(Cause);
            ReleaseShutdownObserver(State);
            co_return std::unexpected(StoredCause);
        }

        /** @brief 在 ShutdownCoordinator executor 上保存并广播唯一结果。 */
        [[nodiscard]] inline auto PublishOnCoordinator(
            std::shared_ptr<Application::RuntimeState> State,
            ShutdownOutcome Outcome) -> Net::awaitable<ShutdownOutcome>
        {
            const auto Status = State->ShutdownResultStatus.load(std::memory_order_acquire);
            if (Status == ShutdownResultStage::Published && State->ShutdownResult)
            {
                co_return *State->ShutdownResult;
            }
            if (Status == ShutdownResultStage::Publishing)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            State->ShutdownResultStatus.store(
                ShutdownResultStage::Publishing, std::memory_order_release);
            auto Result = FinalizeShutdownOutcome(State, std::move(Outcome));
            try
            {
                State->ShutdownResultTimer.cancel();
            }
            catch (...)
            {
                State->ShutdownObserverCancellationFailed = true;
                Result = std::unexpected(
                    RecordCoordinatorException(State, std::current_exception()));
            }
            State->ShutdownResult = Result;
            State->ShutdownResultStatus.store(
                ShutdownResultStage::Published, std::memory_order_release);
            State->ShutdownObserverCount.fetch_or(
                ShutdownObserverClosedMask, std::memory_order_acq_rel);
            co_return Result;
        }

        /** @brief 等待结果观察 handler 退栈后再停止应用 executor。 */
        [[nodiscard]] inline auto StopAfterObservers(
            std::shared_ptr<Application::RuntimeState> State) -> Net::awaitable<void>
        {
            if (State->ShutdownResultStatus.load(std::memory_order_acquire) !=
                    ShutdownResultStage::Published)
            {
                auto Cause = State->ShutdownFailure.value_or(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                (void)co_await PublishOnCoordinator(State, std::unexpected(Cause));
            }
            std::exception_ptr NativeFailure;
            try
            {
                if (!State->ShutdownObserverCancellationFailed)
                {
                    if (ShutdownObserverCount(State) == 0U)
                    {
                        State->ShutdownObserversRetiredTimer.cancel();
                    }
                    else
                    {
                        boost::system::error_code Error;
                        co_await State->ShutdownObserversRetiredTimer.async_wait(
                            Net::redirect_error(Net::use_awaitable, Error));
                        if (Error && Error != Net::error::operation_aborted)
                        {
                            throw boost::system::system_error(Error);
                        }
                    }
                }
                co_await Net::post(State->ShutdownCoordinator, Net::use_awaitable);
            }
            catch (...)
            {
                NativeFailure = std::current_exception();
                (void)RecordCoordinatorException(State, NativeFailure);
            }
            State->Io.stop();
            State->StopCompleted.store(true, std::memory_order_release);
            co_return;
        }

        /** @brief stop fence coroutine 异常的 coordinator-strand 收口。 */
        inline auto OnStopFenceComplete(
            const std::shared_ptr<Application::RuntimeState> &State,
            const std::exception_ptr ExceptionValue) noexcept -> void
        {
            if (ExceptionValue)
            {
                (void)RecordCoordinatorException(State, ExceptionValue);
                State->Io.stop();
                State->StopCompleted.store(true, std::memory_order_release);
            }
        }

    } // namespace Detail

    /**
     * @brief 竞争应用关闭的唯一 gate。
     * @param State 共享进程级运行时。
     * @return 首个调用取得关闭责任；后续调用不得重复 drain。
     */
    [[nodiscard]] inline auto TryClaimShutdown(
        const std::shared_ptr<Application::RuntimeState> &State) noexcept -> bool
    {
        if (!State)
        {
            return false;
        }
        bool Expected = false;
        if (!State->ShutdownScheduled.compare_exchange_strong(
            Expected, true, std::memory_order_acq_rel))
        {
            return false;
        }
        State->StopRequested.store(true, std::memory_order_release);
        return true;
    }

    /**
     * @brief 在控制 executor 退出后读取已发布的关闭结果。
     * @param State 已停止 I/O 的应用运行时。
     * @return 已发布的 typed 关闭结果；缺少真实回执时返回 Blocked。
     * @note acquire 读取与协调 strand 上的 release 发布配对；仅由应用控制线程在 Io.run 返回后调用。
     */
    [[nodiscard]] inline auto ReadPublishedShutdownOutcome(
        const std::shared_ptr<Application::RuntimeState> &State) noexcept -> ShutdownOutcome
    {
        if (!State || State->ShutdownResultStatus.load(std::memory_order_acquire) !=
                ShutdownResultStage::Published ||
            !State->ShutdownResult)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        return *State->ShutdownResult;
    }

    /**
     * @brief 在应用控制线程合成最终 typed shutdown 结果。
     * @param State 已停止 I/O 并等待同步资源最终化的运行时。
     * @return 原发布结果；缺失回执、worker fatal 或 control fatal 保留为失败。
     * @note 仅由应用控制线程在 Io.run 返回后调用；不执行 join 或资源释放。
     */
    [[nodiscard]] inline auto CheckPublishedShutdownOutcome(
        const std::shared_ptr<Application::RuntimeState> &State) noexcept -> ShutdownOutcome
    {
        if (!State)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        if (State->ShutdownFailure)
        {
            return std::unexpected(*State->ShutdownFailure);
        }
        if (const auto ExceptionValue = State->ControlContext->Fatal->Error())
        {
            return std::unexpected(State->RecordShutdownFailure(
                ShutdownOperation::FailureFromException(ExceptionValue)));
        }
        if (State->WorkerFatal.load(std::memory_order_acquire))
        {
            return std::unexpected(State->RecordShutdownFailure(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked}));
        }
        const auto Outcome = ReadPublishedShutdownOutcome(State);
        if (!Outcome)
        {
            return std::unexpected(State->RecordShutdownFailure(Outcome.error()));
        }
        return Outcome;
    }

    /**
     * @brief 观察唯一 shutdown 终态；timer 与共享回执只由 ShutdownCoordinator 操作。
     * @param State 持有协调 strand、回执 timer 与最终结果的应用运行时。
     * @return 原关闭结果；观察设施失败保留 typed cause。
     */
    [[nodiscard]] inline auto ObserveShutdownResult(
        std::shared_ptr<Application::RuntimeState> State)
        -> Net::awaitable<ShutdownOutcome>
    {
        if (!State)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        if (State->ShutdownResultStatus.load(std::memory_order_acquire) ==
                ShutdownResultStage::Published)
        {
            co_return ReadPublishedShutdownOutcome(State);
        }
        if (!Detail::TryReserveShutdownObserver(State))
        {
            co_return ReadPublishedShutdownOutcome(State);
        }
        try
        {
            co_return co_await Net::co_spawn(State->ShutdownCoordinator,
                Detail::ObserveOnCoordinator(State), Net::use_awaitable);
        }
        catch (...)
        {
            const auto ExceptionValue = std::current_exception();
            const auto Previous = State->ShutdownObserverCount.fetch_sub(1, std::memory_order_acq_rel);
            if (State->ShutdownResultStatus.load(std::memory_order_acquire) ==
                    ShutdownResultStage::Published &&
                (Previous & ~Detail::ShutdownObserverClosedMask) == 1U)
            {
                RequestShutdownContextStop(State);
            }
            co_return std::unexpected(ShutdownOperation::FailureFromException(ExceptionValue));
        }
    }

    /**
     * @brief 在 ShutdownCoordinator 上发布唯一 typed 结果；不提前停止结果接收 executor。
     * @param State 持有协调 strand 和最终 root executor 的运行时。
     * @param Outcome 已按关闭阶段顺序合成的 typed 结果。
     * @return coordinator 操作的真实结果；调用者 continuation 得到结果后再安排 stop fence。
     */
    [[nodiscard]] inline auto PublishShutdownResult(
        std::shared_ptr<Application::RuntimeState> State,
        ShutdownOutcome Outcome) -> Net::awaitable<ShutdownOutcome>
    {
        if (!State)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        try
        {
            co_return co_await Net::co_spawn(State->ShutdownCoordinator,
                Detail::PublishOnCoordinator(State, std::move(Outcome)), Net::use_awaitable);
        }
        catch (...)
        {
            co_return std::unexpected(
                ShutdownOperation::FailureFromException(std::current_exception()));
        }
    }

    /**
     * @brief 在真正 coordinator strand 上等待所有已登记观察者后停止 root executor。
     * @param State 已发布唯一 typed 结果的运行时。
     * @note 由拥有型 shutdown/process-drain co_spawn completion 调用，保证其 typed receipt 已返回。
     */
    inline auto RequestShutdownContextStop(
        const std::shared_ptr<Application::RuntimeState> &State) noexcept -> void
    {
        if (!State)
        {
            return;
        }
        try
        {
            Net::co_spawn(State->ShutdownCoordinator, Detail::StopAfterObservers(State),
                Net::bind_executor(State->ShutdownCoordinator,
                    [State](std::exception_ptr ExceptionValue) noexcept
                    {
                        Detail::OnStopFenceComplete(State, ExceptionValue);
                    }));
        }
        catch (...)
        {
            State->ControlContext->Fatal->Publish(std::current_exception());
            State->Io.stop();
            State->StopCompleted.store(true, std::memory_order_release);
        }
    }

    namespace Detail
    {

        /** @brief 将逃逸 shutdown 异常在 coordinator 上发布为真实 typed failure。 */
        [[nodiscard]] inline auto PublishEscapedDriverFailure(
            std::shared_ptr<Application::RuntimeState> State,
            std::exception_ptr ExceptionValue) -> Net::awaitable<void>
        {
            const auto Cause = RecordCoordinatorException(State, ExceptionValue);
            if (State->ShutdownResultStatus.load(std::memory_order_acquire) !=
                ShutdownResultStage::Published)
            {
                (void)co_await PublishOnCoordinator(State, std::unexpected(Cause));
            }
            co_return;
        }

        /** @brief 处理 escape-failure 发布完成并继续关闭 context。 */
        inline auto OnEscapedDriverFailurePublished(
            const std::shared_ptr<Application::RuntimeState> &State,
            const std::exception_ptr ExceptionValue) noexcept -> void
        {
            if (ExceptionValue)
            {
                OnStopFenceComplete(State, ExceptionValue);
                return;
            }
            RequestShutdownContextStop(State);
        }

    } // namespace Detail

    /** @brief shutdown co_spawn 真实退栈后请求有界 receipt fence 与 context stop。 */
    inline auto OnShutdownDriverComplete(
        const std::shared_ptr<Application::RuntimeState> &State,
        const std::exception_ptr ExceptionValue) noexcept -> void
    {
        if (!State)
        {
            return;
        }
        if (!ExceptionValue)
        {
            RequestShutdownContextStop(State);
            return;
        }
        try
        {
            Net::co_spawn(State->ShutdownCoordinator,
                Detail::PublishEscapedDriverFailure(State, ExceptionValue),
                Net::bind_executor(State->ShutdownCoordinator,
                    [State](std::exception_ptr FailureValue) noexcept
                    {
                        Detail::OnEscapedDriverFailurePublished(State, FailureValue);
                    }));
        }
        catch (...)
        {
            State->ControlContext->Fatal->Publish(std::current_exception());
            State->Io.stop();
            State->StopCompleted.store(true, std::memory_order_release);
        }
    }

} // namespace Prism::Application::Shutdown
