/**
 * @file Shutdown.hpp
 * @brief Prism 应用优雅停机、回滚和最终资源释放。
 */

#pragma once

#include <Prism/Application/Startup/Detail/RuntimeState.hpp>
#include <Prism/Application/Shutdown/Detail/BoundedOperation.hpp>
#include <Prism/Application/Shutdown/Detail/Coordinator.hpp>
#include <Prism/Application/Shutdown/Detail/DrainStages.hpp>
#include <Prism/Application/Shutdown/Detail/GenerationRetirement.hpp>
#include <Prism/Application/Shutdown/Detail/Failure.hpp>
#include <Prism/Application/Shutdown/Detail/Types.hpp>
#include <Prism/Application/Startup/Detail/Errors.hpp>
#include <Prism/Application/Storage/Detail/Lifecycle.hpp>
#include <Prism/Runtime/WorkerGroup.hpp>

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <system_error>
#include <utility>

namespace Prism::Application::Shutdown
{

    namespace Net = boost::asio;

    inline auto ScheduleShutdown(const std::shared_ptr<Application::RuntimeState>& State) noexcept -> void;
    inline auto ArmDiagnoseFlush(const std::shared_ptr<Application::RuntimeState>& State) -> void;
    inline auto ArmStatisticsFlush(const std::shared_ptr<Application::RuntimeState>& State) -> void;

    inline auto CompleteGenerationReaper(
        const std::weak_ptr<Application::RuntimeState> &Weak,
        const std::exception_ptr ExceptionValue,
        const ShutdownOutcome Result) noexcept -> void
    {
        const auto Owner = Weak.lock();
        if (!Owner)
        {
            return;
        }
        if (ExceptionValue || !Result)
        {
            Owner->ObservationFailures.fetch_add(1, std::memory_order_relaxed);
        }
        Owner->GenerationReaperRunning.store(false, std::memory_order_release);
        try
        {
            (void)Owner->GenerationReaperSignal.cancel();
        }
        catch (const boost::system::system_error &)
        {
            Owner->ObservationFailures.fetch_add(1, std::memory_order_relaxed);
        }
    }

    inline auto GenerationReaperCompleted(
        const std::weak_ptr<Application::RuntimeState> &Weak,
        const std::exception_ptr ExceptionValue,
        const ShutdownOutcome Result) noexcept -> void
    {
        CompleteGenerationReaper(Weak, ExceptionValue, Result);
    }

    /** @brief 控制 executor 定期消费数值观察队列；弱持应用，观察失败不进入业务停机错误。 */
    inline auto OnStatisticsFlush(const std::weak_ptr<Application::RuntimeState>& Weak,
        const boost::system::error_code Error) -> void
    {
        const auto State = Weak.lock();
        if (!State) return;
        State->StatisticsFlushArmedIntervalMilliseconds.store(0, std::memory_order_release);
        if (Error) return;
        if (State->WorkerFatal.load(std::memory_order_acquire))
        {
            MarkShutdownFailed(State);
            ScheduleShutdown(State);
            return;
        }
        if (!State->Traffic || State->Traffic->IsSealed()) return;
        State->Traffic->Flush();
        const auto Generation = State->ActiveGenerationSnapshot();
        if (Generation && Generation->Generation &&
            Generation->Generation->Configuration().Statistics.Enabled)
        {
            State->Traffic->Sample(static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()));
        }
        if (State->Phase.load(std::memory_order_acquire) == RuntimePhase::Ready)
        {
            auto Expected = false;
            if (State->GenerationReaperRunning.compare_exchange_strong(
                    Expected, true, std::memory_order_acq_rel))
            {
                const auto Weak = std::weak_ptr<Application::RuntimeState>(State);
                try
                {
                    Net::co_spawn(State->Io.get_executor(), GenerationRetirement::ReapRetiredGenerationSnapshots(State),
                        [Weak](std::exception_ptr ExceptionValue, ShutdownOutcome Result) noexcept
                        {
                            GenerationReaperCompleted(Weak, ExceptionValue, Result);
                        });
                }
                catch (...)
                {
                    State->GenerationReaperRunning.store(false, std::memory_order_release);
                    State->ObservationFailures.fetch_add(1, std::memory_order_relaxed);
                    try
                    {
                        (void)State->GenerationReaperSignal.cancel();
                    }
                    catch (const boost::system::system_error &)
                    {
                        State->ObservationFailures.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }
        }
        ArmStatisticsFlush(State);
    }

    /** @brief timer 只在应用控制 executor 装配；每次读取当前generation采样间隔。 */
    inline auto ArmStatisticsFlush(const std::shared_ptr<Application::RuntimeState>& State) -> void
    {
        if (!State->Traffic || State->Traffic->IsSealed())
        {
            State->StatisticsFlushArmedIntervalMilliseconds.store(0, std::memory_order_release);
            return;
        }
        auto Interval = State->StatisticsFlushInterval;
        const auto Generation = State->ActiveGenerationSnapshot();
        if (Generation && Generation->Generation)
        {
            Interval = std::chrono::milliseconds{
                Generation->Generation->Configuration().Statistics.Interval};
        }
        if (Interval.count() <= 0)
        {
            State->StatisticsFlushArmedIntervalMilliseconds.store(0, std::memory_order_release);
            return;
        }
        State->StatisticsFlushTimer.expires_after(Interval);
        const auto Weak = std::weak_ptr<Application::RuntimeState>(State);
        State->StatisticsFlushTimer.async_wait([Weak](boost::system::error_code Error)
            { OnStatisticsFlush(Weak, Error); });
        State->StatisticsFlushArmedIntervalMilliseconds.store(
            Interval.count(), std::memory_order_release);
    }

    /**
     * @brief 处理周期 flush timer 完成并安排下一次请求。
     * @param WeakState 应用状态的弱引用，避免 timer handler 延长运行时生命周期。
     * @param Error timer 完成状态；取消时直接返回。
     */
    inline auto OnDiagnoseFlush(const std::weak_ptr<Application::RuntimeState>& WeakState,
        const boost::system::error_code& Error) noexcept -> void
    {
        if (Error)
        {
            return;
        }
        if (const auto State = WeakState.lock(); State && State->Diagnose && State->Diagnose->IsInstalled())
        {
            State->Diagnose->Flush();
            try
            {
                ArmDiagnoseFlush(State);
            }
            catch (...)
            {
                MarkShutdownFailed(State);
                ScheduleShutdown(State);
            }
        }
    }

    /**
     * @brief 在 Asio executor 上安排下一次非阻塞 sink flush 请求。
     * @param State 持有 timer、配置间隔和 Diagnose runtime 的应用状态。
     * @details timer 到期后调用 Diagnose backend 的 Flush 请求；应用线程不等待 sink I/O 完成。
     */
    inline auto ArmDiagnoseFlush(const std::shared_ptr<Application::RuntimeState>& State) -> void
    {
        if (!State->Diagnose || !State->Diagnose->IsInstalled())
        {
            return;
        }
        State->DiagnoseFlushTimer.expires_after(State->DiagnoseFlushInterval);
        const auto WeakState = std::weak_ptr<Application::RuntimeState>(State);
        State->DiagnoseFlushTimer.async_wait([WeakState](const boost::system::error_code& Error) noexcept
            { OnDiagnoseFlush(WeakState, Error); });
    }

    /**
     * @brief 在 root Asio 运行循环退出后 join worker 和管理 controller 并关闭 Diagnose backend。
     * @param State 已完成异步停机的应用状态。
     * @details 含有同步 join，只能由应用控制线程调用，不能从协程或 I/O worker 调用。
     */
    inline auto FinalizeRuntimeResources(const std::shared_ptr<Application::RuntimeState>& State) noexcept
        -> void
    {
        if (State->ResourcesFinalized.load(std::memory_order_acquire)) return;
        const auto OperationsDrained = State->OperationsShutdown.load(std::memory_order_acquire) ==
            ShutdownStage::Completed;
        if (State->ManagementController && OperationsDrained)
        {
            const auto ManagementJoined = Detail::JoinManagementController(State);
            if (!ManagementJoined)
            {
                MarkShutdownDrainFailed(State, ManagementJoined.error());
                State->FinalizeFailedShutdown();
                return;
            }
        }
        const auto WorkerDrainMissing = State->Process && State->WorkersStarted &&
            !State->WorkerShutdownSucceeded.load(std::memory_order_acquire);
        const auto OperationsDrainMissing = State->ManagementController && !OperationsDrained;
        if (State->ShutdownDrainFailed.load(std::memory_order_acquire) ||
            State->ProtocolDrainFailed.load(std::memory_order_acquire) || WorkerDrainMissing ||
            OperationsDrainMissing ||
            State->ControlContext->Fatal->HasFailure() ||
            State->ClosingResources->IsSealed() || State->ClosingResources->Pending() != 0)
        {
            MarkShutdownDrainFailed(State);
            State->FinalizeFailedShutdown();
            return;
        }
        State->ManagementController.reset();
        if (State->Process)
        {
            State->StopWorkers();
        }
        if (State->Diagnose)
        {
            State->Diagnose->BeginShutdown();
        }
        State->Services.reset();
        State->Traffic.reset();
        State->DnsResolver.reset();
        State->Generation.reset();
        State->Accounts = {};
        try
        {
            StorageLifecycle::Join(State);
        }
        catch (const std::exception &)
        {
            MarkShutdownDrainFailed(State,
                ShutdownOperation::FailureFromException(std::current_exception()));
            State->FinalizeFailedShutdown();
            return;
        }
        State->StorageOwner.reset();
        if (State->Diagnose)
        {
            const auto Receipt = State->Diagnose->FinalizeShutdown();
            if (Receipt.Status == Prism::Diagnose::SubmissionStatus::Failed)
            {
                State->ObservationFailures.fetch_add(1, std::memory_order_relaxed);
            }
        }
        State->Diagnose.reset();
        State->WorkerContexts.clear();
        State->RootContext = Prism::Diagnose::ContextState::Empty();
        State->ClosingResources->Collect();
        if (State->ClosingResources->IsSealed() || State->ClosingResources->Pending() != 0)
        {
            MarkShutdownDrainFailed(State);
            State->FinalizeFailedShutdown();
            return;
        }
        State->Process.reset();
        State->ClosingResources->Collect();
        if (State->ClosingResources->IsSealed() || State->ClosingResources->Pending() != 0)
        {
            MarkShutdownDrainFailed(State);
            State->FinalizeFailedShutdown();
            return;
        }
        State->ResourcesFinalized.store(true, std::memory_order_release);
    }

    /** @brief 信号和 startup rollback 的全流程 typed close owner。 */
    [[nodiscard]] inline auto ShutdownRuntime(
        std::shared_ptr<Application::RuntimeState> State) -> Net::awaitable<ShutdownOutcome>
    {
        if (!State)
        {
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        if (State->WorkerFatal.load(std::memory_order_acquire) ||
            State->ControlContext->Fatal->HasFailure())
        {
            auto Cause = State->ShutdownFailure.value_or(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            if (const auto ExceptionValue = State->ControlContext->Fatal->Error())
            {
                Cause = ShutdownOperation::FailureFromException(ExceptionValue);
            }
            co_return std::unexpected(MarkShutdownDrainFailed(State, Cause));
        }
        const ShutdownDeadline Deadline =
            std::chrono::steady_clock::now() + State->ShutdownTimeout;
        const auto DataPlane = co_await DrainApplicationDataPlane(State, Deadline);
        const auto Operations = co_await DrainOperationsServer(State, Deadline);
        if (!DataPlane)
        {
            co_return std::unexpected(State->ShutdownFailure.value_or(DataPlane.error()));
        }
        if (!Operations)
        {
            co_return std::unexpected(State->ShutdownFailure.value_or(Operations.error()));
        }
        co_return ShutdownOutcome{};
    }

    /** @brief 顺序执行完整 shutdown 并发布唯一 typed 终态。 */
    [[nodiscard]] inline auto RunShutdownAndPublish(
        std::shared_ptr<Application::RuntimeState> State) -> Net::awaitable<void>
    {
        auto Outcome = ShutdownOutcome{};
        try
        {
            Outcome = co_await ShutdownRuntime(State);
        }
        catch (...)
        {
            const auto ExceptionValue = std::current_exception();
            const auto Cause = ShutdownOperation::FailureFromException(ExceptionValue);
            Outcome = std::unexpected(State->RecordShutdownFailure(Cause));
            State->ControlContext->Fatal->Publish(ExceptionValue);
        }
        const auto Published = co_await PublishShutdownResult(State, std::move(Outcome));
        if (!Published)
        {
            (void)State->RecordShutdownFailure(Published.error());
        }
        co_return;
    }

    /** @brief shutdown gate 的后续请求只观察结果，不启动第二次 drain。 */
    [[nodiscard]] inline auto ObserveShutdownAndRecord(
        std::shared_ptr<Application::RuntimeState> State) -> Net::awaitable<void>
    {
        const auto Outcome = co_await ObserveShutdownResult(State);
        if (!Outcome)
        {
            (void)State->RecordShutdownFailure(Outcome.error());
        }
        co_return;
    }

    inline auto RunStartupRollback(
        const std::shared_ptr<Application::RuntimeState> &State) noexcept -> void
    {
        if (!State)
        {
            return;
        }
        try
        {
            State->Io.restart();
            // 未发布的 worker 仍拥有构造期任务；封止准入后驱动原 executor 才能真实 Drain。
            if (State->Process && !State->WorkersStarted)
            {
                const auto Count = State->Process->Workers().Size();
                for (std::size_t Index = 0; Index < Count; ++Index)
                {
                    auto *Worker = State->Process->Workers().Find(
                        Prism::WorkerId{static_cast<std::uint64_t>(Index + 1U)});
                    if (Worker)
                    {
                        Worker->CloseAdmission();
                    }
                }
                State->StartWorkers(Count);
            }
            if (TryClaimShutdown(State))
            {
                Net::co_spawn(State->ShutdownCoordinator,
                    RunShutdownAndPublish(State),
                    Net::bind_executor(State->ShutdownCoordinator,
                        [State](std::exception_ptr ExceptionValue) noexcept
                        {
                            OnShutdownDriverComplete(State, ExceptionValue);
                        }));
            }
            else
            {
                Net::co_spawn(State->ShutdownCoordinator,
                    ObserveShutdownAndRecord(State), Net::detached);
            }
            while (!State->Io.stopped())
            {
                if (State->Io.run_one() == 0U)
                {
                    State->Io.restart();
                }
            }
            if (!State->StopCompleted.load(std::memory_order_acquire))
            {
                auto Cause = Prism::Fault::Failure{Prism::Fault::Code::Blocked};
                if (const auto ExceptionValue = State->ControlContext->Fatal->Error())
                {
                    Cause = ShutdownOperation::FailureFromException(ExceptionValue);
                }
                (void)State->RecordShutdownFailure(Cause);
                State->StopCompleted.store(true, std::memory_order_release);
            }
            FinalizeRuntimeResources(State);
        }
        catch (...)
        {
            const auto ExceptionValue = std::current_exception();
            (void)State->RecordShutdownFailure(
                ShutdownOperation::FailureFromException(ExceptionValue));
            State->StopCompleted.store(true, std::memory_order_release);
            State->ControlContext->Fatal->Publish(ExceptionValue);
            State->Io.stop();
            FinalizeRuntimeResources(State);
        }
    }

    inline auto ScheduleShutdown(
        const std::shared_ptr<Application::RuntimeState> &State) noexcept -> void
    {
        if (!State)
        {
            return;
        }
        try
        {
            if (!TryClaimShutdown(State))
            {
                Net::co_spawn(State->ShutdownCoordinator,
                    ObserveShutdownAndRecord(State), Net::detached);
                return;
            }
            Net::co_spawn(State->ShutdownCoordinator,
                RunShutdownAndPublish(State),
                Net::bind_executor(State->ShutdownCoordinator,
                    [State](std::exception_ptr ExceptionValue) noexcept
                    {
                        OnShutdownDriverComplete(State, ExceptionValue);
                    }));
        }
        catch (...)
        {
            const auto ExceptionValue = std::current_exception();
            (void)State->RecordShutdownFailure(
                ShutdownOperation::FailureFromException(ExceptionValue));
            State->StopCompleted.store(true, std::memory_order_release);
            State->ControlContext->Fatal->Publish(ExceptionValue);
        }
    }
} // namespace Prism::Application::Shutdown
