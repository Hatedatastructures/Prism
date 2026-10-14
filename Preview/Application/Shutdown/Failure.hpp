/**
 * @file Failure.hpp
 * @brief 应用 shutdown 首因、事件与完整失败运行时保留。
 */
#pragma once

#include <Preview/Application/RuntimeState.hpp>
#include <Preview/Application/Shutdown/BoundedOperation.hpp>
#include <Preview/Application/Shutdown/Types.hpp>
#include <Preview/Statistics/EventRing.hpp>

#include <boost/asio/post.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <utility>

namespace Preview::Application::Shutdown
{
    namespace Net = boost::asio;

    /** @brief 在事件环唯一协调 strand 上追加失败事实；观察故障不得逃出关闭路径。 */
    inline auto AppendShutdownFailedEvent(
        const std::shared_ptr<Application::RuntimeState> &State) noexcept -> void
    {
        if (!State || !State->Events)
        {
            return;
        }
        try
        {
            Preview::Statistics::DetailedEvent Event;
            Event.Timestamp = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
            Event.Generation = State->Generation ? State->Generation->Id() : Preview::GenerationId{};
            Event.Process = State->Process ? State->Process->Id() : Preview::ProcessId{};
            Event.Kind = Preview::Statistics::EventKind::Failed;
            Event.Severity = Preview::Statistics::EventSeverity::Error;
            Event.Terminal = true;
            Event.Detail = "application shutdown failed";
            if (!State->Events->Append(std::move(Event)))
            {
                State->ObservationFailures.fetch_add(1U, std::memory_order_relaxed);
            }
        }
        catch (...)
        {
            State->ObservationFailures.fetch_add(1U, std::memory_order_relaxed);
        }
    }

    /** @brief 记录 shutdown 终态事件；不创建新的失败事实。 */
    inline auto MarkShutdownFailed(
        const std::shared_ptr<Application::RuntimeState> &State) noexcept -> void
    {
        State->ExitCode = 1;
        State->Phase.store(RuntimePhase::Failed, std::memory_order_release);
        if (!State->Events)
        {
            return;
        }
        if (State->ShutdownCoordinator.running_in_this_thread())
        {
            AppendShutdownFailedEvent(State);
            return;
        }
        try
        {
            Net::post(State->ShutdownCoordinator,
                [State] { AppendShutdownFailedEvent(State); });
        }
        catch (...)
        {
            State->ObservationFailures.fetch_add(1U, std::memory_order_relaxed);
        }
    }

    /** @brief 保留首个 typed cause 并将完整运行时交给进程关闭存储。 */
    inline auto MarkShutdownDrainFailed(
        const std::shared_ptr<Application::RuntimeState> &State,
        const Preview::Fault::Failure Cause =
            Preview::Fault::Failure{Preview::Fault::Code::Blocked}) noexcept -> Preview::Fault::Failure
    {
        const auto StoredCause = State->RecordShutdownFailure(Cause);
        MarkShutdownFailed(State);
        return StoredCause;
    }

    /**
     * @brief 校验所有 owner 阶段与最终关闭存储，并返回首个 typed shutdown 结果。
     * @param State 已结束数据面和管理入口 drain 的运行时。
     * @param Outcome 当前流程的首个 typed 结果。
     * @return 阶段完整且没有残留关闭实物时返回 success。
     */
    [[nodiscard]] inline auto FinalizeShutdownOutcome(
        const std::shared_ptr<Application::RuntimeState> &State,
        ShutdownOutcome Outcome) noexcept -> ShutdownOutcome
    {
        if (!Outcome)
        {
            return std::unexpected(MarkShutdownDrainFailed(State, Outcome.error()));
        }
        if (State->ShutdownFailure)
        {
            return std::unexpected(*State->ShutdownFailure);
        }
        if (State->ShutdownDrainFailed.load(std::memory_order_acquire) ||
            State->ProtocolDrainFailed.load(std::memory_order_acquire))
        {
            return std::unexpected(MarkShutdownDrainFailed(
                State, Preview::Fault::Failure{Preview::Fault::Code::Blocked}));
        }
        if (const auto ExceptionValue = State->ControlContext->Fatal->Error())
        {
            return std::unexpected(MarkShutdownDrainFailed(
                State, ShutdownOperation::FailureFromException(ExceptionValue)));
        }
        if (State->DataPlaneShutdown.load(std::memory_order_acquire) != ShutdownStage::Completed ||
            State->OperationsShutdown.load(std::memory_order_acquire) != ShutdownStage::Completed)
        {
            return std::unexpected(MarkShutdownDrainFailed(
                State, Preview::Fault::Failure{Preview::Fault::Code::Blocked}));
        }
        State->ClosingResources->Collect();
        if (State->ClosingResources->IsSealed() || State->ClosingResources->Pending() != 0)
        {
            return std::unexpected(MarkShutdownDrainFailed(
                State, Preview::Fault::Failure{Preview::Fault::Code::Blocked}));
        }
        if (State->Phase.load(std::memory_order_acquire) != RuntimePhase::Failed)
        {
            State->Phase.store(RuntimePhase::Stopped, std::memory_order_release);
        }
        return {};
    }

    } // namespace Preview::Application::Shutdown
