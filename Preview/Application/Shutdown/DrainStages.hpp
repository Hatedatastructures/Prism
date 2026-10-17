/**
 * @file DrainStages.hpp
 * @brief Preview 应用数据面、worker 与管理入口的 typed shutdown stages。
 * @details DataPlane 阶段不关闭 Operations；管理入口只在数据面和 worker 已有完成 receipt 后 drain。
 */
#pragma once

#include <Preview/Application/RuntimeState.hpp>
#include <Preview/Boundary/Datagram/DatagramListener.hpp>
#include <Preview/Composition/Provider/ProviderCatalog.hpp>
#include <Preview/Lifecycle/TaskRegistry.hpp>
#include <Preview/Operations/Controller.hpp>
#include <Preview/Runtime/Listener.hpp>
#include <Preview/Application/Shutdown/BoundedOperation.hpp>
#include <Preview/Application/Shutdown/GenerationRetirement.hpp>
#include <Preview/Application/Shutdown/Failure.hpp>
#include <Preview/Application/Shutdown/ProcessDns.hpp>
#include <Preview/Application/Shutdown/RuntimeResources.hpp>
#include <Preview/Application/Shutdown/Types.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <string_view>
#include <system_error>
#include <utility>

namespace Preview::Application::Shutdown
{
    namespace Net = boost::asio;

    /** @brief 借用独立管理 controller 并保留其 typed graceful drain 结果。 */
    [[nodiscard]] inline auto DrainManagementController(
        Preview::Operations::Controller &Owner,
        const ShutdownDeadline Deadline) -> Net::awaitable<ShutdownOutcome>
    {
        const auto Result = co_await Owner.Drain(Deadline);
        if (!Result.Failure.Succeeded())
        {
            co_return std::unexpected(Result.Failure);
        }
        co_return ShutdownOutcome{};
    }

    /** @brief 按值保留 TCP listener 并返回原始 typed shutdown result。 */
    [[nodiscard]] inline auto DrainListener(
        std::unique_ptr<Preview::Runtime::TcpListener> Owner) -> Net::awaitable<ShutdownOutcome>
    {
        co_return co_await Owner->Shutdown();
    }

    /** @brief 按值保留 provider catalog 并返回所有 binding 的 typed drain result。 */
    [[nodiscard]] inline auto DrainProviderBindings(
        Preview::Composition::Provider::BoundCatalog Owner) -> Net::awaitable<ShutdownOutcome>
    {
        co_return co_await Owner.Drain();
    }

    /** @brief 按值保留 datagram listener 并确认 receive loop 已真实完成。 */
    [[nodiscard]] inline auto DrainDatagramListener(
        std::unique_ptr<Preview::Boundary::DatagramListener> Owner) -> Net::awaitable<ShutdownOutcome>
    {
        const auto Result = co_await Owner->Drain();
        if (!Result.Completed)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
        co_return ShutdownOutcome{};
    }

    /** @brief 按值保留 TaskRegistry 并返回其原始 typed drain failure。 */
    [[nodiscard]] inline auto DrainTasks(
        std::shared_ptr<Preview::Lifecycle::TaskRegistry> Owner) -> Net::awaitable<ShutdownOutcome>
    {
        co_return co_await Owner->Drain();
    }

    /** @brief 保持 worker Process owner 并返回真实 root-scope drain result。 */
    [[nodiscard]] inline auto DrainWorkers(
        std::shared_ptr<Application::RuntimeState> State) -> Net::awaitable<ShutdownOutcome>
    {
        if (!State || !State->Process)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
        co_return co_await State->Process->ShutdownWorkers();
    }

    /** @brief 取回有界操作的原始 typed failure；缺少 cause 时返回 Blocked。 */
    [[nodiscard]] inline auto BoundedDrainFailure(
        const ShutdownOperation::WaitResult &Result) noexcept -> Preview::Fault::Failure
    {
        if (!Result.Outcome)
        {
            return Result.Outcome.error();
        }
        return {Preview::Fault::Code::Blocked};
    }

    /**
     * @brief 按 owner 顺序排空 listener、provider、datagram 与 task。
     * @param State 持有阶段 owner 和 control ContextOwner 的运行时。
     * @param Deadline 本次 shutdown 全阶段共享的绝对截止时间。
     * @return 全部 owner 真实完成返回 success；首个失败原样返回。
     * @details 不触碰 Operations 管理入口；超时不将取消请求冒充完成。
     */
    [[nodiscard]] inline auto DrainApplicationOwners(
        std::shared_ptr<Application::RuntimeState> State,
        const ShutdownDeadline Deadline) -> Net::awaitable<ShutdownOutcome>
    {
        auto FirstFailure=std::optional<Preview::Fault::Failure>{};
        auto DatagramDrainSucceeded=!State->DatagramListener;
        if (State->QuicConnectionRegistry)
        {
            State->QuicConnectionRegistry->StopAdmission();
        }
        const auto ActiveGeneration = State->ActiveGenerationSnapshot();
        std::shared_ptr<Preview::Composition::Provider::BoundCatalog> ActiveProviders;
        if (ActiveGeneration)
        {
            ActiveProviders = ActiveGeneration->Services.Providers;
        }
        if (ActiveProviders)
        {
            ActiveProviders->Close();
        }
        else if (State->ProviderBindings)
        {
            State->ProviderBindings->Close();
        }
        if (State->Listener)
        {
            State->Listener->Stop();
            State->Listener->Registry().BeginShutdown();
            auto DrainOwner = std::move(State->Listener);
            auto Operation = DrainListener(std::move(DrainOwner));
            const auto Result = co_await ShutdownOperation::Await(
                ShutdownOperation::Request{State, Deadline, std::move(Operation)});
            if (!Result.Completed || !Result.Outcome)
            {
                const auto Cause = BoundedDrainFailure(Result);
                if (!FirstFailure) FirstFailure = Cause;
            }
        }
        if (State->DatagramListener)
        {
            State->DatagramListener->Stop(Preview::Boundary::DatagramListener::StopRequest{});
            if (State->QuicPacketGateway)
            {
                State->QuicPacketGateway->Drain();
            }
            auto DrainOwner = std::move(State->DatagramListener);
            auto Operation = DrainDatagramListener(std::move(DrainOwner));
            const auto Result = co_await ShutdownOperation::Await(
                ShutdownOperation::Request{State, Deadline, std::move(Operation)});
            if (!Result.Completed || !Result.Outcome)
            {
                const auto Cause = BoundedDrainFailure(Result);
                if (!FirstFailure) FirstFailure = Cause;
            }
            else
            {
                DatagramDrainSucceeded=true;
            }
            if (State->QuicConnectionRegistry)
            {
                (void)State->QuicConnectionRegistry->Close();
            }
            if (State->QuicPacketGateway)
            {
                State->QuicPacketGateway->Close();
            }
        }
        if (State->Tasks)
        {
            (void)State->Tasks->Cancel();
            auto DrainOwner = std::move(State->Tasks);
            auto Operation = DrainTasks(std::move(DrainOwner));
            const auto Result = co_await ShutdownOperation::Await(
                ShutdownOperation::Request{State, Deadline, std::move(Operation)});
            if (!Result.Completed || !Result.Outcome)
            {
                const auto Cause = BoundedDrainFailure(Result);
                if (!FirstFailure) FirstFailure = Cause;
            }
        }
        if(State->QuicConnectionRegistry && DatagramDrainSucceeded)
        {
            const auto CloseResult=State->QuicConnectionRegistry->Close();
            if(!CloseResult)
            {
                if(!FirstFailure)FirstFailure=CloseResult.error();
            }
        }
        if(FirstFailure)
        {
            co_return std::unexpected(*FirstFailure);
        }
        const auto Generations = co_await GenerationRetirement::DrainGenerationSnapshots(State, Deadline);
        if (!Generations)
        {
            State->ProtocolDrainFailed.store(true, std::memory_order_release);
            co_return std::unexpected(Generations.error());
        }
        co_return ShutdownOutcome{};
    }

    /** @brief 记下数据面 stage 首因并发布失败进度。 */
    inline auto FailDataPlaneShutdown(
        const std::shared_ptr<Application::RuntimeState> &State,
        const Preview::Fault::Failure Cause) noexcept -> ShutdownOutcome
    {
        const auto StoredCause = MarkShutdownDrainFailed(State, Cause);
        State->DataPlaneShutdown.store(ShutdownStage::Failed, std::memory_order_release);
        return std::unexpected(StoredCause);
    }

    /**
     * @brief 完成数据面、worker、DNS 与非管理资源的真实 retirement。
     * @param State 唯一应用 shutdown owner。
     * @param Deadline 与最后 Operations close 共用的 absolute deadline。
     * @return 全部数据面与 worker 真实退栈返回 success。
     * @details 不关闭 Operations；Running 的竞争者只拿到 Blocked，不启动重复 drain。
     */
    [[nodiscard]] inline auto DrainApplicationDataPlane(
        std::shared_ptr<Application::RuntimeState> State,
        const ShutdownDeadline Deadline) -> Net::awaitable<ShutdownOutcome>
    {
        if (!State)
        {
            co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
        auto Expected = ShutdownStage::NotStarted;
        if (!State->DataPlaneShutdown.compare_exchange_strong(
            Expected, ShutdownStage::Running, std::memory_order_acq_rel))
        {
            if (Expected == ShutdownStage::Completed)
            {
                co_return ShutdownOutcome{};
            }
            if (Expected == ShutdownStage::Failed)
            {
                if(State->QuicConnectionRegistry &&
                    State->QuicConnectionRegistry->CanRetryClose())
                {
                    const auto Retry=State->QuicConnectionRegistry->Close();
                    if(!Retry)
                    {
                        co_return std::unexpected(Retry.error());
                    }
                }
                co_return std::unexpected(State->ShutdownFailure.value_or(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked}));
            }
            co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
        if (State->Phase.load(std::memory_order_acquire) != RuntimePhase::Failed)
        {
            State->Phase.store(RuntimePhase::Stopping, std::memory_order_release);
        }
        try
        {
            const auto OwnersDrained = co_await DrainApplicationOwners(State, Deadline);
            if (!OwnersDrained)
            {
                co_return FailDataPlaneShutdown(State, OwnersDrained.error());
            }
            State->ClosingResources->Retry();
            co_await Net::post(State->Io.get_executor(), Net::use_awaitable);
            if (State->Process && !State->WorkersStarted)
            {
                co_return FailDataPlaneShutdown(State,
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            if (State->Process && State->WorkersStarted)
            {
                auto Operation = DrainWorkers(State);
                const auto Result = co_await ShutdownOperation::Await(
                    ShutdownOperation::Request{State, Deadline, std::move(Operation)});
                if (!Result.Completed || !Result.Outcome)
                {
                    co_return FailDataPlaneShutdown(State, BoundedDrainFailure(Result));
                }
                State->WorkerShutdownSucceeded.store(true, std::memory_order_release);
            }
            co_await Net::post(State->Io.get_executor(), Net::use_awaitable);
            State->ClosingResources->Collect();
            const auto DnsDrained = co_await Detail::DrainProcessDnsResolver(State, Deadline);
            if (!DnsDrained)
            {
                co_return FailDataPlaneShutdown(State, DnsDrained.error());
            }
            const auto Released = Detail::ReleaseRuntimeResources(State);
            if (!Released)
            {
                co_return FailDataPlaneShutdown(State, Released.error());
            }
            State->ClosingResources->Collect();
        }
        catch (...)
        {
            const auto ExceptionValue = std::current_exception();
            const auto Cause = MarkShutdownDrainFailed(State,
                ShutdownOperation::FailureFromException(ExceptionValue));
            State->DataPlaneShutdown.store(ShutdownStage::Failed, std::memory_order_release);
            State->ControlContext->Fatal->Publish(ExceptionValue);
            co_return std::unexpected(Cause);
        }
        State->DataPlaneShutdown.store(ShutdownStage::Completed, std::memory_order_release);
        co_return ShutdownOutcome{};
    }

    /**
     * @brief 在数据面 receipt 与管理 response delivery 后关闭 Operations 入口。
     * @param State 应用运行时与管理入口 owner。
     * @param Deadline 与数据面 drain 共用的绝对截止时间。
     * @return 管理入口真实 drain 后返回 success；未完成时保留首因和完整 owner。
     */
    [[nodiscard]] inline auto DrainOperationsServer(
        std::shared_ptr<Application::RuntimeState> State,
        const ShutdownDeadline Deadline) -> Net::awaitable<ShutdownOutcome>
    {
        if (!State)
        {
            co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
        const auto DataPlaneState = State->DataPlaneShutdown.load(std::memory_order_acquire);
        if (DataPlaneState == ShutdownStage::NotStarted || DataPlaneState == ShutdownStage::Running)
        {
            co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
        auto Expected = ShutdownStage::NotStarted;
        if (!State->OperationsShutdown.compare_exchange_strong(
            Expected, ShutdownStage::Running, std::memory_order_acq_rel))
        {
            if (Expected == ShutdownStage::Completed)
            {
                co_return ShutdownOutcome{};
            }
            if (Expected == ShutdownStage::Failed)
            {
                co_return std::unexpected(State->ShutdownFailure.value_or(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked}));
            }
            co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
        if (!State->ManagementController)
        {
            State->OperationsShutdown.store(ShutdownStage::Completed, std::memory_order_release);
            if (DataPlaneState == ShutdownStage::Completed)
            {
                State->Phase.store(RuntimePhase::Stopped, std::memory_order_release);
            }
            co_return ShutdownOutcome{};
        }
        auto Operation = DrainManagementController(*State->ManagementController, Deadline);
        try
        {
            const auto Result = co_await ShutdownOperation::Await(
                ShutdownOperation::Request{State, Deadline, std::move(Operation)});
            if (!Result.Completed || !Result.Outcome)
            {
                const auto Cause = MarkShutdownDrainFailed(
                    State, BoundedDrainFailure(Result));
                State->OperationsShutdown.store(ShutdownStage::Failed, std::memory_order_release);
                co_return std::unexpected(Cause);
            }
        }
        catch (...)
        {
            const auto ExceptionValue = std::current_exception();
            const auto Cause = MarkShutdownDrainFailed(State,
                ShutdownOperation::FailureFromException(ExceptionValue));
            State->OperationsShutdown.store(ShutdownStage::Failed, std::memory_order_release);
            State->ControlContext->Fatal->Publish(ExceptionValue);
            co_return std::unexpected(Cause);
        }
        State->OperationsShutdown.store(ShutdownStage::Completed, std::memory_order_release);
        if (DataPlaneState == ShutdownStage::Completed)
        {
            State->Phase.store(RuntimePhase::Stopped, std::memory_order_release);
        }
        co_return ShutdownOutcome{};
    }

} // namespace Preview::Application::Shutdown
