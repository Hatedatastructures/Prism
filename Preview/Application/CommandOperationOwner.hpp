/**
 * @file CommandOperationOwner.hpp
 * @brief 管理 scoped command 的真实执行 owner 与唯一终态发布
 * @details 实际命令 awaitable 退栈后，同一个 owner coroutine 提交 Router 终态；
 *          wrapper 自身返回不代表业务资源退栈。
 */
#pragma once

#include <Preview/Application/OperationsEventProducer.hpp>
#include <Preview/Application/RuntimeState.hpp>
#include <Preview/Application/Shutdown.hpp>
#include <Preview/Operations/Models.hpp>
#include <Preview/Operations/Router.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/system/system_error.hpp>

#include <chrono>
#include <exception>
#include <memory>
#include <system_error>
#include <utility>

namespace Preview::Application::CommandOperationOwner
{
    namespace Net = boost::asio;
    using RuntimeState = Preview::Application::Application::RuntimeState;
    using ShutdownOutcome = Preview::Application::Shutdown::ShutdownOutcome;
    using ShutdownDeadline = Preview::Application::Shutdown::ShutdownDeadline;

    /** @brief 异常边界保留原生 cause；无 system_error 时使用明确 I/O 失败。 */
    [[nodiscard]] inline auto FailureFromException(const std::exception_ptr Error) noexcept
        -> Preview::Fault::Failure
    {
        if (!Error)
        {
            return {Preview::Fault::Code::GenericError};
        }
        try
        {
            std::rethrow_exception(Error);
        }
        catch (const std::system_error &Native)
        {
            return Preview::Fault::FromNative(Native.code());
        }
        catch (const boost::system::system_error &Native)
        {
            return Preview::Fault::FromNative(static_cast<std::error_code>(Native.code()));
        }
        catch (...)
        {
            return {Preview::Fault::Code::IoError};
        }
    }

    /** @brief 一次异步命令接受响应与终态共享的固定身份。 */
    struct ScopedCommandRequest final
    {
        std::shared_ptr<RuntimeState> State;
        Preview::Operations::OperationCompletion Completion;
        Preview::RequestId Correlation{};
        ShutdownDeadline Deadline;
        const Preview::Operations::CommandTargetScope Target;
        Net::awaitable<ShutdownOutcome> Operation;
        Preview::GenerationId ResultGeneration{};
    };

    /** @brief 保活真实完成所需应用、Router、executor 和目标身份直到终态提交结束。 */
    struct ScopedCommandOwner final
    {
        ScopedCommandOwner(
            const ScopedCommandRequest &Request,
            Preview::Application::OperationsEventProducer::Identity EventIdentityValue)
            : RuntimePin(Request.State),
              ContextPin(Request.State->ControlContext),
              ControllerPin(Request.State->ManagementController),
              Completion(Request.Completion),
              EventIdentity(std::move(EventIdentityValue)),
              Deadline(Request.Deadline)
        {
        }

        std::shared_ptr<RuntimeState> RuntimePin;
        std::shared_ptr<Preview::Executor::ContextOwner> ContextPin;
        std::shared_ptr<Preview::Operations::Controller> ControllerPin;
        Preview::Operations::OperationCompletion Completion;
        Preview::Application::OperationsEventProducer::Identity EventIdentity;
        ShutdownDeadline Deadline;
    };

    /** @brief 从一次预登记命令构造固定事件身份；Process generation 在提交时捕获。 */
    [[nodiscard]] inline auto MakeEventIdentity(const ScopedCommandRequest &Request)
        -> Preview::Application::OperationsEventProducer::Identity
    {
        auto Generation = Request.ResultGeneration;
        if (!Generation)
        {
            const auto Snapshot = Request.State->ActiveGenerationSnapshot();
            if (Snapshot)
            {
                Generation = Snapshot->Id();
            }
        }
        return Preview::Application::OperationsEventProducer::Identity{
            Request.State->Process->Id(), Generation, Request.Completion.Id(),
            Request.Correlation, Request.Target};
    }

    /** @brief 终态未提交或等待者通知失败时记录原因并交给唯一进程停机 owner。 */
    inline auto RecordTerminalPublicationFailure(
        const std::shared_ptr<ScopedCommandOwner> &Owner,
        const Preview::Fault::Failure Cause) noexcept -> void
    {
        (void)Owner->RuntimePin->RecordShutdownFailure(Cause);
        Owner->RuntimePin->ObservationFailures.fetch_add(1U, std::memory_order_relaxed);
        Preview::Application::Shutdown::ScheduleShutdown(Owner->RuntimePin);
    }

    /** @brief 保有命令 owner 直至实际操作退栈并提交其唯一终态。 */
    [[nodiscard]] inline auto RunScopedCommandOperation(
        std::shared_ptr<ScopedCommandOwner> Owner,
        Net::awaitable<ShutdownOutcome> Operation) -> Net::awaitable<void>
    {
        Preview::Application::OperationsEventProducer::Append(
            Owner->RuntimePin,
            Preview::Application::OperationsEventProducer::MakeAccepted(Owner->EventIdentity));
        ShutdownOutcome Outcome;
        try
        {
            Outcome = co_await std::move(Operation);
        }
        catch (...)
        {
            Outcome = std::unexpected(FailureFromException(std::current_exception()));
        }
        const auto CompletedAt = std::chrono::steady_clock::now();
        if (Outcome && CompletedAt >= Owner->Deadline)
        {
            Outcome = std::unexpected(Preview::Fault::Failure{
                Preview::Fault::Code::Timeout, std::make_error_code(std::errc::timed_out)});
        }

        try
        {
            Preview::Operations::CommandResult Terminal;
            if (Outcome)
            {
                Terminal = Preview::Operations::CommandResult::Completed(
                    Owner->EventIdentity.Correlation, {}, Owner->EventIdentity.Generation);
            }
            else
            {
                Terminal = Preview::Operations::CommandResult::FromFailure(
                    Owner->EventIdentity.Correlation, Outcome.error());
            }
            Preview::Operations::ApplyCommandTarget(Terminal, Owner->EventIdentity.Target);
            const auto Published = co_await Owner->Completion.CompleteAsync(std::move(Terminal));
            if (!Published)
            {
                RecordTerminalPublicationFailure(Owner, Published.error());
                co_return;
            }
            if (Published->WaiterSignalFailure.Failed())
            {
                RecordTerminalPublicationFailure(Owner, Published->WaiterSignalFailure);
            }
        }
        catch (...)
        {
            RecordTerminalPublicationFailure(
                Owner, FailureFromException(std::current_exception()));
            co_return;
        }

        Preview::Application::OperationsEventProducer::Append(
            Owner->RuntimePin,
            Preview::Application::OperationsEventProducer::MakeTerminal(
                Owner->EventIdentity, static_cast<bool>(Outcome)));
        co_return;
    }

    /**
     * @brief 预登记并提交 scoped operation；提交失败不产生 Accepted 事件。
     * @details Operation 按值移交到应用 ShutdownCoordinator；调用者构造的实际 owner 继续负责取消、
     *          半关闭与最终关闭。操作协程在自身退栈后，由同一个 owner coroutine 提交 typed 终态并追加事件，
     *          避免通过第二次 co_spawn 延迟其 owner。deadline 后成功映射 Timeout；既有 typed Failure 保留原 Native cause。
     * @param Request 已预登记 OperationId、绝对期限、target 和实际命令 awaitable。
     * @return Operation 已成功提交时返回 Accepted；其他情况返回带原 target 的 typed 非 Accepted 结果。
     * @note 本函数在调用者的 control executor 同步提交；取消与传输关闭仍由 Request.Operation 的真实 owner 执行。
     */
    [[nodiscard]] inline auto StartScopedCommand(ScopedCommandRequest Request)
        -> Preview::Operations::CommandResult
    {
        if (!Request.State || !Request.State->Process || !Request.State->ManagementController)
        {
            auto Result = Preview::Operations::CommandResult::Blocked(
                Request.Correlation,
                Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            Preview::Operations::ApplyCommandTarget(Result, Request.Target);
            return Result;
        }

        try
        {
            auto Owner = std::make_shared<ScopedCommandOwner>(Request, MakeEventIdentity(Request));
            Net::co_spawn(Request.State->ShutdownCoordinator,
                RunScopedCommandOperation(Owner, std::move(Request.Operation)),
                [Owner](std::exception_ptr Exception) noexcept
                {
                    if (Exception)
                    {
                        RecordTerminalPublicationFailure(
                            Owner, FailureFromException(Exception));
                    }
                });
        }
        catch (...)
        {
            auto Result = Preview::Operations::CommandResult::FromFailure(
                Request.Correlation, FailureFromException(std::current_exception()));
            Preview::Operations::ApplyCommandTarget(Result, Request.Target);
            return Result;
        }

        auto Result = Preview::Operations::CommandResult::Accepted(
            Request.Correlation, Request.Completion.Id());
        Preview::Operations::ApplyCommandTarget(Result, Request.Target);
        return Result;
    }
}
