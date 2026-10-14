/**
 * @file OperationsDrain.hpp
 * @brief 管理面账户、会话和进程排空命令的异步装配 owner。
 * @details ProcessDrain 依次等待已接受命令、数据面、终态、HTTP 回执和管理入口。
 */
#pragma once

#include <Preview/Application/CommandOperationOwner.hpp>
#include <Preview/Application/OperationsEventProducer.hpp>
#include <Preview/Application/RuntimeState.hpp>
#include <Preview/Application/Shutdown.hpp>
#include <Preview/Application/Shutdown/BoundedOperation.hpp>
#include <Preview/Contract/Ingress/StreamCatalog.hpp>
#include <Preview/Operations/Models.hpp>
#include <Preview/Operations/Router.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <exception>
#include <memory>
#include <utility>

namespace Preview::Application::OperationsDrain
{

    namespace Net = boost::asio;
    using RuntimeState = Preview::Application::Application::RuntimeState;
    using ShutdownOutcome = Preview::Application::Shutdown::ShutdownOutcome;
    using ShutdownDeadline = Preview::Application::Shutdown::ShutdownDeadline;
    using Preview::Application::CommandOperationOwner::FailureFromException;
    using Preview::Application::CommandOperationOwner::ScopedCommandRequest;
    using Preview::Application::CommandOperationOwner::StartScopedCommand;

    [[nodiscard]] inline auto IsTransientAdmissionBusy(
        const Preview::Fault::Failure Failure) noexcept -> bool
    {
        const auto RegistryBusy = Preview::Account::MakeFailure(
            Preview::Account::FailureReason::Busy);
        return Failure.Code == Preview::Fault::Code::WouldBlock ||
            (Failure.Native && Failure.Native == RegistryBusy.Native);
    }

    /** @brief 在账户准入读预约退出前异步重试撤销，不延长命令的绝对期限。 */
    [[nodiscard]] inline auto RevokeUntilReady(
        const std::shared_ptr<Preview::Account::AccountStore> &Store,
        const Preview::AccountId Id,
        const ShutdownDeadline Deadline) -> Net::awaitable<ShutdownOutcome>
    {
        for (;;)
        {
            const auto Revoked = Store->Revoke(Id);
            if (Revoked)
            {
                co_return ShutdownOutcome{};
            }
            if (!IsTransientAdmissionBusy(Revoked.error()))
            {
                co_return std::unexpected(Revoked.error());
            }
            if (std::chrono::steady_clock::now() >= Deadline)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Timeout});
            }
            Net::steady_timer Retry(co_await Net::this_coro::executor);
            Retry.expires_after(std::chrono::milliseconds(1));
            boost::system::error_code WaitError;
            co_await Retry.async_wait(Net::redirect_error(Net::use_awaitable, WaitError));
            if (WaitError)
            {
                co_return std::unexpected(Preview::Fault::FromNative(
                    static_cast<std::error_code>(WaitError)));
            }
        }
    }

    /** @brief 一次 worker drain 固定的 typed identity 与绝对 deadline。 */
    struct WorkerDrainRequest final
    {
        Preview::WorkerId Worker{};
        Preview::GenerationId Generation{};
        ShutdownDeadline Deadline;
    };

    /** @brief 已接受进程排空的终态回执与目标身份。 */
    struct ProcessDrainOperation final
    {
        Preview::Operations::OperationCompletion Completion;
        Preview::RequestId Correlation{};
        Preview::Operations::CommandTargetScope Target;
    };

    /** @brief 保留顺序中首个失败；后续关闭阶段仍继续执行。 */
    inline auto KeepFirstFailure(ShutdownOutcome &Current,
                                 const Preview::Fault::Failure Cause) noexcept -> void
    {
        if (Current)
        {
            Current = std::unexpected(Cause);
        }
    }

    /** @brief 先 Revoke 封止准入，再按同一绝对期限等待真实 session 与 lease 退休。 */
    [[nodiscard]] inline auto DrainAccountSessions(
        const std::shared_ptr<RuntimeState> &State,
        const std::shared_ptr<const Preview::Account::AccountBinding> &Binding,
        const ShutdownDeadline Deadline) -> Net::awaitable<ShutdownOutcome>
    {
        if (!State || !Binding)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
        const auto Runtime = Binding->Runtime();
        if (!Runtime)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
        if (State->Listener)
        {
            const auto Sessions = co_await State->Listener->Registry().CancelAccountAndDrain(
                Binding->AccountId(), Runtime->RuntimeIdentity());
            if (!Sessions)
            {
                co_return std::unexpected(Sessions.error());
            }
        }
        const auto Leases = co_await Runtime->WaitForNoActiveConnections(Deadline);
        if (!Leases)
        {
            co_return std::unexpected(Leases.error());
        }
        if (State->Listener)
        {
            const auto GateReleased = State->Listener->Registry().ReleaseAccountRuntimeGate(
                Binding->AccountId(), Runtime->RuntimeIdentity());
            if (!GateReleased)
            {
                co_return std::unexpected(GateReleased.error());
            }
        }
        co_return ShutdownOutcome{};
    }

    /** @brief 一次账户撤销操作所拥有的绑定、命令值和绝对截止时间。 */
    struct AccountRevokeRequest final
    {
        std::shared_ptr<const Preview::Account::AccountBinding> Binding;
        Preview::Operations::RevokeCommand Command;
        ShutdownDeadline Deadline;
    };

    /** @brief 由已接受命令 owner 执行 Revoke，并等待可选的账户范围真实排空。 */
    [[nodiscard]] inline auto RevokeAndDrainAccount(
        std::shared_ptr<RuntimeState> State,
        AccountRevokeRequest Request) -> Net::awaitable<ShutdownOutcome>
    {
        const auto Generation = State ? State->ActiveGenerationSnapshot() : nullptr;
        if (!State || !Generation || !Generation->Accounts.Store || !Request.Binding)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
        if (Request.Binding->AccountId() != Request.Command.Account)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
        }
        const auto Runtime = Request.Binding->Runtime();
        if (!Runtime)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
        const auto Revoked = co_await RevokeUntilReady(
            Generation->Accounts.Store, Request.Command.Account, Request.Deadline);
        if (!Revoked)
        {
            co_return std::unexpected(Revoked.error());
        }
        if (!Request.Command.CloseSessions)
        {
            co_return ShutdownOutcome{};
        }
        co_return co_await DrainAccountSessions(State, Request.Binding, Request.Deadline);
    }

    /** @brief 分配已接受 Operation，再由真实 owner 运行 Revoke 和排空。 */
    [[nodiscard]] inline auto StartAccountRevoke(
        const std::shared_ptr<RuntimeState> &State,
        const Preview::Operations::RevokeCommand &Command,
        const Preview::Operations::OperationCompletion &Completion)
        -> Preview::Operations::CommandResult
    {
        const auto Generation = State->ActiveGenerationSnapshot();
        if (!Generation || !Generation->Accounts.Store)
        {
            return Preview::Operations::CommandResult::Unavailable(Command.Correlation);
        }
        const auto Binding = Generation->Accounts.Store->FindById(Command.Account);
        if (!Binding)
        {
            auto Rejected = Preview::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "account_unavailable";
            return Rejected;
        }
        const auto Deadline =
            std::chrono::steady_clock::now() + State->ShutdownTimeout;
        auto Result = StartScopedCommand(ScopedCommandRequest{
            State, Completion, Command.Correlation, Deadline,
            Preview::Operations::CommandTargetScope{Preview::Operations::AccountTargetScope{
                Generation->Id(), Command.Account}},
            RevokeAndDrainAccount(State, AccountRevokeRequest{Binding, Command, Deadline})});
        return Result;
    }

    /** @brief 按唯一会话 ID 取消并等待对应 Session owner 真实退栈。 */
    [[nodiscard]] inline auto StartSessionCancel(
        const std::shared_ptr<RuntimeState> &State,
        const Preview::Operations::CancelCommand &Command,
        const Preview::Operations::OperationCompletion &Completion)
        -> Preview::Operations::CommandResult
    {
        if (!State->Process || !State->Listener || !Command.Session ||
            (Command.Process && Command.Process != State->Process->Id()))
        {
            auto Rejected = Preview::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "session_scope_mismatch";
            return Rejected;
        }
        Preview::Runtime::SessionInfo Session;
        if (!State->Listener->Registry().Find(Command.Session.Value(), Session))
        {
            auto Rejected = Preview::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "session_unavailable";
            return Rejected;
        }
        if ((Command.Worker && Command.Worker != Session.Worker) ||
            (Command.Generation && Command.Generation != Session.Generation))
        {
            auto Rejected = Preview::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "session_scope_mismatch";
            return Rejected;
        }
        if (Command.Stream || Command.ParentTask || Command.Task)
        {
            auto Rejected = Preview::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "scoped_child_owner_unavailable";
            return Rejected;
        }
        const auto Deadline =
            std::chrono::steady_clock::now() + State->ShutdownTimeout;
        auto Result = StartScopedCommand(ScopedCommandRequest{
            State, Completion, Command.Correlation, Deadline,
            Preview::Operations::CommandTargetScope{Preview::Operations::SessionTargetScope{
                State->Process->Id(), Session.Generation, Session.Worker, Command.Session}},
            State->Listener->Registry().CancelAndDrain(Command.Session.Value())});
        return Result;
    }

    /** @brief 校验完整父 scope 并提交单一 stream reset 的真实退休操作。 */
    [[nodiscard]] inline auto StartStreamReset(
        const std::shared_ptr<RuntimeState> &State,
        const Preview::Operations::StreamResetCommand &Command,
        const Preview::Operations::OperationCompletion &Completion)
        -> Preview::Operations::CommandResult
    {
        if (!State->Process || !State->Listener || !Command.Process ||
            Command.Process != State->Process->Id() || !Command.Session ||
            !Command.Worker || !Command.Generation || !Command.Stream ||
            !Command.ParentTask || !Command.Task)
        {
            auto Rejected = Preview::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "bad_stream_scope";
            return Rejected;
        }
        Preview::Runtime::SessionInfo Session;
        if (!State->Listener->Registry().Find(Command.Session.Value(), Session))
        {
            auto Rejected = Preview::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "session_unavailable";
            return Rejected;
        }
        if (Session.Worker != Command.Worker || Session.Generation != Command.Generation)
        {
            auto Rejected = Preview::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "session_scope_mismatch";
            return Rejected;
        }
        const Preview::Contract::Ingress::StreamResetRequest Request{
            .Identity = {Command.Session, Command.Worker, Command.Generation, Command.Stream},
            .Task = Command.Task,
            .ParentTask = Command.ParentTask};
        const auto Deadline = std::chrono::steady_clock::now() + State->ShutdownTimeout;
        auto Result = StartScopedCommand(ScopedCommandRequest{
            State, Completion, Command.Correlation, Deadline,
            Preview::Operations::CommandTargetScope{Preview::Operations::StreamTargetScope{
                Command.Process, Command.Generation, Command.Worker, Command.Session,
                Command.Stream, Command.ParentTask, Command.Task}},
            State->Listener->Registry().ResetStreamAndDrain(Request)});
        return Result;
    }

    /** @brief 按绝对期限等待单一 worker 的 admission、session 和 task owner 真实退休。 */
    [[nodiscard]] inline auto DrainWorkerOwner(
        std::shared_ptr<RuntimeState> State,
        WorkerDrainRequest Request) -> Net::awaitable<ShutdownOutcome>
    {
        if (!State || !State->Process)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
        if (const auto *Worker = State->Process->Workers().Find(Request.Worker);
            !Worker || !State->GenerationPublisher->Contains(Request.Generation))
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
        }
        auto Drain = State->Process->Workers().DrainWorker(
            Request.Worker, Request.Generation);
        const auto Result = co_await Shutdown::ShutdownOperation::Await(
            Shutdown::ShutdownOperation::Request{State, Request.Deadline, std::move(Drain)});
        if (!Result.Completed || !Result.Outcome)
        {
            co_return std::unexpected(Shutdown::BoundedDrainFailure(Result));
        }
        if (State->Listener)
        {
            const auto Sessions = State->Listener->Registry().Snapshot();
            for (const auto &[Id, Session] : *Sessions)
            {
                (void)Id;
                if (Session.Worker == Request.Worker)
                {
                    co_return std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                }
            }
        }
        auto *RetiredWorker = State->Process->Workers().Find(Request.Worker);
        if (!RetiredWorker)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
        const auto Snapshot = RetiredWorker->Snapshot();
        if (Snapshot.Accepting || Snapshot.ActiveTasks != 0 || Snapshot.MailboxSize != 0)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
        co_return ShutdownOutcome{};
    }

    /** @brief 返回 Accepted 并由 deadline owner drain 指定 worker；force 暂无安全语义。 */
    [[nodiscard]] inline auto StartWorkerDrain(
        const std::shared_ptr<RuntimeState> &State,
        const Preview::Operations::WorkerDrainCommand &Command,
        const Preview::Operations::OperationCompletion &Completion)
        -> Preview::Operations::CommandResult
    {
        if (Command.Force)
        {
            auto Rejected = Preview::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "force_worker_drain_unsupported";
            Rejected.Worker = Command.Worker;
            return Rejected;
        }
        if (!State || !State->Process || !Command.Worker)
        {
            auto Rejected = Preview::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "worker_scope_mismatch";
            Rejected.Worker = Command.Worker;
            return Rejected;
        }
        const auto Generation = State->Process->Workers().Generation();
        const auto *Worker = State->Process->Workers().Find(Command.Worker);
        if (!Worker || Worker->Generation() != Generation)
        {
            auto Rejected = Preview::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "worker_scope_mismatch";
            Rejected.Worker = Command.Worker;
            return Rejected;
        }
        const auto Deadline =
            std::chrono::steady_clock::now() + State->ShutdownTimeout;
        auto Result = StartScopedCommand(ScopedCommandRequest{
            State, Completion, Command.Correlation, Deadline,
            Preview::Operations::CommandTargetScope{Preview::Operations::WorkerTargetScope{
                State->Process->Id(), Generation, Command.Worker}},
            DrainWorkerOwner(State, WorkerDrainRequest{Command.Worker, Generation, Deadline})});
        return Result;
    }

    /**
     * @brief 执行 ProcessDrain 的真实阶段并发布唯一进程关闭结果。
     * @param State 持有应用阶段、管理 server 和关闭协调器的运行时。
     * @param Operation 已接受命令的终态回执、correlation 与目标作用域。
     * @return 最终发布后退栈；Operation 结果只反映数据面真实 receipt。
     */
    [[nodiscard]] inline auto RunProcessDrain(
        std::shared_ptr<RuntimeState> State,
        ProcessDrainOperation Operation) -> Net::awaitable<void>
    {
        const auto EventIdentity =
            Preview::Application::OperationsEventProducer::MakeProcessDrainIdentity(
                State, Preview::Application::OperationsEventProducer::ProcessDrainIdentityInput{
                    Operation.Completion.Id(), Operation.Correlation, Operation.Target});
        Preview::Application::OperationsEventProducer::AppendAccepted(State, EventIdentity);
        const ShutdownDeadline Deadline =
            std::chrono::steady_clock::now() + State->ShutdownTimeout;
        ShutdownOutcome FinalOutcome;
        try
        {
            const auto PriorOperations =
                co_await Operation.Completion.WaitForPriorOperationsAsync(Deadline);
            if (!PriorOperations)
            {
                KeepFirstFailure(FinalOutcome, PriorOperations.error());
            }
        }
        catch (...)
        {
            KeepFirstFailure(FinalOutcome,
                FailureFromException(std::current_exception()));
        }

        try
        {
            const auto DataPlane = co_await
                Preview::Application::Shutdown::DrainApplicationDataPlane(State, Deadline);
            if (!DataPlane)
            {
                KeepFirstFailure(FinalOutcome, DataPlane.error());
            }
        }
        catch (...)
        {
            KeepFirstFailure(FinalOutcome,
                FailureFromException(std::current_exception()));
        }

        Preview::Operations::CommandResult Terminal;
        if (FinalOutcome)
        {
            Terminal = Preview::Operations::CommandResult::Completed(Operation.Correlation);
        }
        else
        {
            Terminal = Preview::Operations::CommandResult::FromFailure(
                Operation.Correlation, FinalOutcome.error());
        }
        Preview::Operations::ApplyCommandTarget(Terminal, Operation.Target);

        std::expected<Preview::Operations::OperationPublicationReceipt, Preview::Fault::Failure>
            CompletionPublished{std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked})};
        const auto TerminalSucceeded = static_cast<bool>(FinalOutcome);
        bool TerminalPublished = false;
        try
        {
            CompletionPublished = co_await Operation.Completion.CompleteAsync(std::move(Terminal));
            TerminalPublished = static_cast<bool>(CompletionPublished);
        }
        catch (...)
        {
            KeepFirstFailure(FinalOutcome, FailureFromException(std::current_exception()));
        }
        if (!CompletionPublished)
        {
            KeepFirstFailure(FinalOutcome, CompletionPublished.error());
        }
        if (TerminalPublished)
        {
            Preview::Application::OperationsEventProducer::AppendTerminal(
                State, EventIdentity, TerminalSucceeded);
            if (CompletionPublished->WaiterSignalFailure.Failed())
            {
                KeepFirstFailure(FinalOutcome, CompletionPublished->WaiterSignalFailure);
                State->ObservationFailures.fetch_add(1U, std::memory_order_relaxed);
            }
        }

        Preview::Operations::ResponseDeliveryReceipt::Outcome Delivery;
        try
        {
            Delivery = co_await Operation.Completion.WaitForResponseDeliveryAsync(Deadline);
        }
        catch (...)
        {
            Delivery = std::unexpected(FailureFromException(std::current_exception()));
        }
        if (!Delivery)
        {
            KeepFirstFailure(FinalOutcome, Delivery.error());
        }

        ShutdownOutcome Operations;
        try
        {
            Operations = co_await Preview::Application::Shutdown::DrainOperationsServer(
                State, Deadline);
        }
        catch (...)
        {
            Operations = std::unexpected(FailureFromException(std::current_exception()));
        }
        if (!Operations)
        {
            KeepFirstFailure(FinalOutcome, Operations.error());
        }

        const auto Published = co_await
            Preview::Application::Shutdown::PublishShutdownResult(State, std::move(FinalOutcome));
        if (!Published)
        {
            (void)State->RecordShutdownFailure(Published.error());
        }
        co_return;
    }

    /** @brief 取得唯一 shutdown gate 后提交后台 ProcessDrain；输家立即 Rejected。 */
    [[nodiscard]] inline auto StartProcessDrain(
        const std::shared_ptr<RuntimeState> &State,
        const Preview::Operations::ProcessDrainCommand &Command,
        const Preview::Operations::OperationCompletion &Completion)
        -> Preview::Operations::CommandResult
    {
        if (!State || !State->Process)
        {
            return Preview::Operations::CommandResult::Unavailable(Command.Correlation);
        }
        if (Command.Force)
        {
            auto Result = Preview::Operations::CommandResult::Rejected(Command.Correlation);
            Result.Message = "force_drain_unsupported";
            return Result;
        }
        if (!Preview::Application::Shutdown::TryClaimShutdown(State))
        {
            auto Result = Preview::Operations::CommandResult::Rejected(Command.Correlation);
            Result.Message = "shutdown_already_scheduled";
            return Result;
        }
        const Preview::Operations::CommandTargetScope Target{
            Preview::Operations::ProcessTargetScope{State->Process->Id()}};

        try
        {
            Net::co_spawn(State->ShutdownCoordinator,
                RunProcessDrain(State, ProcessDrainOperation{
                    Completion, Command.Correlation, Target}),
                [State](std::exception_ptr Exception) noexcept
                {
                    Preview::Application::Shutdown::OnShutdownDriverComplete(
                        State, std::move(Exception));
                });
        }
        catch (...)
        {
            const auto Exception = std::current_exception();
            const auto Cause = FailureFromException(Exception);
            (void)State->RecordShutdownFailure(Cause);
            Preview::Application::Shutdown::OnShutdownDriverComplete(State, Exception);
            auto Result = Preview::Operations::CommandResult::FromFailure(
                Command.Correlation, Cause);
            Preview::Operations::ApplyCommandTarget(Result, Target);
            return Result;
        }
        auto Result = Preview::Operations::CommandResult::Accepted(
            Command.Correlation, Completion.Id());
        Preview::Operations::ApplyCommandTarget(Result, Target);
        return Result;
    }

} // namespace Preview::Application::OperationsDrain
