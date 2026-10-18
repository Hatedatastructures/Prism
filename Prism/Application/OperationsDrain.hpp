/**
 * @file OperationsDrain.hpp
 * @brief 管理面账户、会话和进程排空命令的异步装配 owner。
 * @details ProcessDrain 依次等待已接受命令、数据面、终态、HTTP 回执和管理入口。
 */
#pragma once

#include <Prism/Application/CommandOperationOwner.hpp>
#include <Prism/Application/OperationsEventProducer.hpp>
#include <Prism/Application/RuntimeState.hpp>
#include <Prism/Application/Shutdown.hpp>
#include <Prism/Application/Shutdown/BoundedOperation.hpp>
#include <Prism/Contract/Ingress/StreamCatalog.hpp>
#include <Prism/Operations/Models.hpp>
#include <Prism/Operations/Router.hpp>

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

namespace Prism::Application::OperationsDrain
{

    namespace Net = boost::asio;
    using RuntimeState = Prism::Application::Application::RuntimeState;
    using ShutdownOutcome = Prism::Application::Shutdown::ShutdownOutcome;
    using ShutdownDeadline = Prism::Application::Shutdown::ShutdownDeadline;
    using Prism::Application::CommandOperationOwner::FailureFromException;
    using Prism::Application::CommandOperationOwner::ScopedCommandRequest;
    using Prism::Application::CommandOperationOwner::StartScopedCommand;

    [[nodiscard]] inline auto IsTransientAdmissionBusy(
        const Prism::Fault::Failure Failure) noexcept -> bool
    {
        const auto RegistryBusy = Prism::Account::MakeFailure(
            Prism::Account::FailureReason::Busy);
        return Failure.Code == Prism::Fault::Code::WouldBlock ||
            (Failure.Native && Failure.Native == RegistryBusy.Native);
    }

    /** @brief 在账户准入读预约退出前异步重试撤销，不延长命令的绝对期限。 */
    [[nodiscard]] inline auto RevokeUntilReady(
        const std::shared_ptr<Prism::Account::AccountStore> &Store,
        const Prism::AccountId Id,
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
                    Prism::Fault::Failure{Prism::Fault::Code::Timeout});
            }
            Net::steady_timer Retry(co_await Net::this_coro::executor);
            Retry.expires_after(std::chrono::milliseconds(1));
            boost::system::error_code WaitError;
            co_await Retry.async_wait(Net::redirect_error(Net::use_awaitable, WaitError));
            if (WaitError)
            {
                co_return std::unexpected(Prism::Fault::FromNative(
                    static_cast<std::error_code>(WaitError)));
            }
        }
    }

    /** @brief 一次 worker drain 固定的 typed identity 与绝对 deadline。 */
    struct WorkerDrainRequest final
    {
        Prism::WorkerId Worker{};
        Prism::GenerationId Generation{};
        ShutdownDeadline Deadline;
    };

    /** @brief 已接受进程排空的终态回执与目标身份。 */
    struct ProcessDrainOperation final
    {
        Prism::Operations::OperationCompletion Completion;
        Prism::RequestId Correlation{};
        Prism::Operations::CommandTargetScope Target;
    };

    /** @brief 保留顺序中首个失败；后续关闭阶段仍继续执行。 */
    inline auto KeepFirstFailure(ShutdownOutcome &Current,
                                 const Prism::Fault::Failure Cause) noexcept -> void
    {
        if (Current)
        {
            Current = std::unexpected(Cause);
        }
    }

    /** @brief 先 Revoke 封止准入，再按同一绝对期限等待真实 session 与 lease 退休。 */
    [[nodiscard]] inline auto DrainAccountSessions(
        const std::shared_ptr<RuntimeState> &State,
        const std::shared_ptr<const Prism::Account::AccountBinding> &Binding,
        const ShutdownDeadline Deadline) -> Net::awaitable<ShutdownOutcome>
    {
        if (!State || !Binding)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        const auto Runtime = Binding->Runtime();
        if (!Runtime)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
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
        std::shared_ptr<const Prism::Account::AccountBinding> Binding;
        Prism::Operations::RevokeCommand Command;
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
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        if (Request.Binding->AccountId() != Request.Command.Account)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        const auto Runtime = Request.Binding->Runtime();
        if (!Runtime)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
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
        const Prism::Operations::RevokeCommand &Command,
        const Prism::Operations::OperationCompletion &Completion)
        -> Prism::Operations::CommandResult
    {
        const auto Generation = State->ActiveGenerationSnapshot();
        if (!Generation || !Generation->Accounts.Store)
        {
            return Prism::Operations::CommandResult::Unavailable(Command.Correlation);
        }
        const auto Binding = Generation->Accounts.Store->FindById(Command.Account);
        if (!Binding)
        {
            auto Rejected = Prism::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "account_unavailable";
            return Rejected;
        }
        const auto Deadline =
            std::chrono::steady_clock::now() + State->ShutdownTimeout;
        auto Result = StartScopedCommand(ScopedCommandRequest{
            State, Completion, Command.Correlation, Deadline,
            Prism::Operations::CommandTargetScope{Prism::Operations::AccountTargetScope{
                Generation->Id(), Command.Account}},
            RevokeAndDrainAccount(State, AccountRevokeRequest{Binding, Command, Deadline})});
        return Result;
    }

    /** @brief 按唯一会话 ID 取消并等待对应 Session owner 真实退栈。 */
    [[nodiscard]] inline auto StartSessionCancel(
        const std::shared_ptr<RuntimeState> &State,
        const Prism::Operations::CancelCommand &Command,
        const Prism::Operations::OperationCompletion &Completion)
        -> Prism::Operations::CommandResult
    {
        if (!State->Process || !State->Listener || !Command.Session ||
            (Command.Process && Command.Process != State->Process->Id()))
        {
            auto Rejected = Prism::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "session_scope_mismatch";
            return Rejected;
        }
        Prism::Runtime::SessionInfo Session;
        if (!State->Listener->Registry().Find(Command.Session.Value(), Session))
        {
            auto Rejected = Prism::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "session_unavailable";
            return Rejected;
        }
        if ((Command.Worker && Command.Worker != Session.Worker) ||
            (Command.Generation && Command.Generation != Session.Generation))
        {
            auto Rejected = Prism::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "session_scope_mismatch";
            return Rejected;
        }
        if (Command.Stream || Command.ParentTask || Command.Task)
        {
            auto Rejected = Prism::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "scoped_child_owner_unavailable";
            return Rejected;
        }
        const auto Deadline =
            std::chrono::steady_clock::now() + State->ShutdownTimeout;
        auto Result = StartScopedCommand(ScopedCommandRequest{
            State, Completion, Command.Correlation, Deadline,
            Prism::Operations::CommandTargetScope{Prism::Operations::SessionTargetScope{
                State->Process->Id(), Session.Generation, Session.Worker, Command.Session}},
            State->Listener->Registry().CancelAndDrain(Command.Session.Value())});
        return Result;
    }

    /** @brief 校验完整父 scope 并提交单一 stream reset 的真实退休操作。 */
    [[nodiscard]] inline auto StartStreamReset(
        const std::shared_ptr<RuntimeState> &State,
        const Prism::Operations::StreamResetCommand &Command,
        const Prism::Operations::OperationCompletion &Completion)
        -> Prism::Operations::CommandResult
    {
        if (!State->Process || !State->Listener || !Command.Process ||
            Command.Process != State->Process->Id() || !Command.Session ||
            !Command.Worker || !Command.Generation || !Command.Stream ||
            !Command.ParentTask || !Command.Task)
        {
            auto Rejected = Prism::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "bad_stream_scope";
            return Rejected;
        }
        Prism::Runtime::SessionInfo Session;
        if (!State->Listener->Registry().Find(Command.Session.Value(), Session))
        {
            auto Rejected = Prism::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "session_unavailable";
            return Rejected;
        }
        if (Session.Worker != Command.Worker || Session.Generation != Command.Generation)
        {
            auto Rejected = Prism::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "session_scope_mismatch";
            return Rejected;
        }
        const Prism::Contract::Ingress::StreamResetRequest Request{
            .Identity = {Command.Session, Command.Worker, Command.Generation, Command.Stream},
            .Task = Command.Task,
            .ParentTask = Command.ParentTask};
        const auto Deadline = std::chrono::steady_clock::now() + State->ShutdownTimeout;
        auto Result = StartScopedCommand(ScopedCommandRequest{
            State, Completion, Command.Correlation, Deadline,
            Prism::Operations::CommandTargetScope{Prism::Operations::StreamTargetScope{
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
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        if (const auto *Worker = State->Process->Workers().Find(Request.Worker);
            !Worker || !State->GenerationPublisher->Contains(Request.Generation))
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
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
                        Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                }
            }
        }
        auto *RetiredWorker = State->Process->Workers().Find(Request.Worker);
        if (!RetiredWorker)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        const auto Snapshot = RetiredWorker->Snapshot();
        if (Snapshot.Accepting || Snapshot.ActiveTasks != 0 || Snapshot.MailboxSize != 0)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        co_return ShutdownOutcome{};
    }

    /** @brief 返回 Accepted 并由 deadline owner drain 指定 worker；force 暂无安全语义。 */
    [[nodiscard]] inline auto StartWorkerDrain(
        const std::shared_ptr<RuntimeState> &State,
        const Prism::Operations::WorkerDrainCommand &Command,
        const Prism::Operations::OperationCompletion &Completion)
        -> Prism::Operations::CommandResult
    {
        if (Command.Force)
        {
            auto Rejected = Prism::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "force_worker_drain_unsupported";
            Rejected.Worker = Command.Worker;
            return Rejected;
        }
        if (!State || !State->Process || !Command.Worker)
        {
            auto Rejected = Prism::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "worker_scope_mismatch";
            Rejected.Worker = Command.Worker;
            return Rejected;
        }
        const auto Generation = State->Process->Workers().Generation();
        const auto *Worker = State->Process->Workers().Find(Command.Worker);
        if (!Worker || Worker->Generation() != Generation)
        {
            auto Rejected = Prism::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "worker_scope_mismatch";
            Rejected.Worker = Command.Worker;
            return Rejected;
        }
        const auto Deadline =
            std::chrono::steady_clock::now() + State->ShutdownTimeout;
        auto Result = StartScopedCommand(ScopedCommandRequest{
            State, Completion, Command.Correlation, Deadline,
            Prism::Operations::CommandTargetScope{Prism::Operations::WorkerTargetScope{
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
            Prism::Application::OperationsEventProducer::MakeProcessDrainIdentity(
                State, Prism::Application::OperationsEventProducer::ProcessDrainIdentityInput{
                    Operation.Completion.Id(), Operation.Correlation, Operation.Target});
        Prism::Application::OperationsEventProducer::AppendAccepted(State, EventIdentity);
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
                Prism::Application::Shutdown::DrainApplicationDataPlane(State, Deadline);
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

        Prism::Operations::CommandResult Terminal;
        if (FinalOutcome)
        {
            Terminal = Prism::Operations::CommandResult::Completed(Operation.Correlation);
        }
        else
        {
            Terminal = Prism::Operations::CommandResult::FromFailure(
                Operation.Correlation, FinalOutcome.error());
        }
        Prism::Operations::ApplyCommandTarget(Terminal, Operation.Target);

        std::expected<Prism::Operations::OperationPublicationReceipt, Prism::Fault::Failure>
            CompletionPublished{std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked})};
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
            Prism::Application::OperationsEventProducer::AppendTerminal(
                State, EventIdentity, TerminalSucceeded);
            if (CompletionPublished->WaiterSignalFailure.Failed())
            {
                KeepFirstFailure(FinalOutcome, CompletionPublished->WaiterSignalFailure);
                State->ObservationFailures.fetch_add(1U, std::memory_order_relaxed);
            }
        }

        Prism::Operations::ResponseDeliveryReceipt::Outcome Delivery;
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
            Operations = co_await Prism::Application::Shutdown::DrainOperationsServer(
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
            Prism::Application::Shutdown::PublishShutdownResult(State, std::move(FinalOutcome));
        if (!Published)
        {
            (void)State->RecordShutdownFailure(Published.error());
        }
        co_return;
    }

    /** @brief 取得唯一 shutdown gate 后提交后台 ProcessDrain；输家立即 Rejected。 */
    [[nodiscard]] inline auto StartProcessDrain(
        const std::shared_ptr<RuntimeState> &State,
        const Prism::Operations::ProcessDrainCommand &Command,
        const Prism::Operations::OperationCompletion &Completion)
        -> Prism::Operations::CommandResult
    {
        if (!State || !State->Process)
        {
            return Prism::Operations::CommandResult::Unavailable(Command.Correlation);
        }
        if (Command.Force)
        {
            auto Result = Prism::Operations::CommandResult::Rejected(Command.Correlation);
            Result.Message = "force_drain_unsupported";
            return Result;
        }
        if (!Prism::Application::Shutdown::TryClaimShutdown(State))
        {
            auto Result = Prism::Operations::CommandResult::Rejected(Command.Correlation);
            Result.Message = "shutdown_already_scheduled";
            return Result;
        }
        const Prism::Operations::CommandTargetScope Target{
            Prism::Operations::ProcessTargetScope{State->Process->Id()}};

        try
        {
            Net::co_spawn(State->ShutdownCoordinator,
                RunProcessDrain(State, ProcessDrainOperation{
                    Completion, Command.Correlation, Target}),
                [State](std::exception_ptr Exception) noexcept
                {
                    Prism::Application::Shutdown::OnShutdownDriverComplete(
                        State, std::move(Exception));
                });
        }
        catch (...)
        {
            const auto Exception = std::current_exception();
            const auto Cause = FailureFromException(Exception);
            (void)State->RecordShutdownFailure(Cause);
            Prism::Application::Shutdown::OnShutdownDriverComplete(State, Exception);
            auto Result = Prism::Operations::CommandResult::FromFailure(
                Command.Correlation, Cause);
            Prism::Operations::ApplyCommandTarget(Result, Target);
            return Result;
        }
        auto Result = Prism::Operations::CommandResult::Accepted(
            Command.Correlation, Completion.Id());
        Prism::Operations::ApplyCommandTarget(Result, Target);
        return Result;
    }

} // namespace Prism::Application::OperationsDrain
