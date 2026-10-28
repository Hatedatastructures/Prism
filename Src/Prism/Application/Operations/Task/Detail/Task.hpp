/**
 * @file Task.hpp
 * @brief worker task 的按值观察、精确查询与真实取消回执 owner。
 */
#pragma once

#include <Prism/Application/Operations/Detail/CommandOwner.hpp>
#include <Prism/Application/Startup/Detail/RuntimeState.hpp>
#include <Prism/Operations/Models.hpp>
#include <Prism/Runtime/Process.hpp>
#include <Prism/Runtime/Session/Registry.hpp>
#include <Prism/Runtime/Worker.hpp>
#include <Prism/Runtime/WorkerGroup.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <chrono>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>
#include <variant>

namespace Prism::Application::OperationsTask
{

    namespace Net = boost::asio;
    using RuntimeState = Prism::Application::Application::RuntimeState;
    using TaskIdentity = Prism::Lifecycle::TaskIdentity;
    using TaskHandle = Prism::Lifecycle::TaskHandle;
    using TaskLookupResult = std::expected<
        std::optional<TaskHandle>, Prism::Fault::Failure>;
    using TaskListLookupResult = std::expected<
        Prism::Lifecycle::TaskRegistryListPage, Prism::Fault::Failure>;
    using ShutdownOutcome = Prism::Application::Shutdown::ShutdownOutcome;
    using ShutdownDeadline = Prism::Application::Shutdown::ShutdownDeadline;

    struct TaskOwnerScope final
    {
        Prism::ProcessId Process{};
        TaskIdentity Identity{};
    };

    struct TaskSessionScope final
    {
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{};
        Prism::WorkerId Worker{};
        Prism::SessionId Session{};
    };

    /** @brief 同一 worker task page 的完整父身份、游标和绝对截止时间。 */
    struct TaskListDeadlineRequest final
    {
        TaskSessionScope Scope{};
        Prism::Operations::PageRequest Page{};
        ShutdownDeadline Deadline{};
    };

    /** @brief 从查询复制完整身份；不会使用 TaskId 单字段查找。 */
    [[nodiscard]] inline auto TaskScopeFromQuery(
        const Prism::Operations::TaskQuery &QueryValue) noexcept -> TaskOwnerScope
    {
        return {QueryValue.Process, {QueryValue.Id, QueryValue.Session, QueryValue.Stream,
            QueryValue.Worker, QueryValue.Generation, QueryValue.ParentTask}};
    }

    /** @brief 从取消命令复制完整身份；不会使用 TaskId 单字段查找。 */
    [[nodiscard]] inline auto TaskScopeFromCommand(
        const Prism::Operations::CancelCommand &Command) noexcept -> TaskOwnerScope
    {
        return {Command.Process, {Command.Task, Command.Session, Command.Stream,
            Command.Worker, Command.Generation, Command.ParentTask}};
    }

    /** @brief 验证当前进程、已登记父会话及真实 worker owner。 */
    [[nodiscard]] inline auto ResolveWorker(
        const std::shared_ptr<RuntimeState> &State,
        const TaskOwnerScope &Scope) noexcept -> Prism::Runtime::Worker *
    {
        const auto &Identity = Scope.Identity;
        if (!State || !State->Process || !State->Listener ||
            Scope.Process != State->Process->Id() || !Identity.TaskId ||
            !Identity.Generation || !Identity.WorkerId || !Identity.SessionId)
        {
            return nullptr;
        }
        Prism::Runtime::SessionInfo Parent;
        if (!State->Listener->Registry().Find(Identity.SessionId.Value(), Parent) ||
            Parent.Worker != Identity.WorkerId || Parent.Generation != Identity.Generation)
        {
            return nullptr;
        }
        auto *Worker = State->Process->Workers().Find(Identity.WorkerId);
        if (!Worker || !State->GenerationPublisher ||
            !State->GenerationPublisher->Contains(Identity.Generation))
        {
            return nullptr;
        }
        return Worker;
    }

    [[nodiscard]] inline auto ResolveSessionWorker(
        const std::shared_ptr<RuntimeState> &State,
        const TaskSessionScope &Scope) noexcept -> Prism::Runtime::Worker *
    {
        if (!State || !State->Process || !State->Listener ||
            Scope.Process != State->Process->Id() || !Scope.Generation ||
            !Scope.Worker || !Scope.Session)
        {
            return nullptr;
        }
        Prism::Runtime::SessionInfo Parent;
        if (!State->Listener->Registry().Find(Scope.Session.Value(), Parent) ||
            Parent.Worker != Scope.Worker || Parent.Generation != Scope.Generation)
        {
            return nullptr;
        }
        auto *Worker = State->Process->Workers().Find(Scope.Worker);
        if (!Worker || Worker->Generation() != Scope.Generation)
        {
            return nullptr;
        }
        return Worker;
    }

    /** @brief 由已 pin 的 Application owner 在真实 worker root registry 查询完整身份。 */
    [[nodiscard]] inline auto FindTaskOnWorker(
        std::shared_ptr<RuntimeState> State,
        TaskOwnerScope Scope) -> Net::awaitable<TaskLookupResult>
    {
        auto *Worker = ResolveWorker(State, Scope);
        if (!Worker)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        try
        {
            co_return co_await Worker->TaskRegistry().FindTask(Scope.Identity);
        }
        catch (...)
        {
            co_return std::unexpected(
                Prism::Application::CommandOperationOwner::FailureFromException(
                    std::current_exception()));
        }
    }

    /** @brief 在调用方 control executor 等待单一绝对 deadline。 */
    [[nodiscard]] inline auto WaitForTaskQueryDeadline(
        const ShutdownDeadline Deadline)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Executor = co_await Net::this_coro::executor;
        Net::steady_timer Timer(Executor);
        Timer.expires_at(Deadline);
        boost::system::error_code Error;
        co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            co_return std::unexpected(Prism::Fault::FromNative(
                static_cast<std::error_code>(Error)));
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    /** @brief 将 lookup 与同一绝对查询期限竞争；迟到结果不作为新鲜快照返回。 */
    [[nodiscard]] inline auto FindTaskBeforeDeadline(
        std::shared_ptr<RuntimeState> State,
        TaskOwnerScope Scope,
        const ShutdownDeadline Deadline) -> Net::awaitable<TaskLookupResult>
    {
        using Net::experimental::awaitable_operators::operator||;
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        auto Winner = co_await (
            FindTaskOnWorker(std::move(State), Scope) ||
            WaitForTaskQueryDeadline(Deadline));
        if (auto *Lookup = std::get_if<TaskLookupResult>(&Winner))
        {
            if (std::chrono::steady_clock::now() >= Deadline)
            {
                co_return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::Timeout,
                    std::make_error_code(std::errc::timed_out)});
            }
            co_return std::move(*Lookup);
        }
        const auto &Timer = std::get<std::expected<void, Prism::Fault::Failure>>(Winner);
        if (!Timer)
        {
            co_return std::unexpected(Timer.error());
        }
        co_return std::unexpected(Prism::Fault::Failure{
            Prism::Fault::Code::Timeout,
            std::make_error_code(std::errc::timed_out)});
    }

    [[nodiscard]] inline auto FindTasksOnWorker(
        const std::shared_ptr<RuntimeState> &State,
        const TaskSessionScope &Scope,
        const Prism::Operations::PageRequest &Page) -> Net::awaitable<TaskListLookupResult>
    {
        auto *Worker = ResolveSessionWorker(State, Scope);
        if (!Worker)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        co_return co_await Worker->TaskRegistry().ListTasks(
            Prism::Lifecycle::TaskRegistryListRequest{
                Scope.Session, Scope.Worker, Scope.Generation,
                Page.Cursor, Page.BoundedLimit()});
    }

    /** @brief 把 owner executor 的 task page 与同一绝对查询期限竞争。 */
    [[nodiscard]] inline auto FindTasksBeforeDeadline(
        std::shared_ptr<RuntimeState> State,
        TaskListDeadlineRequest Request) -> Net::awaitable<TaskListLookupResult>
    {
        using Net::experimental::awaitable_operators::operator||;
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        auto Winner = co_await (
            FindTasksOnWorker(State, Request.Scope, Request.Page) ||
            WaitForTaskQueryDeadline(Request.Deadline));
        if (auto *Lookup = std::get_if<TaskListLookupResult>(&Winner))
        {
            if (std::chrono::steady_clock::now() >= Request.Deadline)
            {
                co_return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::Timeout,
                    std::make_error_code(std::errc::timed_out)});
            }
            co_return std::move(*Lookup);
        }
        const auto &Timer = std::get<std::expected<void, Prism::Fault::Failure>>(Winner);
        if (!Timer) co_return std::unexpected(Timer.error());
        co_return std::unexpected(Prism::Fault::Failure{
            Prism::Fault::Code::Timeout,
            std::make_error_code(std::errc::timed_out)});
    }

    /** @brief 将稳定 TaskObservation 转成完整值快照，不暴露 slot 或 TaskState。 */
    [[nodiscard]] inline auto MakeTaskSnapshot(
        const Prism::ProcessId Process,
        const Prism::Lifecycle::TaskObservation &Observation) noexcept
        -> Prism::Operations::TaskSnapshot
    {
        Prism::Operations::TaskSnapshot Snapshot;
        Snapshot.Id = Observation.Identity.TaskId;
        Snapshot.Process = Process;
        Snapshot.Worker = Observation.Identity.WorkerId;
        Snapshot.Session = Observation.Identity.SessionId;
        Snapshot.Stream = Observation.Identity.StreamId;
        Snapshot.Generation = Observation.Identity.Generation;
        Snapshot.ParentTask = Observation.Identity.ParentTaskId;
        Snapshot.StartedAt = Observation.StartedAt;
        Snapshot.CompletedAt = Observation.CompletedAt;
        Snapshot.CancelRequested = Observation.CancelRequested;
        Snapshot.Cancellable = Observation.Cancellable;
        Snapshot.DrainBlocked = Observation.DrainBlocked;
        Snapshot.Failure = Observation.Result.Failure;
        Snapshot.DrainFailure = Observation.DrainFailure;
        switch (Observation.Result.Outcome)
        {
        case Prism::Lifecycle::TaskOutcome::Pending:
            Snapshot.Status = Observation.Started
                ? Prism::Operations::TaskStatus::Running
                : Prism::Operations::TaskStatus::Pending;
            break;
        case Prism::Lifecycle::TaskOutcome::Succeeded:
            Snapshot.Status = Prism::Operations::TaskStatus::Succeeded;
            break;
        case Prism::Lifecycle::TaskOutcome::Cancelled:
            Snapshot.Status = Prism::Operations::TaskStatus::Canceled;
            break;
        case Prism::Lifecycle::TaskOutcome::Failed:
            Snapshot.Status = Prism::Operations::TaskStatus::Failed;
            break;
        case Prism::Lifecycle::TaskOutcome::Quarantined:
            Snapshot.Status = Prism::Operations::TaskStatus::Quarantined;
            break;
        }
        return Snapshot;
    }

    /** @brief 在所属 worker root registry 上精确读取活动任务并返回按值分页结果。 */
    [[nodiscard]] inline auto Query(
        std::shared_ptr<RuntimeState> State,
        Prism::Operations::TaskQuery QueryValue)
        -> Net::awaitable<Prism::Operations::QueryResult>
    {
        const auto Scope = TaskScopeFromQuery(QueryValue);
        if (!ResolveWorker(State, Scope))
        {
            auto Result = Prism::Operations::QueryResult::Failed(
                QueryValue.Correlation,
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            Result.Message = "task_scope_mismatch";
            co_return Result;
        }
        const auto Deadline =
            std::chrono::steady_clock::now() + State->ShutdownTimeout;
        auto Found = co_await FindTaskBeforeDeadline(State, Scope, Deadline);
        if (!Found)
        {
            auto Result = Prism::Operations::QueryResult::Failed(
                QueryValue.Correlation, Found.error());
            Result.Message = Found.error().Code == Prism::Fault::Code::Timeout
                ? "task_query_timeout"
                : "task_owner_lookup_failed";
            co_return Result;
        }
        Prism::Operations::Page<Prism::Operations::TaskSnapshot> Page;
        if (Found->has_value() && QueryValue.Id.Value() > QueryValue.Page.Cursor)
        {
            if (QueryValue.Page.BoundedLimit() == 0U)
            {
                Page.HasMore = true;
                Page.NextCursor = QueryValue.Page.Cursor;
            }
            else
            {
                Page.Items.push_back(MakeTaskSnapshot(State->Process->Id(),
                    Found->value().Observation()));
                Page.NextCursor = QueryValue.Id.Value();
            }
        }
        else
        {
            Page.NextCursor = QueryValue.Page.Cursor;
        }
        co_return Prism::Operations::QueryResult::Tasks(
            QueryValue.Correlation, std::move(Page));
    }

    /** @brief 通过真实 worker root TaskRegistry 按 session 身份分页列出活动任务。 */
    [[nodiscard]] inline auto List(
        std::shared_ptr<RuntimeState> State,
        Prism::Operations::TaskListQuery QueryValue)
        -> Net::awaitable<Prism::Operations::QueryResult>
    {
        const TaskSessionScope Scope{
            QueryValue.Process, QueryValue.Generation, QueryValue.Worker, QueryValue.Session};
        if (!ResolveSessionWorker(State, Scope))
        {
            auto Result = Prism::Operations::QueryResult::Failed(
                QueryValue.Correlation,
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            Result.Message = "task_scope_mismatch";
            co_return Result;
        }
        const auto Deadline = std::chrono::steady_clock::now() + State->ShutdownTimeout;
        auto Found = co_await FindTasksBeforeDeadline(
            State, TaskListDeadlineRequest{Scope, QueryValue.Page, Deadline});
        if (!Found)
        {
            auto Result = Prism::Operations::QueryResult::Failed(
                QueryValue.Correlation, Found.error());
            Result.Message = Found.error().Code == Prism::Fault::Code::Timeout
                ? "task_query_timeout"
                : "task_owner_lookup_failed";
            co_return Result;
        }
        Prism::Operations::Page<Prism::Operations::TaskSnapshot> Page;
        Page.NextCursor = Found->NextCursor;
        Page.HasMore = Found->HasMore;
        Page.Items.reserve(Found->Items.size());
        for (const auto &Observation : Found->Items)
        {
            Page.Items.push_back(MakeTaskSnapshot(State->Process->Id(), Observation));
        }
        co_return Prism::Operations::QueryResult::Tasks(
            QueryValue.Correlation, std::move(Page));
    }

    struct TaskCancellationRequest final
    {
        std::shared_ptr<RuntimeState> State;
        TaskOwnerScope Scope{};
    };

    /** @brief 等待精确任务真实退栈；终态失败、隔离和回执错误都保留 typed cause。 */
    [[nodiscard]] inline auto CancelAndWaitForRetirement(TaskCancellationRequest Request)
        -> Net::awaitable<ShutdownOutcome>
    {
        auto *Worker = ResolveWorker(Request.State, Request.Scope);
        if (!Worker)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto Found = co_await Worker->TaskRegistry().FindTask(Request.Scope.Identity);
        if (!Found)
        {
            co_return std::unexpected(Found.error());
        }
        if (!Found->has_value())
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto Target = std::move(Found->value());
        if (!Target.Observation().Cancellable)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
        }
        (void)Target.RequestCancel();
        const auto Retired = co_await Target.WaitForRetirementAsync();
        if (!Retired)
        {
            co_return std::unexpected(Retired.error());
        }
        const auto Observation = Target.Observation();
        if (Observation.DrainBlocked ||
            Observation.Result.Outcome == Prism::Lifecycle::TaskOutcome::Quarantined)
        {
            co_return std::unexpected(Observation.DrainFailure.Failed()
                ? Observation.DrainFailure
                : Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        if (Observation.Result.Outcome == Prism::Lifecycle::TaskOutcome::Pending)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        if (Observation.Result.Outcome == Prism::Lifecycle::TaskOutcome::Failed)
        {
            co_return std::unexpected(Observation.Result.Failure);
        }
        co_return ShutdownOutcome{};
    }

    /** @brief 登记真实 worker owner 后立即返回 Accepted，由其完成查找、取消与退休回执。 */
    [[nodiscard]] inline auto StartTaskCancel(
        std::shared_ptr<RuntimeState> State,
        Prism::Operations::CancelCommand Command,
        Prism::Operations::OperationCompletion Completion)
        -> Prism::Operations::CommandResult
    {
        const auto Scope = TaskScopeFromCommand(Command);
        auto *Worker = ResolveWorker(State, Scope);
        if (!Worker)
        {
            auto Rejected = Prism::Operations::CommandResult::Rejected(Command.Correlation);
            Rejected.Message = "task_scope_mismatch";
            return Rejected;
        }
        const ShutdownDeadline Deadline =
            std::chrono::steady_clock::now() + State->ShutdownTimeout;
        auto Result = Prism::Application::CommandOperationOwner::StartScopedCommand(
            Prism::Application::CommandOperationOwner::ScopedCommandRequest{
                State, Completion, Command.Correlation, Deadline,
                Prism::Operations::CommandTargetScope{
                    Prism::Operations::TaskTargetScope{
                        Scope.Process, Scope.Identity.Generation, Scope.Identity.WorkerId,
                        Scope.Identity.SessionId, Scope.Identity.StreamId,
                        Scope.Identity.ParentTaskId, Scope.Identity.TaskId}},
                CancelAndWaitForRetirement(
                    TaskCancellationRequest{State, Scope})});
        return Result;
    }

} // namespace Prism::Application::OperationsTask
