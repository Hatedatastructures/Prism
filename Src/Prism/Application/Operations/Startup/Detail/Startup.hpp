/**
 * @file Startup.hpp
 * @brief Prism operations HTTP 启动、查询、命令和信号入口。
 */

#pragma once

#include <Prism/Application/Startup/Detail/RuntimeState.hpp>
#include <Prism/Application/Operations/Snapshot/Detail/Queries.hpp>
#include <Prism/Application/Operations/Drain/Detail/Drain.hpp>
#include <Prism/Application/Operations/Configuration.hpp>
#include <Prism/Application/Operations/Configuration/Detail/Query.hpp>
#include <Prism/Application/Operations/Metrics/Detail/Metrics.hpp>
#include <Prism/Application/Operations/Reload/Detail/Reload.hpp>
#include <Prism/Application/Operations/Stream/Detail/Query.hpp>
#include <Prism/Application/Operations/Task/Detail/Task.hpp>
#include <Prism/Application/Operations/Management/Detail/Queries.hpp>
#include <Prism/Application/Shutdown/Detail/Shutdown.hpp>
#include <Prism/Application/Startup/Detail/Errors.hpp>
#include <Prism/Contract/Ingress/StreamCatalog.hpp>
#include <Prism/Operations/Controller.hpp>
#include <Prism/Operations/Models.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/signal_set.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>
#include <variant>

namespace Prism::Application::OperationsStartup
{
    namespace Net = boost::asio;

    /** @brief 在非协程 Application::Start 冷路径同步启动独立管理控制器。 */
    [[nodiscard]] inline auto StartOperations(Prism::Operations::Controller &ControllerOwner)
        -> std::expected<void, StartupError>
    {
        try
        {
            const auto Started = ControllerOwner.Start();
            if (!Started)
            {
                return std::unexpected(Startup::MakeStartupError(
                    StartupErrorCode::Bind, "Operations.Endpoint",
                    "operations listener bind/listen failed: " + Started.error().message()));
            }
        }
        catch (...)
        {
            return std::unexpected(Startup::MakeStartupError(
                StartupErrorCode::Bind, "Operations.Endpoint",
                "operations listener startup threw: " +
                    Startup::DescribeException(std::current_exception())));
        }
        return {};
    }
    /** @brief 从值查询类型选择唯一快照 owner；任务读在实际 worker executor 完成。 */
    template <typename ValueObject>
    [[nodiscard]] auto DispatchOperationsQuery(
        std::shared_ptr<Application::RuntimeState> State,
        ValueObject Value) -> Net::awaitable<Prism::Operations::QueryResult>
    {
        using ValueType = std::remove_cvref_t<decltype(Value)>;
        if constexpr (std::is_same_v<ValueType, Prism::Operations::HealthQuery>)
        {
            co_return MakeOperationsHealth(State, Value);
        }
        else if constexpr (std::is_same_v<ValueType, Prism::Operations::MetricsQuery>)
        {
            co_return Prism::Application::OperationsMetrics::Query(State, Value);
        }
        else if constexpr (std::is_same_v<ValueType, Prism::Operations::WorkerQuery>)
        {
            co_return MakeOperationsWorkers(State, Value);
        }
        else if constexpr (std::is_same_v<ValueType, Prism::Operations::AccountQuery>)
        {
            co_return MakeOperationsAccounts(State, Value);
        }
        else if constexpr (std::is_same_v<ValueType, Prism::Operations::SessionQuery>)
        {
            co_return MakeOperationsSessions(State, Value);
        }
        else if constexpr (std::is_same_v<ValueType, Prism::Operations::GenerationQuery>)
        {
            co_return MakeOperationsGeneration(State, Value);
        }
        else if constexpr (std::is_same_v<ValueType, Prism::Operations::ConfigurationQuery>)
        {
            co_return Prism::Application::OperationsConfiguration::MakeQuery(State, Value);
        }
        else if constexpr (std::is_same_v<ValueType, Prism::Operations::StreamQuery>)
        {
            co_return MakeOperationsStreamQuery(State, Value);
        }
        else if constexpr (std::is_same_v<ValueType, Prism::Operations::StreamListQuery>)
        {
            co_return MakeOperationsStreamListQuery(State, Value);
        }
        else if constexpr (std::is_same_v<ValueType, Prism::Operations::TaskQuery>)
        {
            co_return co_await Prism::Application::OperationsTask::Query(State, Value);
        }
        else if constexpr (std::is_same_v<ValueType, Prism::Operations::TaskListQuery>)
        {
            co_return co_await Prism::Application::OperationsTask::List(State, Value);
        }
        else if constexpr (std::is_same_v<ValueType, Prism::Operations::ManagementQuery>)
        {
            const auto HealthResult = MakeOperationsHealth(State, Prism::Operations::HealthQuery{Value.Correlation});
            const auto *Health = std::get_if<Prism::Operations::HealthSnapshot>(&HealthResult.Value);
            co_return Health ? OperationsManagementQueries::Dispatch(State, Value, *Health)
                : Prism::Operations::QueryResult::Unavailable(Value.Correlation);
        }
        else
        {
            co_return InvalidOperationsQuery(Value.Correlation);
        }
    }

    /** @brief 按值命令选择撤销、取消或停机 owner；保留原 typed 结果与错误。 */
    template <typename ValueObject>
    [[nodiscard]] auto DispatchOperationsCommand(
        std::shared_ptr<Application::RuntimeState> State,
        ValueObject Value,
        Prism::Operations::OperationCompletion Completion)
        -> Net::awaitable<Prism::Operations::CommandResult>
    {
        using ValueType = std::remove_cvref_t<decltype(Value)>;
        if (State->Phase.load(std::memory_order_acquire) != RuntimePhase::Ready)
        {
            auto Rejected = Prism::Operations::CommandResult::Rejected(Value.Correlation);
            Rejected.Message = "application_not_ready";
            co_return Rejected;
        }
        if constexpr (!std::is_same_v<ValueType, Prism::Operations::ProcessDrainCommand>)
        {
            if (State->ShutdownScheduled.load(std::memory_order_acquire))
            {
                auto Rejected = Prism::Operations::CommandResult::Rejected(Value.Correlation);
                Rejected.Message = "shutdown_in_progress";
                co_return Rejected;
            }
        }
        auto Result = Prism::Operations::CommandResult::Completed(Value.Correlation);
        if constexpr (std::is_same_v<ValueType, Prism::Operations::ReloadCommand>)
        {
            co_return Prism::Application::OperationsReload::StartReload(
                State, Value, Completion);
        }
        else if constexpr (std::is_same_v<ValueType, Prism::Operations::RevokeCommand>)
        {
            co_return Prism::Application::OperationsDrain::StartAccountRevoke(
                State, Value, Completion);
        }
        else if constexpr (std::is_same_v<ValueType, Prism::Operations::StreamResetCommand>)
        {
            co_return Prism::Application::OperationsDrain::StartStreamReset(
                State, Value, Completion);
        }
        else if constexpr (std::is_same_v<ValueType, Prism::Operations::CancelCommand>)
        {
            if (Value.Task)
            {
                co_return Prism::Application::OperationsTask::StartTaskCancel(
                    State, Value, Completion);
            }
            co_return Prism::Application::OperationsDrain::StartSessionCancel(
                State, Value, Completion);
        }
        else if constexpr (std::is_same_v<ValueType, Prism::Operations::ProcessDrainCommand>)
        {
            co_return Prism::Application::OperationsDrain::StartProcessDrain(
                State, Value, Completion);
        }
        else if constexpr (std::is_same_v<ValueType, Prism::Operations::WorkerDrainCommand>)
        {
            co_return Prism::Application::OperationsDrain::StartWorkerDrain(
                State, Value, Completion);
        }
        else
        {
            Result.Status = Prism::Operations::CommandStatus::Invalid;
            Result.Message = "command_invalid";
        }
        co_return Result;
    }

    /** @brief 在应用 control executor 消费拥有型查询值并产生值结果。 */
    [[nodiscard]] inline auto OperationsQueryOnControl(
        std::weak_ptr<Application::RuntimeState> WeakState,
        Prism::Operations::Query QueryValue) -> Net::awaitable<Prism::Operations::QueryResult>
    {
        const auto Correlation = Prism::Operations::CorrelationOf(QueryValue);
        const auto State = WeakState.lock();
        if (!State)
        {
            co_return Prism::Operations::QueryResult::Unavailable(Correlation);
        }
        co_return co_await std::visit(
            [&State](const auto &Value) { return DispatchOperationsQuery(State, Value); },
            QueryValue.Value);
    }

    /** @brief 在应用 control executor 校验并提交 typed 命令到真实 owner。 */
    [[nodiscard]] inline auto OperationsCommandOnControl(
        std::weak_ptr<Application::RuntimeState> WeakState,
        Prism::Operations::Command CommandValue,
        Prism::Operations::OperationCompletion Completion)
        -> Net::awaitable<Prism::Operations::CommandResult>
    {
        const auto Correlation = Prism::Operations::CorrelationOf(CommandValue);
        const auto State = WeakState.lock();
        if (!State)
        {
            co_return Prism::Operations::CommandResult::Unavailable(Correlation);
        }
        co_return co_await std::visit(
            [&State, &Completion](const auto &Value)
            { return DispatchOperationsCommand(State, Value, Completion); },
            CommandValue.Value);
    }

    /** @brief 冷路径只捕获 typed owner executor 与弱生命周期；不在管理线程读取运行态。 */
    [[nodiscard]] inline auto MakeOperationsHandlers(
        const std::shared_ptr<Application::RuntimeState> &State)
        -> Prism::Operations::RouterHandlers
    {
        const std::weak_ptr<Application::RuntimeState> WeakState = State;
        const auto ApplicationExecutor = State->Io.get_executor();
        auto QueryHandler = [WeakState, ApplicationExecutor](Prism::Operations::Query QueryValue)
            -> Net::awaitable<Prism::Operations::QueryResult>
        {
            return Net::co_spawn(ApplicationExecutor,
                OperationsQueryOnControl(WeakState, std::move(QueryValue)), Net::use_awaitable);
        };
        auto CommandHandler = [WeakState, ApplicationExecutor](
            Prism::Operations::Command CommandValue,
            Prism::Operations::OperationCompletion Completion)
            -> Net::awaitable<Prism::Operations::CommandResult>
        {
            return Net::co_spawn(ApplicationExecutor,
                OperationsCommandOnControl(
                    WeakState, std::move(CommandValue), std::move(Completion)),
                Net::use_awaitable);
        };
        return Prism::Operations::RouterHandlers{
            std::move(QueryHandler), std::move(CommandHandler)};
    }
    [[nodiscard]] inline auto ArmSignals(const std::shared_ptr<Application::RuntimeState>& State)
        -> std::expected<void, StartupError>
    {
        if (State->SignalsArmed.exchange(true, std::memory_order_acq_rel))
        {
            return {};
        }

        boost::system::error_code Error;
        State->Signals.add(SIGINT, Error);
        if (Error)
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Signal, {},
                "cannot register SIGINT: " + Error.message()));
        }
        State->Signals.add(SIGTERM, Error);
        if (Error)
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Signal, {},
                "cannot register SIGTERM: " + Error.message()));
        }

        const std::weak_ptr<Application::RuntimeState> WeakState = State;
        State->Signals.async_wait(
            [WeakState](const boost::system::error_code& SignalError, const int)
            {
                if (!SignalError)
                {
                    if (const auto StateValue = WeakState.lock())
                    {
                        Shutdown::ScheduleShutdown(StateValue);
                    }
                }
            });
        return {};
    }

} // namespace Prism::Application::OperationsStartup
