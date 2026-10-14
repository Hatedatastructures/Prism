/**
 * @file Models.hpp
 * @brief Preview 管理面查询、命令和结果值模型。
 */

#pragma once

#include <Preview/Statistics/Statistics.hpp>
#include <Preview/Operations/Metrics.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Operations/CommandTargetScope.hpp>
#include <Preview/Operations/QueryPage.hpp>
#include <Preview/Operations/ScopedCollectionModels.hpp>
#include <Preview/Operations/ConfigurationIssue.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace Preview::Operations
{

    struct OperationTag;
    using OperationId = Preview::Identifier::Id<OperationTag>;

    /**
     * @class BootstrapIdentity
     * @brief 单个 Operations listener 的进程身份和命令凭据。
     * @details 由 Application 冷启动生成并以 const 共享所有；此值不执行网络、取消、
     *          半关闭或最终关闭，凭据只通过受 Host/Origin 约束的 Bootstrap 响应公开。
     */
    class BootstrapIdentity final
    {
    public:
        using Incarnation = std::array<std::uint8_t, 16>;
        using CommandToken = std::array<std::uint8_t, 32>;

        /** @brief 冷启动身份和凭据；路由能力由已装配的控制器声明。 */
        struct Options final
        {
            Preview::ProcessId Process{};
            Incarnation ProcessIncarnation{};
            CommandToken Token{};
        };

        explicit BootstrapIdentity(Options Value)
            : Process_(Value.Process),
              Incarnation_(std::move(Value.ProcessIncarnation)),
              CommandToken_(std::move(Value.Token))
        {
        }

        /** @brief 返回当前 Runtime::Process 提供的稳定进程身份。 */
        [[nodiscard]] auto Process() const noexcept -> Preview::ProcessId
        {
            return Process_;
        }

        /** @brief 借用本次启动的随机 incarnation 字节。 */
        [[nodiscard]] auto ProcessIncarnation() const noexcept -> const Incarnation &
        {
            return Incarnation_;
        }

        /** @brief 借用本 listener 唯一的 256-bit 命令令牌字节。 */
        [[nodiscard]] auto Token() const noexcept -> const CommandToken &
        {
            return CommandToken_;
        }

    private:
        Preview::ProcessId Process_{};
        Incarnation Incarnation_{};
        CommandToken CommandToken_{};
    };
    using HealthStatus = Preview::Statistics::HealthStatus;
    using HealthSnapshot = Preview::Statistics::HealthSnapshot;
    using GenerationSnapshot = Preview::Statistics::GenerationSnapshot;
    using ProcessSnapshot = Preview::Statistics::ProcessSnapshot;
    using WorkerSnapshot = Preview::Statistics::WorkerSnapshot;
    using AccountSnapshot = Preview::Statistics::AccountSnapshot;
    using SessionSnapshot = Preview::Statistics::SessionSnapshot;
    using StreamSnapshot = Preview::Statistics::StreamSnapshot;
    using TaskStatus = Preview::Statistics::TaskStatus;
    using TaskSnapshot = Preview::Statistics::TaskSnapshot;
    using EventSnapshot = Preview::Statistics::DetailedEvent;

    struct HealthQuery final
    {
        Preview::RequestId Correlation{};
    };

    struct GenerationQuery final
    {
        Preview::RequestId Correlation{};
        Preview::ProcessId Process{};
        Preview::GenerationId Id{};
    };

    struct WorkerQuery final
    {
        Preview::RequestId Correlation{};
        PageRequest Page{};
        Preview::WorkerId Id{};
    };

    struct AccountQuery final
    {
        Preview::RequestId Correlation{};
        PageRequest Page{};
        Preview::AccountId Id{};
    };

    struct SessionQuery final
    {
        Preview::RequestId Correlation{};
        PageRequest Page{};
        Preview::SessionId Id{};
    };

    /** @brief 以 process/generation/worker/session 完整父身份查询指定 stream。 */
    struct StreamQuery final
    {
        Preview::RequestId Correlation{};
        PageRequest Page{};
        Preview::ProcessId Process{}; ///< stream 所属进程。
        Preview::SessionId Session{}; ///< stream 所属会话。
        Preview::StreamId Id{}; ///< 被查询的 stream。
        Preview::GenerationId Generation{}; ///< 父会话绑定的 generation。
        Preview::WorkerId Worker{}; ///< 父会话绑定的 worker。
    };

    struct TaskQuery final
    {
        Preview::RequestId Correlation{};
        PageRequest Page{};
        Preview::ProcessId Process{};
        Preview::GenerationId Generation{};
        Preview::WorkerId Worker{};
        Preview::SessionId Session{};
        Preview::StreamId Stream{};
        Preview::TaskId ParentTask{};
        Preview::TaskId Id{};
    };

    struct EventQuery final
    {
        Preview::RequestId Correlation{};
        PageRequest Page{};
        bool IncludeDetails{true};
    };

    using QueryValue = std::variant<HealthQuery,
                                    MetricsQuery,
                                    GenerationQuery,
                                    ConfigurationQuery,
                                    WorkerQuery,
                                    AccountQuery,
                                    SessionQuery,
                                    StreamQuery,
                                    StreamListQuery,
                                    TaskQuery,
                                    TaskListQuery,
                                    EventQuery>;

    struct Query final
    {
        QueryValue Value{};

        Query() = default;

        template <typename ValueType>
        explicit Query(ValueType ValueObject) : Value(std::move(ValueObject))
        {
        }
    };

    enum class ReloadMode : std::uint8_t
    {
        ValidateOnly,
        Apply,
    };

    struct ReloadCommand final
    {
        Preview::RequestId Correlation{};
        Preview::GenerationId BaseGeneration{};
        ReloadMode Mode{ReloadMode::ValidateOnly};
        std::string ConfigurationJson;
    };

    struct RevokeCommand final
    {
        Preview::RequestId Correlation{};
        Preview::AccountId Account{};
        bool CloseSessions{true};
    };

    struct CancelCommand final
    {
        Preview::RequestId Correlation{};
        Preview::ProcessId Process{};
        Preview::GenerationId Generation{};
        Preview::WorkerId Worker{};
        Preview::SessionId Session{};
        Preview::StreamId Stream{};
        Preview::TaskId ParentTask{};
        Preview::TaskId Task{};
    };

    /** @brief 完整标识父 Session 与 root task 下单一 mux child stream 的 reset 命令。 */
    struct StreamResetCommand final
    {
        Preview::RequestId Correlation{};
        Preview::ProcessId Process{};
        Preview::GenerationId Generation{};
        Preview::WorkerId Worker{};
        Preview::SessionId Session{};
        Preview::StreamId Stream{};
        Preview::TaskId ParentTask{};
        Preview::TaskId Task{};
    };

    struct ProcessDrainCommand final
    {
        Preview::RequestId Correlation{};
        bool Force{false};
    };

    struct WorkerDrainCommand final
    {
        Preview::RequestId Correlation{};
        Preview::WorkerId Worker{};
        bool Force{false};
    };

    using CommandValue = std::variant<ReloadCommand, RevokeCommand, CancelCommand, StreamResetCommand,
                                      ProcessDrainCommand, WorkerDrainCommand>;

    struct Command final
    {
        CommandValue Value{};

        Command() = default;

        template <typename ValueType>
        explicit Command(ValueType ValueObject) : Value(std::move(ValueObject))
        {
        }
    };

    [[nodiscard]] inline auto CorrelationOf(const Command &CommandValueObject) noexcept
        -> Preview::RequestId
    {
        return std::visit([](const auto &ValueObject) { return ValueObject.Correlation; },
                          CommandValueObject.Value);
    }

    [[nodiscard]] inline auto CorrelationOf(const Query &QueryValueObject) noexcept
        -> Preview::RequestId
    {
        return std::visit([](const auto &ValueObject) { return ValueObject.Correlation; },
                          QueryValueObject.Value);
    }

    enum class CommandStatus : std::uint8_t
    {
        Accepted,
        Completed,
        Rejected,
        Unavailable,
        Failed,
        TimedOut,
        Blocked,
        RestartRequired,
        Conflict,
        Invalid,
    };

    struct CommandResult final
    {
        Preview::RequestId Correlation{};
        CommandStatus Status{CommandStatus::Unavailable};
        OperationId Operation{};
        Preview::ProcessId Process{};
        Preview::GenerationId Generation{};
        Preview::WorkerId Worker{};
        Preview::AccountId Account{};
        Preview::SessionId Session{};
        Preview::StreamId Stream{};
        Preview::TaskId Task{};
        Preview::TaskId ParentTask{};
        std::vector<ConfigurationIssue> ConfigurationIssues;
        std::vector<std::string> RestartRequiredFields;
        std::string Message{};
        Preview::Fault::Failure Failure{};

        [[nodiscard]] static auto Completed(const Preview::RequestId Correlation,
                                            const Preview::WorkerId Worker = {},
                                            const Preview::GenerationId Generation = {}) -> CommandResult
        {
            CommandResult Result;
            Result.Correlation = Correlation;
            Result.Status = CommandStatus::Completed;
            Result.Generation = Generation;
            Result.Worker = Worker;
            return Result;
        }

        [[nodiscard]] static auto Accepted(const Preview::RequestId Correlation,
                                           const OperationId Operation = {}) -> CommandResult
        {
            auto Result = Completed(Correlation);
            Result.Status = CommandStatus::Accepted;
            Result.Operation = Operation;
            return Result;
        }

        [[nodiscard]] static auto Rejected(const Preview::RequestId Correlation) -> CommandResult
        {
            auto Result = Completed(Correlation);
            Result.Status = CommandStatus::Rejected;
            Result.Message = "command_rejected";
            return Result;
        }

        [[nodiscard]] static auto Invalid(const Preview::RequestId Correlation) -> CommandResult
        {
            auto Result = Completed(Correlation);
            Result.Status = CommandStatus::Invalid;
            Result.Message = "command_invalid";
            return Result;
        }

        [[nodiscard]] static auto Unavailable(const Preview::RequestId Correlation) -> CommandResult
        {
            auto Result = Completed(Correlation);
            Result.Status = CommandStatus::Unavailable;
            Result.Message = "handler_unavailable";
            return Result;
        }

        [[nodiscard]] static auto Failed(const Preview::RequestId Correlation,
                                         const Preview::Fault::Failure Failure) -> CommandResult
        {
            auto Result = Completed(Correlation);
            Result.Status = CommandStatus::Failed;
            Result.Message = "handler_failed";
            Result.Failure = Failure;
            return Result;
        }

        [[nodiscard]] static auto TimedOut(const Preview::RequestId Correlation,
                                           const Preview::Fault::Failure Failure) -> CommandResult
        {
            auto Result = Completed(Correlation);
            Result.Status = CommandStatus::TimedOut;
            Result.Message = "command_timeout";
            Result.Failure = Failure;
            return Result;
        }

        [[nodiscard]] static auto Blocked(const Preview::RequestId Correlation,
                                          const Preview::Fault::Failure Failure) -> CommandResult
        {
            auto Result = Completed(Correlation);
            Result.Status = CommandStatus::Blocked;
            Result.Message = "command_blocked";
            Result.Failure = Failure;
            return Result;
        }

        [[nodiscard]] static auto RestartRequired(
            const Preview::RequestId Correlation,
            const Preview::GenerationId Generation) -> CommandResult
        {
            auto Result = Rejected(Correlation);
            Result.Status = CommandStatus::RestartRequired;
            Result.Generation = Generation;
            Result.Message = "restart_required";
            return Result;
        }

        /** @brief 读取基准已过期；返回真实当前代，未开始候选准备或发布。 */
        [[nodiscard]] static auto Conflict(const Preview::RequestId Correlation,
            const Preview::GenerationId Generation) -> CommandResult
        {
            auto Result = Completed(Correlation, {}, Generation);
            Result.Status = CommandStatus::Conflict;
            Result.Message = "generation_conflict";
            return Result;
        }

        [[nodiscard]] static auto FromFailure(const Preview::RequestId Correlation,
                                              const Preview::Fault::Failure Failure) -> CommandResult
        {
            if (Failure.Code == Preview::Fault::Code::Timeout)
            {
                return TimedOut(Correlation, Failure);
            }
            if (Failure.Code == Preview::Fault::Code::Blocked)
            {
                return Blocked(Correlation, Failure);
            }
            return Failed(Correlation, Failure);
        }

        [[nodiscard]] static auto HandlerFailed(const Preview::RequestId Correlation) -> CommandResult
        {
            return Failed(Correlation,
                          Preview::Fault::Failure{Preview::Fault::Code::GenericError});
        }
    };

    /** @brief 按目标类型把身份字段写入唯一命令结果。 */
    inline auto ApplyCommandTarget(CommandResult &Result, const ProcessTargetScope &Target) noexcept -> void
    {
        Result.Process = Target.Process;
    }

    inline auto ApplyCommandTarget(CommandResult &Result, const WorkerTargetScope &Target) noexcept -> void
    {
        Result.Process = Target.Process;
        Result.Generation = Target.Generation;
        Result.Worker = Target.Worker;
    }

    inline auto ApplyCommandTarget(CommandResult &Result, const AccountTargetScope &Target) noexcept -> void
    {
        Result.Generation = Target.Generation;
        Result.Account = Target.Account;
    }

    inline auto ApplyCommandTarget(CommandResult &Result, const SessionTargetScope &Target) noexcept -> void
    {
        Result.Process = Target.Process;
        Result.Generation = Target.Generation;
        Result.Worker = Target.Worker;
        Result.Session = Target.Session;
    }

    inline auto ApplyCommandTarget(CommandResult &Result, const StreamTargetScope &Target) noexcept -> void
    {
        Result.Process = Target.Process;
        Result.Generation = Target.Generation;
        Result.Worker = Target.Worker;
        Result.Session = Target.Session;
        Result.Stream = Target.Stream;
        Result.ParentTask = Target.ParentTask;
        Result.Task = Target.Task;
    }

    inline auto ApplyCommandTarget(CommandResult &Result, const TaskTargetScope &Target) noexcept -> void
    {
        Result.Process = Target.Process;
        Result.Generation = Target.Generation;
        Result.Worker = Target.Worker;
        Result.Session = Target.Session;
        Result.Stream = Target.Stream;
        Result.ParentTask = Target.ParentTask;
        Result.Task = Target.Task;
    }

    /** @brief 在 Accepted 与 terminal 中投影同一 typed operation target。 */
    inline auto ApplyCommandTarget(CommandResult &Result, const CommandTargetScope &Scope) noexcept -> void
    {
        std::visit([&Result](const auto &Target) { ApplyCommandTarget(Result, Target); }, Scope);
    }

    enum class QueryStatus : std::uint8_t
    {
        Ok,
        Unavailable,
        NotFound,
        Failed,
        Invalid,
    };

    using QueryPayload = std::variant<std::monostate,
                                      HealthSnapshot,
                                      MetricsSnapshot,
                                      GenerationSnapshot,
                                      ConfigurationSnapshot,
                                      Page<WorkerSnapshot>,
                                      Page<AccountSnapshot>,
                                      Page<SessionSnapshot>,
                                      Page<StreamSnapshot>,
                                      Page<TaskSnapshot>,
                                      Preview::Statistics::EventPage>;

    struct QueryResult final
    {
        Preview::RequestId Correlation{};
        QueryStatus Status{QueryStatus::Unavailable};
        QueryPayload Value{};
        std::string Message{};
        Preview::Fault::Failure Failure{};

        [[nodiscard]] static auto Unavailable(const Preview::RequestId Correlation) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Unavailable, std::monostate{},
                               "handler_unavailable"};
        }

        [[nodiscard]] static auto NotFound(const Preview::RequestId Correlation) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::NotFound, std::monostate{},
                "stream_not_found"};
        }

        [[nodiscard]] static auto Invalid(const Preview::RequestId Correlation) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Invalid, std::monostate{},
                "invalid_query"};
        }

        [[nodiscard]] static auto Failed(
            const Preview::RequestId Correlation,
            Preview::Fault::Failure Failure) -> QueryResult
        {
            return QueryResult{
                Correlation, QueryStatus::Failed, std::monostate{}, "handler_failed", Failure};
        }

        [[nodiscard]] static auto Sessions(const Preview::RequestId Correlation,
                                           Page<SessionSnapshot> Value) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Ok, std::move(Value), {}};
        }

        [[nodiscard]] static auto Health(const Preview::RequestId Correlation,
                                         HealthSnapshot Value) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Ok, std::move(Value), {}};
        }

        [[nodiscard]] static auto Metrics(const Preview::RequestId Correlation,
                                          MetricsSnapshot Value) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Ok, std::move(Value), {}};
        }

        [[nodiscard]] static auto Generation(const Preview::RequestId Correlation,
                                             GenerationSnapshot Value) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Ok, std::move(Value), {}};
        }

        [[nodiscard]] static auto Configuration(
            const Preview::RequestId Correlation,
            ConfigurationSnapshot Value) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Ok, std::move(Value), {}};
        }

        [[nodiscard]] static auto Workers(const Preview::RequestId Correlation,
                                          Page<WorkerSnapshot> Value) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Ok, std::move(Value), {}};
        }

        [[nodiscard]] static auto Accounts(const Preview::RequestId Correlation,
                                           Page<AccountSnapshot> Value) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Ok, std::move(Value), {}};
        }

        [[nodiscard]] static auto Streams(const Preview::RequestId Correlation,
                                          Page<StreamSnapshot> Value) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Ok, std::move(Value), {}};
        }

        [[nodiscard]] static auto Tasks(const Preview::RequestId Correlation,
                                        Page<TaskSnapshot> Value) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Ok, std::move(Value), {}};
        }

        [[nodiscard]] static auto Events(const Preview::RequestId Correlation,
                                         Preview::Statistics::EventPage Value) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Ok, std::move(Value), {}};
        }
    };

} // namespace Preview::Operations
