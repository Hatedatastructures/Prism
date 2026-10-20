/**
 * @file Models.hpp
 * @brief Prism 管理面查询、命令和结果值模型。
 */

#pragma once

#include <Prism/Statistics/Statistics.hpp>
#include <Prism/Operations/Metrics.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Operations/QueryPage.hpp>
#include <Prism/Operations/ScopedCollectionModels.hpp>
#include <Prism/Operations/ManagementModels.hpp>
#include <Prism/Operations/QueryResult.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace Prism::Operations
{

    /** @brief 安全配置校验的字段与类别值，不拥有 secret 或执行域。 */
    struct ConfigurationIssue final
    {
        std::string Code;
        std::string Path;
        std::string Message;
    };

    /** @brief 每种异步操作只携带其真实目标所需身份。 */
    struct ProcessTargetScope final
    {
        Prism::ProcessId Process{};
    };

    /** @brief 单一 worker drain 的进程、代次与 worker 身份。 */
    struct WorkerTargetScope final
    {
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{};
        Prism::WorkerId Worker{};
    };

    /** @brief 单一代次内账户撤销的目标。 */
    struct AccountTargetScope final
    {
        Prism::GenerationId Generation{};
        Prism::AccountId Account{};
    };

    /** @brief 单一父 session cancel 的真实父身份。 */
    struct SessionTargetScope final
    {
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{};
        Prism::WorkerId Worker{};
        Prism::SessionId Session{};
    };

    /** @brief 单一 mux child reset 的父、stream 与任务身份。 */
    struct StreamTargetScope final
    {
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{};
        Prism::WorkerId Worker{};
        Prism::SessionId Session{};
        Prism::StreamId Stream{};
        Prism::TaskId ParentTask{};
        Prism::TaskId Task{};
    };

    /** @brief worker task retirement 的实际生命周期身份。 */
    struct TaskTargetScope final
    {
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{};
        Prism::WorkerId Worker{};
        Prism::SessionId Session{};
        Prism::StreamId Stream{};
        Prism::TaskId ParentTask{};
        Prism::TaskId Task{};
    };

    using CommandTargetScope = std::variant<
        ProcessTargetScope, WorkerTargetScope, AccountTargetScope,
        SessionTargetScope, StreamTargetScope, TaskTargetScope>;

    struct OperationTag;
    using OperationId = Prism::Identifier::Id<OperationTag>;

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
            Prism::ProcessId Process{};
            Incarnation ProcessIncarnation{};
            CommandToken Token{};
            std::string InstanceKey;
        };

        explicit BootstrapIdentity(Options Value)
            : Process_(Value.Process),
              Incarnation_(std::move(Value.ProcessIncarnation)),
              CommandToken_(std::move(Value.Token)),
              InstanceKey_(std::move(Value.InstanceKey))
        {
        }

        /** @brief 返回当前 Runtime::Process 提供的稳定进程身份。 */
        [[nodiscard]] auto Process() const noexcept -> Prism::ProcessId
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
        /** @brief 持久实例身份由数据目录保存；不由进程 PID 推导。 */
    public:
        [[nodiscard]] auto InstanceKey() const noexcept -> const std::string& { return InstanceKey_; }
    private:
        Prism::ProcessId Process_{};
        Incarnation Incarnation_{};
        CommandToken CommandToken_{};
        std::string InstanceKey_;
    };
    using HealthStatus = Prism::Statistics::HealthStatus;
    using HealthSnapshot = Prism::Statistics::HealthSnapshot;
    using GenerationSnapshot = Prism::Statistics::GenerationSnapshot;
    using ProcessSnapshot = Prism::Statistics::ProcessSnapshot;
    using WorkerSnapshot = Prism::Statistics::WorkerSnapshot;
    using AccountSnapshot = Prism::Statistics::AccountSnapshot;
    using SessionSnapshot = Prism::Statistics::SessionSnapshot;
    using StreamSnapshot = Prism::Statistics::StreamSnapshot;
    using TaskStatus = Prism::Statistics::TaskStatus;
    using TaskSnapshot = Prism::Statistics::TaskSnapshot;
    using EventSnapshot = Prism::Statistics::DetailedEvent;

    struct HealthQuery final
    {
        Prism::RequestId Correlation{};
    };

    struct GenerationQuery final
    {
        Prism::RequestId Correlation{};
        Prism::ProcessId Process{};
        Prism::GenerationId Id{};
    };

    struct WorkerQuery final
    {
        Prism::RequestId Correlation{};
        PageRequest Page{};
        Prism::WorkerId Id{};
    };

    struct AccountQuery final
    {
        Prism::RequestId Correlation{};
        PageRequest Page{};
        Prism::AccountId Id{};
    };

    struct SessionQuery final
    {
        Prism::RequestId Correlation{};
        PageRequest Page{};
        Prism::SessionId Id{};
    };

    /** @brief 以 process/generation/worker/session 完整父身份查询指定 stream。 */
    struct StreamQuery final
    {
        Prism::RequestId Correlation{};
        PageRequest Page{};
        Prism::ProcessId Process{}; ///< stream 所属进程。
        Prism::SessionId Session{}; ///< stream 所属会话。
        Prism::StreamId Id{}; ///< 被查询的 stream。
        Prism::GenerationId Generation{}; ///< 父会话绑定的 generation。
        Prism::WorkerId Worker{}; ///< 父会话绑定的 worker。
    };

    struct TaskQuery final
    {
        Prism::RequestId Correlation{};
        PageRequest Page{};
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{};
        Prism::WorkerId Worker{};
        Prism::SessionId Session{};
        Prism::StreamId Stream{};
        Prism::TaskId ParentTask{};
        Prism::TaskId Id{};
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
                                    ManagementQuery>;

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
        ApplyAndPersist,
    };

    struct ReloadCommand final
    {
        Prism::RequestId Correlation{};
        Prism::GenerationId BaseGeneration{};
        ReloadMode Mode{ReloadMode::ValidateOnly};
        std::string ConfigurationJson;
    };

    struct RevokeCommand final
    {
        Prism::RequestId Correlation{};
        Prism::AccountId Account{};
        bool CloseSessions{true};
    };

    struct CancelCommand final
    {
        Prism::RequestId Correlation{};
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{};
        Prism::WorkerId Worker{};
        Prism::SessionId Session{};
        Prism::StreamId Stream{};
        Prism::TaskId ParentTask{};
        Prism::TaskId Task{};
    };

    /** @brief 完整标识父 Session 与 root task 下单一 mux child stream 的 reset 命令。 */
    struct StreamResetCommand final
    {
        Prism::RequestId Correlation{};
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{};
        Prism::WorkerId Worker{};
        Prism::SessionId Session{};
        Prism::StreamId Stream{};
        Prism::TaskId ParentTask{};
        Prism::TaskId Task{};
    };

    struct ProcessDrainCommand final
    {
        Prism::RequestId Correlation{};
        bool Force{false};
    };

    struct WorkerDrainCommand final
    {
        Prism::RequestId Correlation{};
        Prism::WorkerId Worker{};
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
        -> Prism::RequestId
    {
        return std::visit([](const auto &ValueObject) { return ValueObject.Correlation; },
                          CommandValueObject.Value);
    }

    [[nodiscard]] inline auto CorrelationOf(const Query &QueryValueObject) noexcept
        -> Prism::RequestId
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
        Prism::RequestId Correlation{};
        CommandStatus Status{CommandStatus::Unavailable};
        OperationId Operation{};
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{};
        Prism::WorkerId Worker{};
        Prism::AccountId Account{};
        Prism::SessionId Session{};
        Prism::StreamId Stream{};
        Prism::TaskId Task{};
        Prism::TaskId ParentTask{};
        std::vector<ConfigurationIssue> ConfigurationIssues;
        std::vector<std::string> RestartRequiredFields;
        std::string Message{};
        Prism::Fault::Failure Failure{};

        [[nodiscard]] static auto Completed(const Prism::RequestId Correlation,
                                            const Prism::WorkerId Worker = {},
                                            const Prism::GenerationId Generation = {}) -> CommandResult
        {
            CommandResult Result;
            Result.Correlation = Correlation;
            Result.Status = CommandStatus::Completed;
            Result.Generation = Generation;
            Result.Worker = Worker;
            return Result;
        }

        [[nodiscard]] static auto Accepted(const Prism::RequestId Correlation,
                                           const OperationId Operation = {}) -> CommandResult
        {
            auto Result = Completed(Correlation);
            Result.Status = CommandStatus::Accepted;
            Result.Operation = Operation;
            return Result;
        }

        [[nodiscard]] static auto Rejected(const Prism::RequestId Correlation) -> CommandResult
        {
            auto Result = Completed(Correlation);
            Result.Status = CommandStatus::Rejected;
            Result.Message = "command_rejected";
            return Result;
        }

        [[nodiscard]] static auto Invalid(const Prism::RequestId Correlation) -> CommandResult
        {
            auto Result = Completed(Correlation);
            Result.Status = CommandStatus::Invalid;
            Result.Message = "command_invalid";
            return Result;
        }

        [[nodiscard]] static auto Unavailable(const Prism::RequestId Correlation) -> CommandResult
        {
            auto Result = Completed(Correlation);
            Result.Status = CommandStatus::Unavailable;
            Result.Message = "handler_unavailable";
            return Result;
        }

        [[nodiscard]] static auto Failed(const Prism::RequestId Correlation,
                                         const Prism::Fault::Failure Failure) -> CommandResult
        {
            auto Result = Completed(Correlation);
            Result.Status = CommandStatus::Failed;
            Result.Message = "handler_failed";
            Result.Failure = Failure;
            return Result;
        }

        [[nodiscard]] static auto TimedOut(const Prism::RequestId Correlation,
                                           const Prism::Fault::Failure Failure) -> CommandResult
        {
            auto Result = Completed(Correlation);
            Result.Status = CommandStatus::TimedOut;
            Result.Message = "command_timeout";
            Result.Failure = Failure;
            return Result;
        }

        [[nodiscard]] static auto Blocked(const Prism::RequestId Correlation,
                                          const Prism::Fault::Failure Failure) -> CommandResult
        {
            auto Result = Completed(Correlation);
            Result.Status = CommandStatus::Blocked;
            Result.Message = "command_blocked";
            Result.Failure = Failure;
            return Result;
        }

        [[nodiscard]] static auto RestartRequired(
            const Prism::RequestId Correlation,
            const Prism::GenerationId Generation) -> CommandResult
        {
            auto Result = Rejected(Correlation);
            Result.Status = CommandStatus::RestartRequired;
            Result.Generation = Generation;
            Result.Message = "restart_required";
            return Result;
        }

        /** @brief 读取基准已过期；返回真实当前代，未开始候选准备或发布。 */
        [[nodiscard]] static auto Conflict(const Prism::RequestId Correlation,
            const Prism::GenerationId Generation) -> CommandResult
        {
            auto Result = Completed(Correlation, {}, Generation);
            Result.Status = CommandStatus::Conflict;
            Result.Message = "generation_conflict";
            return Result;
        }

        [[nodiscard]] static auto FromFailure(const Prism::RequestId Correlation,
                                              const Prism::Fault::Failure Failure) -> CommandResult
        {
            if (Failure.Code == Prism::Fault::Code::Timeout)
            {
                return TimedOut(Correlation, Failure);
            }
            if (Failure.Code == Prism::Fault::Code::Blocked)
            {
                return Blocked(Correlation, Failure);
            }
            return Failed(Correlation, Failure);
        }

        [[nodiscard]] static auto HandlerFailed(const Prism::RequestId Correlation) -> CommandResult
        {
            return Failed(Correlation,
                          Prism::Fault::Failure{Prism::Fault::Code::GenericError});
        }
    };

    /** @brief 按目标类型把身份字段写入唯一命令结果。 */
    auto ApplyCommandTarget(CommandResult &Result, const ProcessTargetScope &Target) noexcept -> void;
    auto ApplyCommandTarget(CommandResult &Result, const WorkerTargetScope &Target) noexcept -> void;
    auto ApplyCommandTarget(CommandResult &Result, const AccountTargetScope &Target) noexcept -> void;
    auto ApplyCommandTarget(CommandResult &Result, const SessionTargetScope &Target) noexcept -> void;
    auto ApplyCommandTarget(CommandResult &Result, const StreamTargetScope &Target) noexcept -> void;
    auto ApplyCommandTarget(CommandResult &Result, const TaskTargetScope &Target) noexcept -> void;

    /** @brief 在 Accepted 与 terminal 中投影同一 typed operation target。 */
    auto ApplyCommandTarget(CommandResult &Result, const CommandTargetScope &Scope) noexcept -> void;

} // namespace Prism::Operations
