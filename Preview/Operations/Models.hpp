/**
 * @file Models.hpp
 * @brief Preview 管理面查询、命令和结果值模型。
 */

#pragma once

#include <Preview/Statistics/Statistics.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace Preview::Operations
{

    struct OperationTag;
    using OperationId = Preview::Identifier::Id<OperationTag>;

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

    struct PageRequest final
    {
        static constexpr std::size_t MaxLimit = 256;

        std::uint64_t Cursor{0};
        std::size_t Limit{50};

        [[nodiscard]] auto BoundedLimit() const noexcept -> std::size_t
        {
            return Limit > MaxLimit ? MaxLimit : Limit;
        }
    };

    template <typename Value>
    struct Page final
    {
        std::vector<Value> Items;
        std::uint64_t NextCursor{0};
        bool HasMore{false};
    };

    struct HealthQuery final
    {
        Preview::RequestId Correlation{};
    };

    struct GenerationQuery final
    {
        Preview::RequestId Correlation{};
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

    struct StreamQuery final
    {
        Preview::RequestId Correlation{};
        PageRequest Page{};
        Preview::StreamId Id{};
    };

    struct TaskQuery final
    {
        Preview::RequestId Correlation{};
        PageRequest Page{};
        Preview::TaskId Id{};
    };

    struct EventQuery final
    {
        Preview::RequestId Correlation{};
        PageRequest Page{};
        bool IncludeDetails{true};
    };

    using QueryValue = std::variant<HealthQuery,
                                    GenerationQuery,
                                    WorkerQuery,
                                    AccountQuery,
                                    SessionQuery,
                                    StreamQuery,
                                    TaskQuery,
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

    struct ReloadCommand final
    {
        Preview::RequestId Correlation{};
        Preview::GenerationId CurrentGeneration{};
        Preview::GenerationId TargetGeneration{};
        bool ValidateOnly{false};
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
        Preview::SessionId Session{};
        Preview::StreamId Stream{};
        Preview::TaskId Task{};
    };

    struct DrainCommand final
    {
        Preview::RequestId Correlation{};
        Preview::WorkerId Worker{};
        bool StopAccepting{true};
        bool Force{false};
    };

    using CommandValue = std::variant<ReloadCommand, RevokeCommand, CancelCommand, DrainCommand>;

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
        Invalid,
    };

    struct CommandResult final
    {
        Preview::RequestId Correlation{};
        CommandStatus Status{CommandStatus::Unavailable};
        OperationId Operation{};
        Preview::GenerationId Generation{};
        Preview::WorkerId Worker{};
        Preview::AccountId Account{};
        Preview::SessionId Session{};
        Preview::StreamId Stream{};
        Preview::TaskId Task{};
        std::string Message{};

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

        [[nodiscard]] static auto Failed(const Preview::RequestId Correlation) -> CommandResult
        {
            auto Result = Completed(Correlation);
            Result.Status = CommandStatus::Failed;
            Result.Message = "handler_failed";
            return Result;
        }
    };

    enum class QueryStatus : std::uint8_t
    {
        Ok,
        Unavailable,
        Failed,
        Invalid,
    };

    using QueryPayload = std::variant<std::monostate,
                                      HealthSnapshot,
                                      GenerationSnapshot,
                                      Page<WorkerSnapshot>,
                                      Page<AccountSnapshot>,
                                      Page<SessionSnapshot>,
                                      Page<StreamSnapshot>,
                                      Page<TaskSnapshot>,
                                      Page<EventSnapshot>>;

    struct QueryResult final
    {
        Preview::RequestId Correlation{};
        QueryStatus Status{QueryStatus::Unavailable};
        QueryPayload Value{};
        std::string Message{};

        [[nodiscard]] static auto Unavailable(const Preview::RequestId Correlation) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Unavailable, std::monostate{},
                               "handler_unavailable"};
        }

        [[nodiscard]] static auto Failed(const Preview::RequestId Correlation) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Failed, std::monostate{}, "handler_failed"};
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

        [[nodiscard]] static auto Generation(const Preview::RequestId Correlation,
                                             GenerationSnapshot Value) -> QueryResult
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
                                         Page<EventSnapshot> Value) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Ok, std::move(Value), {}};
        }
    };

} // namespace Preview::Operations
