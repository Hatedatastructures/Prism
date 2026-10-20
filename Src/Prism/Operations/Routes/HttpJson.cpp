/** @file HttpJson.cpp @brief Operations stream JSON 的编译单元实现。 */
#include <Prism/Operations/Routes/HttpJson.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Operations/Http/JsonWriter.hpp>
#include <Prism/Operations/Routes/EventJson.hpp>
#include <Prism/Operations/Routes/MetricsJson.hpp>
#include <Prism/Operations/Routes/TrafficJson.hpp>
#include <Prism/Operations/Detail/TrafficJsonSupport.hpp>
#include <Prism/Operations/Routes/ManagementJson.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <variant>

namespace Prism::Operations::HttpDetail
{
    auto AppendStream(JsonWriter& Writer, const StreamSnapshot& Value) -> bool
    {
        if (!Writer.Append("{") || !Writer.Key("id") || !AppendId(Writer, Value.Id) ||
            !Writer.Append(",") || !Writer.Key("task") || !AppendId(Writer, Value.Task) ||
            !Writer.Append(",") || !Writer.Key("parent_task") || !AppendId(Writer, Value.ParentTask) ||
            !Writer.Append(",") || !Writer.Key("process") || !AppendId(Writer, Value.Process) ||
            !Writer.Append(",") || !Writer.Key("session") || !AppendId(Writer, Value.Session) ||
            !Writer.Append(",") || !Writer.Key("account") || !AppendId(Writer, Value.Account) ||
            !Writer.Append(",") || !Writer.Key("worker") || !AppendId(Writer, Value.Worker) ||
            !Writer.Append(",") || !Writer.Key("generation") || !AppendId(Writer, Value.Generation) ||
            !Writer.Append(",") || !Writer.Key("traffic")) return false;
        if (Value.Traffic)
        {
            if (!AppendTraffic(Writer, *Value.Traffic)) return false;
        }
        else if (!Writer.Null())
        {
            return false;
        }
        if (!Writer.Append(",") || !Writer.Key("protocol") || !Writer.String(Value.Protocol) ||
            !Writer.Append(",") || !Writer.Key("state")) return false;
        if (Value.Active)
        {
            if (!Writer.String("active")) return false;
        }
        else if (!Writer.String("draining"))
        {
            return false;
        }
        return Writer.Append("}");
    }
}

namespace Prism::Operations::HttpDetail
{

    [[nodiscard]] auto HealthStatusName(const HealthStatus Value) -> std::string_view
    {
        switch (Value)
        {
        case HealthStatus::Healthy:
            return "healthy";
        case HealthStatus::Degraded:
            return "degraded";
        case HealthStatus::Unhealthy:
            return "unhealthy";
        case HealthStatus::Draining:
            return "draining";
        case HealthStatus::Unknown:
            return "unknown";
        }
        return "unknown";
    }

    [[nodiscard]] auto CommandStatusName(const CommandStatus Value) -> std::string_view
    {
        switch (Value)
        {
        case CommandStatus::Accepted:
            return "accepted";
        case CommandStatus::Completed:
            return "completed";
        case CommandStatus::Rejected:
            return "rejected";
        case CommandStatus::Unavailable:
            return "unavailable";
        case CommandStatus::Failed:
            return "failed";
        case CommandStatus::TimedOut:
            return "timed_out";
        case CommandStatus::Blocked:
            return "blocked";
        case CommandStatus::RestartRequired:
            return "restart_required";
        case CommandStatus::Conflict:
            return "conflict";
        case CommandStatus::Invalid:
            return "invalid";
        }
        return "invalid";
    }

    [[nodiscard]] auto QueryStatusName(const QueryStatus Value) -> std::string_view
    {
        switch (Value)
        {
        case QueryStatus::Ok:
            return "ok";
        case QueryStatus::Unavailable:
            return "unavailable";
        case QueryStatus::NotFound:
            return "not_found";
        case QueryStatus::Failed:
            return "failed";
        case QueryStatus::Invalid:
            return "invalid";
        }
        return "invalid";
    }

    [[nodiscard]] auto StatusFor(const QueryStatus Status) noexcept -> int
    {
        switch (Status)
        {
        case QueryStatus::Ok:
            return 200;
        case QueryStatus::Unavailable:
            return 503;
        case QueryStatus::NotFound:
            return 404;
        case QueryStatus::Failed:
            return 500;
        case QueryStatus::Invalid:
            return 400;
        }
        return 500;
    }

    [[nodiscard]] auto StatusFor(const CommandStatus Status) noexcept -> int
    {
        switch (Status)
        {
        case CommandStatus::Accepted:
            return 202;
        case CommandStatus::Completed:
            return 200;
        case CommandStatus::Rejected:
        case CommandStatus::Invalid:
            return 400;
        case CommandStatus::Unavailable:
            return 503;
        case CommandStatus::Failed:
            return 500;
        case CommandStatus::TimedOut:
            return 504;
        case CommandStatus::RestartRequired:
        case CommandStatus::Conflict:
        case CommandStatus::Blocked:
            return 409;
        }
        return 500;
    }

    /** @brief 序列化终态的 typed Failure，并保留原生 category/value 身份。 */
    [[nodiscard]] auto AppendFailure(JsonWriter &Writer,
                                            const Prism::Fault::Failure &Failure) -> bool
    {
        if (!Writer.Append("{") || !Writer.Key("code") ||
            !Writer.String(Prism::Fault::Describe(Failure.Code)))
        {
            return false;
        }
        if (Failure.Native)
        {
            std::array<char, 32> ValueBuffer{};
            const auto [ValueEnd, ValueError] = std::to_chars(
                ValueBuffer.data(), ValueBuffer.data() + ValueBuffer.size(),
                Failure.Native.value());
            if (ValueError != std::errc{} || !Writer.Append(",") ||
                !Writer.Key("native_category") ||
                !Writer.String(Failure.Native.category().name()) ||
                !Writer.Append(",") || !Writer.Key("native_value") ||
                !Writer.Append(std::string_view(
                    ValueBuffer.data(), static_cast<std::size_t>(ValueEnd - ValueBuffer.data()))))
            {
                return false;
            }
        }
        return Writer.Append("}");
    }

    /** @brief 序列化可选 typed Failure；成功使用 JSON null，不制造成功失败对象。 */
    [[nodiscard]] auto AppendOptionalFailure(
        JsonWriter &Writer,
        const Prism::Fault::Failure &Failure) -> bool
    {
        if (Failure.Failed())
        {
            return AppendFailure(Writer, Failure);
        }
        return Writer.Null();
    }

    /** @brief 序列化动态范围统计退休失败的进程级分项事实。 */
    [[nodiscard]] auto AppendRetirementFailures(
        JsonWriter &Writer,
        const Prism::Statistics::RetirementFailureSnapshot &Value) -> bool
    {
        return Writer.Append("{") && Writer.Key("session") && Writer.Decimal(Value.Session) &&
               Writer.Append(",") && Writer.Key("stream") && Writer.Decimal(Value.Stream) &&
               Writer.Append(",") && Writer.Key("task") && Writer.Decimal(Value.Task) &&
               Writer.Append("}");
    }

    /** @brief 序列化运行状态和协议就绪字段，不结束 JSON 对象。 */
    [[nodiscard]] auto AppendHealthFields(JsonWriter &Writer, const HealthSnapshot &Value) -> bool
    {
        return Writer.Append("{") && Writer.Key("status") && Writer.String(HealthStatusName(Value.Status)) &&
               Writer.Append(",") && Writer.Key("checked_at") && AppendUtcTimestamp(Writer, Value.CheckedAt) &&
               Writer.Append(",") && Writer.Key("active") && Writer.Decimal(Value.Active) &&
               Writer.Append(",") && Writer.Key("errors") && Writer.Decimal(Value.Errors) &&
               Writer.Append(",") && Writer.Key("ready") && Writer.Boolean(Value.Ready) &&
               Writer.Append(",") && Writer.Key("tcp_ready") && Writer.Boolean(Value.TcpReady) &&
               Writer.Append(",") && Writer.Key("udp_ready") && Writer.Boolean(Value.UdpReady) &&
               Writer.Append(",") && Writer.Key("udp_socket_ready") &&
               Writer.Boolean(Value.UdpSocketReady) &&
               Writer.Append(",") && Writer.Key("quic_ready") && Writer.Boolean(Value.QuicReady) &&
               Writer.Append(",") && Writer.Key("quic_socket_ready") &&
               Writer.Boolean(Value.QuicSocketReady) &&
               Writer.Append(",") && Writer.Key("quic_handshake_ready") &&
               Writer.Boolean(Value.QuicHandshakeReady) &&
               Writer.Append(",") && Writer.Key("quic_protocol_ready") &&
               Writer.Boolean(Value.QuicProtocolReady);
    }

    /** @brief 序列化嵌套在 worker 或 generation 中的健康字段。 */
    [[nodiscard]] auto AppendHealth(JsonWriter &Writer, const HealthSnapshot &Value) -> bool
    {
        return AppendHealthFields(Writer, Value) && Writer.Append("}");
    }

    /** @brief 序列化进程健康响应并附加同一 TrafficCounter 的动态 scope 退休失败事实。 */
    [[nodiscard]] auto AppendOperationsHealth(JsonWriter &Writer, const HealthSnapshot &Value) -> bool
    {
        return AppendHealthFields(Writer, Value) && Writer.Append(",") &&
               Writer.Key("retirement_failures") &&
               AppendRetirementFailures(Writer, Value.ProcessRetirementFailures) && Writer.Append("}");
    }

    [[nodiscard]] auto AppendGeneration(JsonWriter &Writer, const GenerationSnapshot &Value) -> bool
    {
        return Writer.Append("{") && Writer.Key("id") && AppendId(Writer, Value.Id) &&
               Writer.Append(",") && Writer.Key("created_at") && AppendUtcTimestamp(Writer, Value.CreatedAt) &&
               Writer.Append(",") && Writer.Key("active") && Writer.Boolean(Value.Active) &&
               Writer.Append(",") && Writer.Key("retiring") && Writer.Boolean(Value.Retiring) &&
               Writer.Append(",") && Writer.Key("health") && AppendHealth(Writer, Value.Health) &&
               Writer.Append("}");
    }

    /** @brief 未安装统计 collector 时显式输出 null，不以零流量代替不可用。 */
    [[nodiscard]] auto AppendOptionalTraffic(
        JsonWriter &Writer,
        const std::optional<Prism::Statistics::TrafficValue> &Value) -> bool
    {
        return Value ? AppendTraffic(Writer, *Value) : Writer.Null();
    }

    [[nodiscard]] auto AppendWorker(JsonWriter &Writer, const WorkerSnapshot &Value) -> bool
    {
        return Writer.Append("{") && Writer.Key("process") && AppendId(Writer, Value.Process) &&
               Writer.Append(",") && Writer.Key("id") && AppendId(Writer, Value.Id) &&
               Writer.Append(",") && Writer.Key("generation") && AppendId(Writer, Value.Generation) &&
               Writer.Append(",") && Writer.Key("health") && AppendHealth(Writer, Value.Health) &&
               Writer.Append(",") && Writer.Key("traffic") && AppendOptionalTraffic(Writer, Value.Traffic) &&
               Writer.Append(",") && Writer.Key("running") && Writer.Boolean(Value.Running) &&
               Writer.Append(",") && Writer.Key("accepting") && Writer.Boolean(Value.Accepting) &&
               Writer.Append(",") && Writer.Key("active_tasks") && Writer.Decimal(Value.ActiveTasks) &&
               Writer.Append(",") && Writer.Key("dropped_events") && Writer.Decimal(Value.DroppedEvents) &&
               Writer.Append(",") && Writer.Key("queue") && Writer.Append("{") &&
               Writer.Key("depth") && Writer.Decimal(Value.MailboxDepth) && Writer.Append(",") &&
               Writer.Key("capacity") && Writer.Decimal(Value.MailboxCapacity) && Writer.Append("}") &&
               Writer.Append(",") && Writer.Key("tasks") && Writer.Append("{") &&
               Writer.Key("started") && Writer.Decimal(Value.StartedTasks) && Writer.Append(",") &&
               Writer.Key("completed") && Writer.Decimal(Value.CompletedTasks) && Writer.Append(",") &&
               Writer.Key("cancelled") && Writer.Decimal(Value.CancelledTasks) && Writer.Append("}") &&
               Writer.Append(",") && Writer.Key("dispatch") && Writer.Append("{") &&
               Writer.Key("accepted") && Writer.Decimal(Value.DispatchAccepted) && Writer.Append(",") &&
               Writer.Key("full") && Writer.Decimal(Value.DispatchFull) && Writer.Append(",") &&
               Writer.Key("closed") && Writer.Decimal(Value.DispatchClosed) && Writer.Append(",") &&
               Writer.Key("unavailable") && Writer.Decimal(Value.DispatchUnavailable) && Writer.Append(",") &&
               Writer.Key("generation_rejected") && Writer.Decimal(Value.DispatchGenerationRejected) &&
               Writer.Append("}") && Writer.Append(",") && Writer.Key("commands") && Writer.Append("{") &&
               Writer.Key("executed") && Writer.Decimal(Value.CommandsExecuted) && Writer.Append(",") &&
               Writer.Key("failed") && Writer.Decimal(Value.CommandsFailed) && Writer.Append("}") &&
               Writer.Append("}");
    }

    [[nodiscard]] auto AppendAccount(JsonWriter &Writer, const AccountSnapshot &Value) -> bool
    {
        if (!Writer.Append("{") || !Writer.Key("id") || !AppendId(Writer, Value.Id) ||
            !Writer.Append(",") || !Writer.Key("generation") || !AppendId(Writer, Value.Generation) ||
            !Writer.Append(",") || !Writer.Key("traffic") || !AppendOptionalTraffic(Writer, Value.Traffic) ||
            !Writer.Append(",") || !Writer.Key("active_sessions") ||
            !Writer.Decimal(Value.ActiveSessions) || !Writer.Append(",") || !Writer.Key("label") ||
            !Writer.String(Value.Label) || !Writer.Append(",") || !Writer.Key("revoked") ||
            !Writer.Boolean(Value.Revoked))
        {
            return false;
        }
        return (!Value.GroupId || (Writer.Append(",") && Writer.Key("group_id") && Writer.String(*Value.GroupId))) &&
               Writer.Append("}");
    }

    [[nodiscard]] auto AppendSession(JsonWriter &Writer, const SessionSnapshot &Value) -> bool
    {
        return Writer.Append("{") && Writer.Key("id") && AppendId(Writer, Value.Id) &&
               Writer.Append(",") && Writer.Key("process") && AppendId(Writer, Value.Process) &&
               Writer.Append(",") && Writer.Key("worker") && AppendId(Writer, Value.Worker) &&
               Writer.Append(",") && Writer.Key("account") && AppendId(Writer, Value.Account) &&
               Writer.Append(",") && Writer.Key("generation") && AppendId(Writer, Value.Generation) &&
               Writer.Append(",") && Writer.Key("traffic") && AppendOptionalTraffic(Writer, Value.Traffic) &&
               Writer.Append(",") && Writer.Key("started_at") && AppendUtcTimestamp(Writer, Value.StartedAt) &&
               Writer.Append(",") && Writer.Key("transport") && Writer.String(Value.Transport) &&
               Writer.Append(",") && Writer.Key("identity") && Writer.String(Value.Identity) &&
               Writer.Append(",") && Writer.Key("source_address") && Writer.String(Value.SourceAddress) &&
               Writer.Append(",") && Writer.Key("protocol") && Writer.String(Value.Protocol) &&
               Writer.Append(",") && Writer.Key("target") && Writer.String(Value.Target) &&
               Writer.Append(",") && Writer.Key("active") && Writer.Boolean(Value.Active) &&
               Writer.Append(",") && Writer.Key("draining") && Writer.Boolean(Value.Draining) &&
               Writer.Append(",") && Writer.Key("active_tasks") &&
               (Value.ActiveTasks ? Writer.Decimal(*Value.ActiveTasks) : Writer.Null()) &&
               Writer.Append("}");
    }

    [[nodiscard]] auto TaskStatusName(const TaskStatus Value) -> std::string_view
    {
        switch (Value)
        {
        case TaskStatus::Pending:
            return "pending";
        case TaskStatus::Running:
            return "running";
        case TaskStatus::Succeeded:
            return "succeeded";
        case TaskStatus::Failed:
            return "failed";
        case TaskStatus::Canceled:
            return "canceled";
        case TaskStatus::Quarantined:
            return "quarantined";
        }
        return "pending";
    }

    [[nodiscard]] auto AppendTask(JsonWriter &Writer, const TaskSnapshot &Value) -> bool
    {
        if (!Writer.Append("{") || !Writer.Key("id") || !AppendId(Writer, Value.Id) ||
            !Writer.Append(",") || !Writer.Key("process") || !AppendId(Writer, Value.Process) ||
            !Writer.Append(",") || !Writer.Key("worker") || !AppendId(Writer, Value.Worker) ||
            !Writer.Append(",") || !Writer.Key("session") || !AppendId(Writer, Value.Session) ||
            !Writer.Append(",") || !Writer.Key("stream") || !AppendId(Writer, Value.Stream) ||
            !Writer.Append(",") || !Writer.Key("generation") || !AppendId(Writer, Value.Generation) ||
            !Writer.Append(",") || !Writer.Key("parent_task") || !AppendId(Writer, Value.ParentTask) ||
            !Writer.Append(",") || !Writer.Key("status") ||
            !Writer.String(TaskStatusName(Value.Status)) || !Writer.Append(",") ||
            !Writer.Key("started_at") || !AppendOptionalUtcTimestamp(Writer, Value.StartedAt) ||
            !Writer.Append(",") || !Writer.Key("completed_at") || !AppendOptionalUtcTimestamp(Writer, Value.CompletedAt) ||
            !Writer.Append(",") || !Writer.Key("cancel_requested") ||
            !Writer.Boolean(Value.CancelRequested) || !Writer.Append(",") ||
            !Writer.Key("cancellable") || !Writer.Boolean(Value.Cancellable) || !Writer.Append(",") ||
            !Writer.Key("drain_blocked") || !Writer.Boolean(Value.DrainBlocked) ||
            !Writer.Append(",") || !Writer.Key("failure") ||
            !AppendOptionalFailure(Writer, Value.Failure) || !Writer.Append(",") ||
            !Writer.Key("drain_failure"))
        {
            return false;
        }
        return AppendOptionalFailure(Writer, Value.DrainFailure) && Writer.Append("}");
    }

    [[nodiscard]] auto AppendConfiguration(
        JsonWriter &Writer,
        const ConfigurationSnapshot &Value) -> bool
    {
        return Writer.Append("{") && Writer.Key("generation") &&
            AppendId(Writer, Value.Generation) && Writer.Append(",") &&
            Writer.Key("reloadable") && Writer.Boolean(Value.Reloadable) &&
            Writer.Append(",") && Writer.Key("configuration") &&
            Writer.Append(Value.Json) && Writer.Append("}");
    }

    template <typename Value>
    [[nodiscard]] auto AppendPage(JsonWriter &Writer,
                                         const Page<Value> &ValuePage,
                                         auto Appender) -> bool
    {
        if (!Writer.Append("{\"items\":["))
        {
            return false;
        }
        bool First = true;
        for (const auto &Item : ValuePage.Items)
        {
            if (!AppendComma(Writer, First) || !Appender(Writer, Item))
            {
                return false;
            }
        }
        return Writer.Append("],\"next_cursor\":") && Writer.Decimal(ValuePage.NextCursor) &&
               Writer.Append(",\"has_more\":") && Writer.Boolean(ValuePage.HasMore) &&
               Writer.Append("}");
    }

    /** @brief 同步借用 typed payload，按既有格式写有界 JSON；不持有业务或网络 owner。 */
    template <typename PayloadValue>
    [[nodiscard]] auto AppendQueryPayload(JsonWriter &Writer, const PayloadValue &Payload,
                                                 const bool IncludeDetails) -> bool
    {
        using PayloadType = std::remove_cvref_t<PayloadValue>;
        if constexpr (std::is_same_v<PayloadType, std::monostate>)
            return Writer.Null();
        else if constexpr (std::is_same_v<PayloadType, HealthSnapshot>)
            return AppendOperationsHealth(Writer, Payload);
        else if constexpr (std::is_same_v<PayloadType, MetricsSnapshot>)
            return AppendMetrics(Writer, Payload);
        else if constexpr (std::is_same_v<PayloadType, GenerationSnapshot>)
            return AppendGeneration(Writer, Payload);
        else if constexpr (std::is_same_v<PayloadType, ConfigurationSnapshot>)
            return AppendConfiguration(Writer, Payload);
        else if constexpr (std::is_same_v<PayloadType, Page<WorkerSnapshot>>)
            return AppendPage(Writer, Payload, AppendWorker);
        else if constexpr (std::is_same_v<PayloadType, Page<AccountSnapshot>>)
            return AppendPage(Writer, Payload, AppendAccount);
        else if constexpr (std::is_same_v<PayloadType, Page<SessionSnapshot>>)
            return AppendPage(Writer, Payload, AppendSession);
        else if constexpr (std::is_same_v<PayloadType, Page<StreamSnapshot>>)
            return AppendPage(Writer, Payload, AppendStream);
        else if constexpr (std::is_same_v<PayloadType, Page<TaskSnapshot>>)
            return AppendPage(Writer, Payload, AppendTask);
        else if constexpr (std::is_same_v<PayloadType, ManagementPayload>)
            return AppendManagementPayload(Writer, Payload);
        else return AppendEventPage(Writer, Payload, IncludeDetails);
    }

    [[nodiscard]] auto AppendQueryValue(JsonWriter &Writer,
                                               const QueryPayload &Value,
                                               const bool IncludeDetails) -> bool
    {
        return std::visit(
            [&Writer, IncludeDetails](const auto &Payload)
            { return AppendQueryPayload(Writer, Payload, IncludeDetails); },
            Value);
    }

    /** @brief 同步借用命令结果；上限拒绝，不截断或制造额外字段。 */
    [[nodiscard]] auto AppendConfigurationOutcome(JsonWriter& Writer,
        const CommandResult& Result) -> bool
    {
        if (Result.ConfigurationIssues.size() > 64 || Result.RestartRequiredFields.size() > 64 ||
            !Writer.Append(",") || !Writer.Key("configuration_issues") || !Writer.Append("["))
            return false;
        bool First = true;
        for (const auto& Issue : Result.ConfigurationIssues)
        {
            if (!AppendComma(Writer, First) || !Writer.Append("{") || !Writer.Key("code") ||
                !Writer.String(Issue.Code) || !Writer.Append(",") || !Writer.Key("path") ||
                !Writer.String(Issue.Path) || !Writer.Append(",") || !Writer.Key("message") ||
                !Writer.String(Issue.Message) || !Writer.Append("}")) return false;
        }
        if (!Writer.Append("],") || !Writer.Key("restart_required_fields") || !Writer.Append("["))
            return false;
        First = true;
        for (const auto& Field : Result.RestartRequiredFields)
            if (!AppendComma(Writer, First) || !Writer.String(Field)) return false;
        return Writer.Append("]");
    }

    [[nodiscard]] auto SerializeQuery(const QueryResult &Result,
                                              const bool IncludeDetails)
        -> std::optional<std::string>
    {
        JsonWriter Writer;
        if (!Writer.Append("{") || !Writer.Key("correlation") ||
            !AppendId(Writer, Result.Correlation) || !Writer.Append(",") ||
            !Writer.Key("status") || !Writer.String(QueryStatusName(Result.Status)) ||
            !Writer.Append(",") || !Writer.Key("value") ||
            !AppendQueryValue(Writer, Result.Value, IncludeDetails) || !Writer.Append(",") ||
            !Writer.Key("message") || !Writer.String(Result.Message) || !Writer.Append(",") ||
            !Writer.Key("failure") ||
            !AppendOptionalFailure(Writer, Result.Failure) || !Writer.Append("}") ||
            !Writer.Good())
        {
            return std::nullopt;
        }
        return std::move(Writer).Take();
    }

    [[nodiscard]] auto SerializeCommand(const CommandResult &Result)
        -> std::optional<std::string>
    {
        JsonWriter Writer;
        if (!Writer.Append("{") || !Writer.Key("correlation") ||
            !AppendId(Writer, Result.Correlation) || !Writer.Append(",") ||
            !Writer.Key("status") || !Writer.String(CommandStatusName(Result.Status)) ||
            !Writer.Append(",") || !Writer.Key("operation") || !AppendId(Writer, Result.Operation) ||
            !Writer.Append(",") || !Writer.Key("generation") || !AppendId(Writer, Result.Generation) ||
            !Writer.Append(",") || !Writer.Key("worker") || !AppendId(Writer, Result.Worker) ||
            !Writer.Append(",") || !Writer.Key("account") || !AppendId(Writer, Result.Account) ||
            !Writer.Append(",") || !Writer.Key("session") || !AppendId(Writer, Result.Session) ||
            !Writer.Append(",") || !Writer.Key("stream") || !AppendId(Writer, Result.Stream) ||
            !Writer.Append(",") || !Writer.Key("task") || !AppendId(Writer, Result.Task) ||
            !Writer.Append(",") || !Writer.Key("message") || !Writer.String(Result.Message) ||
            !AppendConfigurationOutcome(Writer, Result))
        {
            return std::nullopt;
        }
        if (Result.Process &&
            (!Writer.Append(",") || !Writer.Key("process") || !AppendId(Writer, Result.Process)))
        {
            return std::nullopt;
        }
        if (Result.ParentTask &&
            (!Writer.Append(",") || !Writer.Key("parent_task") ||
             !AppendId(Writer, Result.ParentTask)))
        {
            return std::nullopt;
        }
        if (Result.Failure.Failed() &&
            (!Writer.Append(",") || !Writer.Key("failure") ||
             !AppendFailure(Writer, Result.Failure)))
        {
            return std::nullopt;
        }
        if (!Writer.Append("}") || !Writer.Good()) return std::nullopt;
        return std::move(Writer).Take();
    }

    [[nodiscard]] auto HttpReason(const int Status) -> std::string_view
    {
        switch (Status)
        {
        case 200:
            return "OK";
        case 202:
            return "Accepted";
        case 400:
            return "Bad Request";
        case 403:
            return "Forbidden";
        case 404:
            return "Not Found";
        case 409:
            return "Conflict";
        case 405:
            return "Method Not Allowed";
        case 504:
            return "Gateway Timeout";
        case 413:
            return "Payload Too Large";
        case 500:
            return "Internal Server Error";
        case 501:
            return "Not Implemented";
        case 503:
            return "Service Unavailable";
        default:
            return "Internal Server Error";
        }
    }

    [[nodiscard]] auto MakeResponse(const int Status, std::string Body) -> std::string
    {
        std::string Result;
        Result.reserve(96U + Body.size());
        Result.append("HTTP/1.1 ").append(std::to_string(Status)).push_back(' ');
        Result.append(HttpReason(Status));
        Result.append("\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: ");
        Result.append(std::to_string(Body.size())).append("\r\n\r\n");
        Result.append(std::move(Body));
        return Result;
    }

    [[nodiscard]] auto MakeErrorBody(
        const std::string_view Message,
        const Prism::RequestId Correlation) -> std::optional<std::string>
    {
        JsonWriter Writer;
        if (!Writer.Append("{") || !Writer.Key("correlation") || !AppendId(Writer, Correlation) ||
            !Writer.Append(",") || !Writer.Key("error") || !Writer.String(Message) ||
            !Writer.Append("}") || !Writer.Good())
        {
            return std::nullopt;
        }
        return std::move(Writer).Take();
    }

    [[nodiscard]] auto MakeErrorResponse(
        const int Status,
        const std::string_view Message,
        const Prism::RequestId Correlation) -> std::string
    {
        auto Body = MakeErrorBody(Message, Correlation);
        if (!Body)
        {
            return MakeResponse(Status, "{\"error\":\"internal\"}");
        }
        return MakeResponse(Status, std::move(*Body));
    }
} // namespace Prism::Operations::HttpDetail
