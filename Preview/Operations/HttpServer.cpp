/**
 * @file HttpServer.cpp
 * @brief Preview Operations loopback HTTP/1.1 管理监听器实现。
 */

#include "HttpServer.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/errc.hpp>

#include <array>
#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace Preview::Operations
{

    namespace
    {

        using Tcp = Net::ip::tcp;

        [[nodiscard]] auto ToLower(const char Value) noexcept -> char
        {
            return static_cast<char>(std::tolower(static_cast<unsigned char>(Value)));
        }

        [[nodiscard]] auto EqualsInsensitive(const std::string_view Left,
                                             const std::string_view Right) noexcept -> bool
        {
            if (Left.size() != Right.size())
            {
                return false;
            }
            for (std::size_t Index = 0; Index < Left.size(); ++Index)
            {
                if (ToLower(Left[Index]) != ToLower(Right[Index]))
                {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] auto IsTokenCharacter(const char Value) noexcept -> bool
        {
            const auto Byte = static_cast<unsigned char>(Value);
            if ((Byte >= 'A' && Byte <= 'Z') || (Byte >= 'a' && Byte <= 'z') ||
                (Byte >= '0' && Byte <= '9'))
            {
                return true;
            }
            constexpr std::string_view Punctuation{"!#$%&'*+-.^_`|~"};
            return Punctuation.find(Value) != std::string_view::npos;
        }

        [[nodiscard]] auto IsFieldValueCharacter(const char Value) noexcept -> bool
        {
            const auto Byte = static_cast<unsigned char>(Value);
            return Byte == '\t' || (Byte >= 0x20U && Byte != 0x7fU);
        }

        [[nodiscard]] auto Trim(const std::string_view Value) noexcept -> std::string_view
        {
            auto Result = Value;
            while (!Result.empty() && (Result.front() == ' ' || Result.front() == '\t'))
            {
                Result.remove_prefix(1);
            }
            while (!Result.empty() && (Result.back() == ' ' || Result.back() == '\t'))
            {
                Result.remove_suffix(1);
            }
            return Result;
        }

        template <typename Value>
        [[nodiscard]] auto ParseUnsigned(const std::string_view Text, Value &Result) -> bool
        {
            if (Text.empty())
            {
                return false;
            }
            Value Parsed{};
            const auto *First = Text.data();
            const auto *Last = First + Text.size();
            const auto [End, Error] = std::from_chars(First, Last, Parsed, 10);
            if (Error != std::errc{} || End != Last)
            {
                return false;
            }
            Result = Parsed;
            return true;
        }

        [[nodiscard]] auto ParseBoolean(const std::string_view Text, bool &Result) -> bool
        {
            if (Text == "true" || Text == "1")
            {
                Result = true;
                return true;
            }
            if (Text == "false" || Text == "0")
            {
                Result = false;
                return true;
            }
            return false;
        }

        class JsonWriter final
        {
        public:
            explicit JsonWriter(const std::size_t Limit = MaxResponseBytes) : Limit_(Limit)
            {
                Value_.reserve(std::min<std::size_t>(Limit_, 4096U));
            }

            [[nodiscard]] auto Append(const std::string_view Value) -> bool
            {
                if (Value.size() > Limit_ - std::min(Value_.size(), Limit_))
                {
                    Failed_ = true;
                    return false;
                }
                Value_.append(Value);
                return true;
            }

            [[nodiscard]] auto String(const std::string_view Value) -> bool
            {
                if (!Append("\""))
                {
                    return false;
                }
                for (const auto Character : Value)
                {
                    switch (Character)
                    {
                    case '"':
                        if (!Append("\\\""))
                        {
                            return false;
                        }
                        break;
                    case '\\':
                        if (!Append("\\\\"))
                        {
                            return false;
                        }
                        break;
                    case '\b':
                        if (!Append("\\b"))
                        {
                            return false;
                        }
                        break;
                    case '\f':
                        if (!Append("\\f"))
                        {
                            return false;
                        }
                        break;
                    case '\n':
                        if (!Append("\\n"))
                        {
                            return false;
                        }
                        break;
                    case '\r':
                        if (!Append("\\r"))
                        {
                            return false;
                        }
                        break;
                    case '\t':
                        if (!Append("\\t"))
                        {
                            return false;
                        }
                        break;
                    default:
                        if (static_cast<unsigned char>(Character) < 0x20U)
                        {
                            constexpr std::array<char, 16> Hex{
                                '0', '1', '2', '3', '4', '5', '6', '7',
                                '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
                            std::array<char, 7> Escaped{'\\', 'u', '0', '0', '0', '0', '0'};
                            const auto Byte = static_cast<unsigned char>(Character);
                            Escaped[4] = Hex[(Byte >> 4U) & 0x0fU];
                            Escaped[5] = Hex[Byte & 0x0fU];
                            if (!Append(std::string_view(Escaped.data(), Escaped.size())))
                            {
                                return false;
                            }
                        }
                        else if (!Append(std::string_view(&Character, 1)))
                        {
                            return false;
                        }
                        break;
                    }
                }
                return Append("\"");
            }

            [[nodiscard]] auto Key(const std::string_view Name) -> bool
            {
                return String(Name) && Append(":");
            }

            [[nodiscard]] auto Unsigned(const std::uint64_t Value) -> bool
            {
                std::array<char, 32> Buffer{};
                const auto [End, Error] = std::to_chars(Buffer.data(), Buffer.data() + Buffer.size(), Value);
                if (Error != std::errc{})
                {
                    Failed_ = true;
                    return false;
                }
                return Append(std::string_view(Buffer.data(), static_cast<std::size_t>(End - Buffer.data())));
            }

            [[nodiscard]] auto Boolean(const bool Value) -> bool
            {
                return Append(Value ? "true" : "false");
            }

            [[nodiscard]] auto Null() -> bool
            {
                return Append("null");
            }

            [[nodiscard]] auto Good() const noexcept -> bool
            {
                return !Failed_;
            }

            [[nodiscard]] auto Take() && -> std::string
            {
                return std::move(Value_);
            }

        private:
            std::string Value_;
            std::size_t Limit_;
            bool Failed_{false};
        };

        [[nodiscard]] auto AppendComma(JsonWriter &Writer, bool &First) -> bool
        {
            if (!First && !Writer.Append(","))
            {
                return false;
            }
            First = false;
            return true;
        }

        template <typename Id>
        [[nodiscard]] auto AppendId(JsonWriter &Writer, const Id Value) -> bool
        {
            return Writer.Unsigned(Value.Value());
        }

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
            case QueryStatus::Failed:
                return "failed";
            case QueryStatus::Invalid:
                return "invalid";
            }
            return "invalid";
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
            case 404:
                return "Not Found";
            case 405:
                return "Method Not Allowed";
            case 413:
                return "Payload Too Large";
            case 500:
                return "Internal Server Error";
            case 503:
                return "Service Unavailable";
            default:
                return "Internal Server Error";
            }
        }

        [[nodiscard]] auto StatusFor(const QueryStatus Status) noexcept -> int
        {
            switch (Status)
            {
            case QueryStatus::Ok:
                return 200;
            case QueryStatus::Unavailable:
                return 503;
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
            }
            return 500;
        }

        [[nodiscard]] auto AppendHealth(JsonWriter &Writer, const HealthSnapshot &Value) -> bool
        {
            return Writer.Append("{") && Writer.Key("status") && Writer.String(HealthStatusName(Value.Status)) &&
                   Writer.Append(",") && Writer.Key("checked_at") && Writer.Unsigned(Value.CheckedAt) &&
                   Writer.Append(",") && Writer.Key("active") && Writer.Unsigned(Value.Active) &&
                   Writer.Append(",") && Writer.Key("errors") && Writer.Unsigned(Value.Errors) &&
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
                   Writer.Boolean(Value.QuicProtocolReady) &&
                   Writer.Append("}");
        }

        [[nodiscard]] auto AppendTraffic(JsonWriter &Writer, const Preview::Statistics::TrafficValue &Value)
            -> bool
        {
            return Writer.Append("{") && Writer.Key("up_bytes") && Writer.Unsigned(Value.UpBytes) &&
                   Writer.Append(",") && Writer.Key("down_bytes") && Writer.Unsigned(Value.DownBytes) &&
                   Writer.Append(",") && Writer.Key("events") && Writer.Unsigned(Value.Events) &&
                   Writer.Append(",") && Writer.Key("errors") && Writer.Unsigned(Value.Errors) &&
                   Writer.Append("}");
        }

        [[nodiscard]] auto AppendGeneration(JsonWriter &Writer, const GenerationSnapshot &Value) -> bool
        {
            return Writer.Append("{") && Writer.Key("id") && AppendId(Writer, Value.Id) &&
                   Writer.Append(",") && Writer.Key("created_at") && Writer.Unsigned(Value.CreatedAt) &&
                   Writer.Append(",") && Writer.Key("active") && Writer.Boolean(Value.Active) &&
                   Writer.Append(",") && Writer.Key("retiring") && Writer.Boolean(Value.Retiring) &&
                   Writer.Append(",") && Writer.Key("health") && AppendHealth(Writer, Value.Health) &&
                   Writer.Append("}");
        }

        [[nodiscard]] auto AppendWorker(JsonWriter &Writer, const WorkerSnapshot &Value) -> bool
        {
            return Writer.Append("{") && Writer.Key("process") && AppendId(Writer, Value.Process) &&
                   Writer.Append(",") && Writer.Key("id") && AppendId(Writer, Value.Id) &&
                   Writer.Append(",") && Writer.Key("generation") && AppendId(Writer, Value.Generation) &&
                   Writer.Append(",") && Writer.Key("health") && AppendHealth(Writer, Value.Health) &&
                   Writer.Append(",") && Writer.Key("traffic") && AppendTraffic(Writer, Value.Traffic) &&
                   Writer.Append(",") && Writer.Key("running") && Writer.Boolean(Value.Running) &&
                   Writer.Append(",") && Writer.Key("accepting") && Writer.Boolean(Value.Accepting) &&
                   Writer.Append(",") && Writer.Key("active_tasks") && Writer.Unsigned(Value.ActiveTasks) &&
                   Writer.Append(",") && Writer.Key("dropped_events") && Writer.Unsigned(Value.DroppedEvents) &&
                   Writer.Append("}");
        }

        [[nodiscard]] auto AppendAccount(JsonWriter &Writer, const AccountSnapshot &Value) -> bool
        {
            return Writer.Append("{") && Writer.Key("id") && AppendId(Writer, Value.Id) &&
                   Writer.Append(",") && Writer.Key("generation") && AppendId(Writer, Value.Generation) &&
                   Writer.Append(",") && Writer.Key("traffic") && AppendTraffic(Writer, Value.Traffic) &&
                   Writer.Append(",") && Writer.Key("active_sessions") &&
                   Writer.Unsigned(Value.ActiveSessions) && Writer.Append(",") && Writer.Key("label") &&
                   Writer.String(Value.Label) && Writer.Append(",") && Writer.Key("enabled") &&
                   Writer.Boolean(Value.Enabled) && Writer.Append("}");
        }

        [[nodiscard]] auto AppendSession(JsonWriter &Writer, const SessionSnapshot &Value) -> bool
        {
            return Writer.Append("{") && Writer.Key("id") && AppendId(Writer, Value.Id) &&
                   Writer.Append(",") && Writer.Key("process") && AppendId(Writer, Value.Process) &&
                   Writer.Append(",") && Writer.Key("worker") && AppendId(Writer, Value.Worker) &&
                   Writer.Append(",") && Writer.Key("account") && AppendId(Writer, Value.Account) &&
                   Writer.Append(",") && Writer.Key("generation") && AppendId(Writer, Value.Generation) &&
                   Writer.Append(",") && Writer.Key("traffic") && AppendTraffic(Writer, Value.Traffic) &&
                   Writer.Append(",") && Writer.Key("started_at") && Writer.Unsigned(Value.StartedAt) &&
                   Writer.Append(",") && Writer.Key("protocol") && Writer.String(Value.Protocol) &&
                   Writer.Append(",") && Writer.Key("target") && Writer.String(Value.Target) &&
                   Writer.Append(",") && Writer.Key("active") && Writer.Boolean(Value.Active) &&
                   Writer.Append(",") && Writer.Key("draining") && Writer.Boolean(Value.Draining) &&
                   Writer.Append("}");
        }

        [[nodiscard]] auto AppendStream(JsonWriter &Writer, const StreamSnapshot &Value) -> bool
        {
            return Writer.Append("{") && Writer.Key("id") && AppendId(Writer, Value.Id) &&
                   Writer.Append(",") && Writer.Key("session") && AppendId(Writer, Value.Session) &&
                   Writer.Append(",") && Writer.Key("account") && AppendId(Writer, Value.Account) &&
                   Writer.Append(",") && Writer.Key("worker") && AppendId(Writer, Value.Worker) &&
                   Writer.Append(",") && Writer.Key("generation") && AppendId(Writer, Value.Generation) &&
                   Writer.Append(",") && Writer.Key("traffic") && AppendTraffic(Writer, Value.Traffic) &&
                   Writer.Append(",") && Writer.Key("protocol") && Writer.String(Value.Protocol) &&
                   Writer.Append(",") && Writer.Key("active") && Writer.Boolean(Value.Active) &&
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
            return Writer.Append("{") && Writer.Key("id") && AppendId(Writer, Value.Id) &&
                   Writer.Append(",") && Writer.Key("worker") && AppendId(Writer, Value.Worker) &&
                   Writer.Append(",") && Writer.Key("session") && AppendId(Writer, Value.Session) &&
                   Writer.Append(",") && Writer.Key("generation") && AppendId(Writer, Value.Generation) &&
                   Writer.Append(",") && Writer.Key("status") && Writer.String(TaskStatusName(Value.Status)) &&
                   Writer.Append(",") && Writer.Key("started_at") && Writer.Unsigned(Value.StartedAt) &&
                   Writer.Append(",") && Writer.Key("completed_at") && Writer.Unsigned(Value.CompletedAt) &&
                   Writer.Append(",") && Writer.Key("cancel_requested") &&
                   Writer.Boolean(Value.CancelRequested) && Writer.Append(",") && Writer.Key("drain_blocked") &&
                   Writer.Boolean(Value.DrainBlocked) && Writer.Append("}");
        }

        [[nodiscard]] auto AppendEvent(JsonWriter &Writer,
                                       const EventSnapshot &Value,
                                       const bool IncludeDetails) -> bool
        {
            if (!Writer.Append("{") || !Writer.Key("sequence") || !Writer.Unsigned(Value.Sequence) ||
                !Writer.Append(",") || !Writer.Key("timestamp") || !Writer.Unsigned(Value.Timestamp) ||
                !Writer.Append(",") || !Writer.Key("correlation") || !AppendId(Writer, Value.Correlation) ||
                !Writer.Append(",") || !Writer.Key("generation") || !AppendId(Writer, Value.Generation) ||
                !Writer.Append(",") || !Writer.Key("process") || !AppendId(Writer, Value.Process) ||
                !Writer.Append(",") || !Writer.Key("worker") || !AppendId(Writer, Value.Worker) ||
                !Writer.Append(",") || !Writer.Key("account") || !AppendId(Writer, Value.Account) ||
                !Writer.Append(",") || !Writer.Key("session") || !AppendId(Writer, Value.Session) ||
                !Writer.Append(",") || !Writer.Key("stream") || !AppendId(Writer, Value.Stream) ||
                !Writer.Append(",") || !Writer.Key("task") || !AppendId(Writer, Value.Task) ||
                !Writer.Append(",") || !Writer.Key("terminal") || !Writer.Boolean(Value.Terminal))
            {
                return false;
            }
            if (IncludeDetails &&
                (!Writer.Append(",") || !Writer.Key("detail") || !Writer.String(Value.Detail)))
            {
                return false;
            }
            return Writer.Append("}");
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
            return Writer.Append("],\"next_cursor\":") && Writer.Unsigned(ValuePage.NextCursor) &&
                   Writer.Append(",\"has_more\":") && Writer.Boolean(ValuePage.HasMore) &&
                   Writer.Append("}");
        }

        [[nodiscard]] auto AppendQueryValue(JsonWriter &Writer,
                                            const QueryPayload &Value,
                                            const bool IncludeDetails) -> bool
        {
            return std::visit(
                [&Writer, IncludeDetails](const auto &Payload) -> bool
                {
                    using PayloadType = std::remove_cvref_t<decltype(Payload)>;
                    if constexpr (std::is_same_v<PayloadType, std::monostate>)
                    {
                        return Writer.Null();
                    }
                    else if constexpr (std::is_same_v<PayloadType, HealthSnapshot>)
                    {
                        return AppendHealth(Writer, Payload);
                    }
                    else if constexpr (std::is_same_v<PayloadType, GenerationSnapshot>)
                    {
                        return AppendGeneration(Writer, Payload);
                    }
                    else if constexpr (std::is_same_v<PayloadType, Page<WorkerSnapshot>>)
                    {
                        return AppendPage(Writer, Payload, AppendWorker);
                    }
                    else if constexpr (std::is_same_v<PayloadType, Page<AccountSnapshot>>)
                    {
                        return AppendPage(Writer, Payload, AppendAccount);
                    }
                    else if constexpr (std::is_same_v<PayloadType, Page<SessionSnapshot>>)
                    {
                        return AppendPage(Writer, Payload, AppendSession);
                    }
                    else if constexpr (std::is_same_v<PayloadType, Page<StreamSnapshot>>)
                    {
                        return AppendPage(Writer, Payload, AppendStream);
                    }
                    else if constexpr (std::is_same_v<PayloadType, Page<TaskSnapshot>>)
                    {
                        return AppendPage(Writer, Payload, AppendTask);
                    }
                    else
                    {
                        return AppendPage(
                            Writer,
                            Payload,
                            [IncludeDetails](JsonWriter &EventWriter, const EventSnapshot &EventValue)
                            { return AppendEvent(EventWriter, EventValue, IncludeDetails); });
                    }
                },
                Value);
        }

        [[nodiscard]] auto SerializeQuery(const QueryResult &Result,
                                          const bool IncludeDetails) -> std::optional<std::string>
        {
            JsonWriter Writer;
            if (!Writer.Append("{") || !Writer.Key("correlation") ||
                !AppendId(Writer, Result.Correlation) || !Writer.Append(",") || Writer.Key("status") == false ||
                !Writer.String(QueryStatusName(Result.Status)) || !Writer.Append(",") ||
                !Writer.Key("value") || !AppendQueryValue(Writer, Result.Value, IncludeDetails) ||
                !Writer.Append(",") ||
                !Writer.Key("message") || !Writer.String(Result.Message) || !Writer.Append("}") ||
                !Writer.Good())
            {
                return std::nullopt;
            }
            return std::move(Writer).Take();
        }

        [[nodiscard]] auto SerializeCommand(const CommandResult &Result) -> std::optional<std::string>
        {
            JsonWriter Writer;
            if (!Writer.Append("{") || !Writer.Key("correlation") ||
                !AppendId(Writer, Result.Correlation) || !Writer.Append(",") || !Writer.Key("status") ||
                !Writer.String(CommandStatusName(Result.Status)) || !Writer.Append(",") ||
                !Writer.Key("operation") || !AppendId(Writer, Result.Operation) ||
                !Writer.Append(",") || !Writer.Key("generation") || AppendId(Writer, Result.Generation) == false ||
                !Writer.Append(",") || !Writer.Key("worker") || !AppendId(Writer, Result.Worker) ||
                !Writer.Append(",") || !Writer.Key("account") || !AppendId(Writer, Result.Account) ||
                !Writer.Append(",") || !Writer.Key("session") || !AppendId(Writer, Result.Session) ||
                !Writer.Append(",") || !Writer.Key("stream") || !AppendId(Writer, Result.Stream) ||
                !Writer.Append(",") || !Writer.Key("task") || !AppendId(Writer, Result.Task) ||
                !Writer.Append(",") || !Writer.Key("message") || !Writer.String(Result.Message) ||
                !Writer.Append("}") || !Writer.Good())
            {
                return std::nullopt;
            }
            return std::move(Writer).Take();
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

        [[nodiscard]] auto MakeErrorBody(const std::string_view Message,
                                         const Preview::RequestId Correlation = {})
            -> std::optional<std::string>
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

        [[nodiscard]] auto MakeErrorResponse(const int Status,
                                             const std::string_view Message,
                                             const Preview::RequestId Correlation = {}) -> std::string
        {
            auto Body = MakeErrorBody(Message, Correlation);
            return MakeResponse(Status, Body ? std::move(*Body) : "{\"error\":\"internal\"}");
        }

        struct QueryParameter final
        {
            std::string_view Name{};
            std::string_view Value{};
        };

        struct TargetParts final
        {
            std::array<std::string_view, 5> Segments{};
            std::size_t SegmentCount{0};
            std::array<QueryParameter, 16> Parameters{};
            std::size_t ParameterCount{0};
        };

        [[nodiscard]] auto FindParameter(const TargetParts &Parts, const std::string_view Name)
            -> std::optional<std::string_view>
        {
            for (std::size_t Index = 0; Index < Parts.ParameterCount; ++Index)
            {
                if (Parts.Parameters[Index].Name == Name)
                {
                    return Parts.Parameters[Index].Value;
                }
            }
            return std::nullopt;
        }

        [[nodiscard]] auto ParseTarget(const std::string_view Target, TargetParts &Parts) -> bool
        {
            Parts = {};
            const auto QueryStart = Target.find('?');
            const auto Path = Target.substr(0, QueryStart);
            if (Path.empty() || Path.front() != '/')
            {
                return false;
            }

            std::size_t SegmentStart = 1;
            while (SegmentStart <= Path.size())
            {
                const auto SegmentEnd = Path.find('/', SegmentStart);
                const auto End = SegmentEnd == std::string_view::npos ? Path.size() : SegmentEnd;
                if (End == SegmentStart || Parts.SegmentCount >= Parts.Segments.size())
                {
                    return false;
                }
                Parts.Segments[Parts.SegmentCount++] = Path.substr(SegmentStart, End - SegmentStart);
                if (SegmentEnd == std::string_view::npos)
                {
                    break;
                }
                SegmentStart = SegmentEnd + 1U;
            }

            if (QueryStart == std::string_view::npos)
            {
                return true;
            }
            const auto Query = Target.substr(QueryStart + 1U);
            if (Query.empty())
            {
                return false;
            }
            std::size_t ParameterStart = 0;
            while (ParameterStart <= Query.size())
            {
                const auto ParameterEnd = Query.find('&', ParameterStart);
                const auto End = ParameterEnd == std::string_view::npos ? Query.size() : ParameterEnd;
                const auto Parameter = Query.substr(ParameterStart, End - ParameterStart);
                const auto Equal = Parameter.find('=');
                if (Equal == std::string_view::npos || Equal == 0U ||
                    Parts.ParameterCount >= Parts.Parameters.size())
                {
                    return false;
                }
                const auto Name = Parameter.substr(0, Equal);
                const auto Value = Parameter.substr(Equal + 1U);
                if (Value.empty() || FindParameter(Parts, Name))
                {
                    return false;
                }
                Parts.Parameters[Parts.ParameterCount++] = QueryParameter{Name, Value};
                if (ParameterEnd == std::string_view::npos)
                {
                    break;
                }
                ParameterStart = ParameterEnd + 1U;
            }
            return true;
        }

        template <typename Value>
        [[nodiscard]] auto ReadParameter(const TargetParts &Parts,
                                         const std::string_view Name,
                                         const Value Default,
                                         Value &Result) -> bool
        {
            const auto Parameter = FindParameter(Parts, Name);
            if (!Parameter)
            {
                Result = Default;
                return true;
            }
            return ParseUnsigned(*Parameter, Result);
        }

        [[nodiscard]] auto ReadBooleanParameter(const TargetParts &Parts,
                                                const std::string_view Name,
                                                const bool Default,
                                                bool &Result) -> bool
        {
            const auto Parameter = FindParameter(Parts, Name);
            if (!Parameter)
            {
                Result = Default;
                return true;
            }
            return ParseBoolean(*Parameter, Result);
        }

        [[nodiscard]] auto ReadCorrelation(const HttpRequest &Request,
                                           const TargetParts &Parts,
                                           std::atomic<std::uint64_t> &NextCorrelation,
                                           Preview::RequestId &Result) -> bool
        {
            auto Correlation = Request.Correlation;
            if (Correlation.empty())
            {
                const auto QueryCorrelation = FindParameter(Parts, "correlation");
                Correlation = QueryCorrelation ? *QueryCorrelation : std::string_view{};
            }
            if (Correlation.empty())
            {
                const auto Next = NextCorrelation.fetch_add(1U, std::memory_order_relaxed);
                Result = Preview::RequestId{Next == 0U ? NextCorrelation.fetch_add(1U) : Next};
                return static_cast<bool>(Result);
            }
            std::uint64_t Value{};
            if (!ParseUnsigned(Correlation, Value) || Value == 0U)
            {
                return false;
            }
            Result = Preview::RequestId{Value};
            return true;
        }

        struct RouteFailure final
        {
            int Status{400};
            std::string_view Message{"bad_request"};
        };

        struct OperationStatusRoute final
        {
            OperationId Operation{};
            Preview::RequestId Correlation{};
        };

        using RouteValue = std::variant<Query, Command, OperationStatusRoute>;

        [[nodiscard]] auto MakePage(const TargetParts &Parts, PageRequest &Page) -> bool
        {
            std::uint64_t Cursor{};
            std::uint64_t Limit{};
            if (!ReadParameter(Parts, "cursor", std::uint64_t{0}, Cursor) ||
                !ReadParameter(Parts, "limit", std::uint64_t{50}, Limit) ||
                Limit > std::numeric_limits<std::size_t>::max())
            {
                return false;
            }
            Page.Cursor = Cursor;
            Page.Limit = static_cast<std::size_t>(Limit);
            return true;
        }

        [[nodiscard]] auto MakeGetRoute(const HttpRequest &Request,
                                        const TargetParts &Parts,
                                        const Preview::RequestId Correlation)
            -> std::expected<RouteValue, RouteFailure>
        {
            if (Parts.SegmentCount == 3U && Parts.Segments[0] == "Operations" &&
                (Parts.Segments[1] == "Status" || Parts.Segments[1] == "Operation" ||
                 Parts.Segments[1] == "Operations"))
            {
                std::uint64_t Value{};
                if (!ParseUnsigned(Parts.Segments[2], Value) || Value == 0U)
                {
                    return std::unexpected(RouteFailure{400, "bad_operation_id"});
                }
                return RouteValue{OperationStatusRoute{OperationId{Value}, Correlation}};
            }
            if (Parts.SegmentCount != 2U || Parts.Segments[0] != "Operations")
            {
                return std::unexpected(RouteFailure{404, "route_not_found"});
            }
            if (Parts.Segments[1] == "Health")
            {
                if (Parts.ParameterCount != 0U && FindParameter(Parts, "correlation") == std::nullopt)
                {
                    return std::unexpected(RouteFailure{400, "bad_query"});
                }
                return RouteValue{Query{HealthQuery{Correlation}}};
            }

            if (Parts.Segments[1] == "Workers")
            {
                WorkerQuery Value;
                Value.Correlation = Correlation;
                if (!MakePage(Parts, Value.Page))
                {
                    return std::unexpected(RouteFailure{400, "bad_page"});
                }
                std::uint64_t Id{};
                if (!ReadParameter(Parts, "id", std::uint64_t{0}, Id))
                {
                    return std::unexpected(RouteFailure{400, "bad_id"});
                }
                Value.Id = Preview::WorkerId{Id};
                return RouteValue{Query{std::move(Value)}};
            }
            if (Parts.Segments[1] == "Accounts")
            {
                AccountQuery Value;
                Value.Correlation = Correlation;
                if (!MakePage(Parts, Value.Page))
                {
                    return std::unexpected(RouteFailure{400, "bad_page"});
                }
                std::uint64_t Id{};
                if (!ReadParameter(Parts, "id", std::uint64_t{0}, Id))
                {
                    return std::unexpected(RouteFailure{400, "bad_id"});
                }
                Value.Id = Preview::AccountId{Id};
                return RouteValue{Query{std::move(Value)}};
            }
            if (Parts.Segments[1] == "Sessions")
            {
                SessionQuery Value;
                Value.Correlation = Correlation;
                if (!MakePage(Parts, Value.Page))
                {
                    return std::unexpected(RouteFailure{400, "bad_page"});
                }
                std::uint64_t Id{};
                if (!ReadParameter(Parts, "id", std::uint64_t{0}, Id))
                {
                    return std::unexpected(RouteFailure{400, "bad_id"});
                }
                Value.Id = Preview::SessionId{Id};
                return RouteValue{Query{std::move(Value)}};
            }
            if (Parts.Segments[1] == "Events")
            {
                EventQuery Value;
                Value.Correlation = Correlation;
                if (!MakePage(Parts, Value.Page) ||
                    !ReadBooleanParameter(Parts, "include_details", true, Value.IncludeDetails))
                {
                    return std::unexpected(RouteFailure{400, "bad_query"});
                }
                return RouteValue{Query{std::move(Value)}};
            }
            (void)Request;
            return std::unexpected(RouteFailure{404, "route_not_found"});
        }

        [[nodiscard]] auto MakePostRoute(const HttpRequest &Request,
                                         const TargetParts &Parts,
                                         const Preview::RequestId Correlation)
            -> std::expected<RouteValue, RouteFailure>
        {
            if (Parts.SegmentCount < 2U || Parts.Segments[0] != "Operations")
            {
                return std::unexpected(RouteFailure{404, "route_not_found"});
            }
            if (Parts.SegmentCount == 2U && Parts.Segments[1] == "Drain")
            {
                DrainCommand Value;
                Value.Correlation = Correlation;
                std::uint64_t Worker{};
                if (!ReadParameter(Parts, "worker", std::uint64_t{0}, Worker) ||
                    !ReadBooleanParameter(Parts, "stop_accepting", true, Value.StopAccepting) ||
                    !ReadBooleanParameter(Parts, "force", false, Value.Force))
                {
                    return std::unexpected(RouteFailure{400, "bad_command"});
                }
                Value.Worker = Preview::WorkerId{Worker};
                return RouteValue{Command{std::move(Value)}};
            }
            if (Parts.SegmentCount == 2U && Parts.Segments[1] == "Reload")
            {
                ReloadCommand Value;
                Value.Correlation = Correlation;
                std::uint64_t Current{};
                std::uint64_t Target{};
                if (!ReadParameter(Parts, "current_generation", std::uint64_t{0}, Current) ||
                    !ReadParameter(Parts, "target_generation", std::uint64_t{0}, Target) ||
                    !ReadBooleanParameter(Parts, "validate_only", false, Value.ValidateOnly))
                {
                    return std::unexpected(RouteFailure{400, "bad_command"});
                }
                Value.CurrentGeneration = Preview::GenerationId{Current};
                Value.TargetGeneration = Preview::GenerationId{Target};
                return RouteValue{Command{std::move(Value)}};
            }
            if (Parts.SegmentCount == 4U && Parts.Segments[1] == "Accounts" &&
                Parts.Segments[3] == "Revoke")
            {
                RevokeCommand Value;
                Value.Correlation = Correlation;
                std::uint64_t Account{};
                if (!ParseUnsigned(Parts.Segments[2], Account) || Account == 0U ||
                    !ReadBooleanParameter(Parts, "close_sessions", true, Value.CloseSessions))
                {
                    return std::unexpected(RouteFailure{400, "bad_account_id"});
                }
                Value.Account = Preview::AccountId{Account};
                return RouteValue{Command{std::move(Value)}};
            }
            if (Parts.SegmentCount == 4U && Parts.Segments[1] == "Sessions" &&
                Parts.Segments[3] == "Cancel")
            {
                CancelCommand Value;
                Value.Correlation = Correlation;
                std::uint64_t Session{};
                std::uint64_t Stream{};
                std::uint64_t Task{};
                if (!ParseUnsigned(Parts.Segments[2], Session) || Session == 0U ||
                    !ReadParameter(Parts, "stream", std::uint64_t{0}, Stream) ||
                    !ReadParameter(Parts, "task", std::uint64_t{0}, Task))
                {
                    return std::unexpected(RouteFailure{400, "bad_session_id"});
                }
                Value.Session = Preview::SessionId{Session};
                Value.Stream = Preview::StreamId{Stream};
                Value.Task = Preview::TaskId{Task};
                return RouteValue{Command{std::move(Value)}};
            }
            if (Parts.SegmentCount == 4U && Parts.Segments[1] == "Streams" &&
                Parts.Segments[3] == "Reset")
            {
                CancelCommand Value;
                Value.Correlation = Correlation;
                std::uint64_t Stream{};
                if (!ParseUnsigned(Parts.Segments[2], Stream) || Stream == 0U)
                {
                    return std::unexpected(RouteFailure{400, "bad_stream_id"});
                }
                Value.Stream = Preview::StreamId{Stream};
                return RouteValue{Command{std::move(Value)}};
            }
            (void)Request;
            return std::unexpected(RouteFailure{404, "route_not_found"});
        }

        [[nodiscard]] auto BuildRoute(const HttpRequest &Request,
                                      std::atomic<std::uint64_t> &NextCorrelation)
            -> std::expected<RouteValue, RouteFailure>
        {
            TargetParts Parts;
            if (!ParseTarget(Request.Target, Parts))
            {
                return std::unexpected(RouteFailure{400, "bad_target"});
            }
            Preview::RequestId Correlation;
            if (!ReadCorrelation(Request, Parts, NextCorrelation, Correlation))
            {
                return std::unexpected(RouteFailure{400, "bad_correlation"});
            }
            if (Request.Method == "GET")
            {
                return MakeGetRoute(Request, Parts, Correlation);
            }
            if (Request.Method == "POST")
            {
                return MakePostRoute(Request, Parts, Correlation);
            }
            return std::unexpected(RouteFailure{405, "method_not_allowed"});
        }

        template <typename StateValue>
        [[nodiscard]] auto Dispatch(const std::shared_ptr<StateValue> &State,
                                    const HttpRequest &Request) -> Net::awaitable<std::string>
        {
            const auto Route = BuildRoute(Request, State->NextCorrelation);
            if (!Route)
            {
                co_return MakeErrorResponse(Route.error().Status, Route.error().Message);
            }
            if (const auto *QueryValue = std::get_if<Query>(&*Route))
            {
                const auto Result = co_await State->OperationsRouter.QueryAsync(*QueryValue);
                const auto IncludeDetails = std::visit(
                    [](const auto &Value)
                    {
                        using ValueType = std::remove_cvref_t<decltype(Value)>;
                        if constexpr (std::is_same_v<ValueType, EventQuery>)
                        {
                            return Value.IncludeDetails;
                        }
                        else
                        {
                            return true;
                        }
                    },
                    QueryValue->Value);
                const auto Body = SerializeQuery(Result, IncludeDetails);
                if (!Body)
                {
                    co_return MakeErrorResponse(500, "response_too_large", Result.Correlation);
                }
                co_return MakeResponse(StatusFor(Result.Status), std::move(*Body));
            }
            if (const auto *StatusValue = std::get_if<OperationStatusRoute>(&*Route))
            {
                const auto Result = co_await State->OperationsRouter.StatusAsync(
                    StatusValue->Operation, StatusValue->Correlation);
                const auto Body = SerializeCommand(Result);
                if (!Body)
                {
                    co_return MakeErrorResponse(500, "response_too_large", Result.Correlation);
                }
                co_return MakeResponse(StatusFor(Result.Status), std::move(*Body));
            }
            const auto Result = co_await State->OperationsRouter.ExecuteAsync(std::get<Command>(*Route));
            const auto Body = SerializeCommand(Result);
            if (!Body)
            {
                co_return MakeErrorResponse(500, "response_too_large", Result.Correlation);
            }
            co_return MakeResponse(StatusFor(Result.Status), std::move(*Body));
        }

        template <typename StateValue>
        auto CloseOnExecutor(const std::shared_ptr<StateValue> &State) noexcept -> void
        {
            boost::system::error_code Error;
            if (State->Acceptor.is_open())
            {
                State->Acceptor.cancel(Error);
                State->Acceptor.close(Error);
            }
            for (const auto &Socket : State->ActiveSockets)
            {
                if (!Socket)
                {
                    continue;
                }
                Socket->cancel(Error);
                Socket->shutdown(Tcp::socket::shutdown_both, Error);
                Socket->close(Error);
            }
            State->Running.store(false, std::memory_order_release);
        }

        template <typename StateValue>
        auto FinishConnection(const std::shared_ptr<StateValue> &State,
                              const std::shared_ptr<Tcp::socket> &Socket) noexcept -> void
        {
            const auto It = std::find(State->ActiveSockets.begin(), State->ActiveSockets.end(), Socket);
            if (It != State->ActiveSockets.end())
            {
                State->ActiveSockets.erase(It);
            }
            if (State->ActiveConnections.fetch_sub(1U, std::memory_order_acq_rel) == 1U &&
                State->Draining.load(std::memory_order_acquire))
            {
                State->Drained.store(true, std::memory_order_release);
                (void)State->DrainTimer.cancel();
            }
        }

        template <typename StateValue>
        class ConnectionGuard final
        {
        public:
            ConnectionGuard(std::shared_ptr<StateValue> StateValueObject,
                            std::shared_ptr<Tcp::socket> SocketValue)
                : State_(std::move(StateValueObject)), Socket_(std::move(SocketValue))
            {
            }

            ~ConnectionGuard()
            {
                FinishConnection(State_, Socket_);
            }

            ConnectionGuard(const ConnectionGuard &) = delete;
            auto operator=(const ConnectionGuard &) -> ConnectionGuard & = delete;

        private:
            std::shared_ptr<StateValue> State_;
            std::shared_ptr<Tcp::socket> Socket_;
        };

        [[nodiscard]] auto StartReadDeadline(const std::shared_ptr<Tcp::socket> &Socket,
                                             const std::chrono::milliseconds Deadline)
            -> std::shared_ptr<Net::steady_timer>
        {
            const auto Timer = std::make_shared<Net::steady_timer>(Socket->get_executor());
            Timer->expires_after(Deadline);
            Net::co_spawn(
                Socket->get_executor(),
                [Socket, Timer]() -> Net::awaitable<void>
                {
                    boost::system::error_code Error;
                    co_await Timer->async_wait(Net::redirect_error(Net::use_awaitable, Error));
                    if (!Error)
                    {
                        Socket->cancel(Error);
                    }
                },
                Net::detached);
            return Timer;
        }

        auto CancelReadDeadline(const std::shared_ptr<Net::steady_timer> &Timer) noexcept -> void
        {
            if (Timer)
            {
                Timer->cancel();
            }
        }

        template <typename StateValue>
        [[nodiscard]] auto Serve(std::shared_ptr<StateValue> State,
                                 std::shared_ptr<Tcp::socket> Socket)
            -> Net::awaitable<void>
        {
            ConnectionGuard Guard(State, Socket);
            const auto ReadDeadline = StartReadDeadline(Socket, State->ReadDeadline);
            std::array<char, 4096> Chunk{};
            std::string RequestBytes;
            RequestBytes.reserve(MaxRequestBytes);
            HttpRequest Request;
            ParseStatus Status = ParseStatus::Incomplete;
            while (Status == ParseStatus::Incomplete)
            {
                boost::system::error_code Error;
                const auto Count = co_await Socket->async_read_some(
                    Net::buffer(Chunk), Net::redirect_error(Net::use_awaitable, Error));
                if (Error || Count == 0U)
                {
                    CancelReadDeadline(ReadDeadline);
                    co_return;
                }
                if (Count > MaxRequestBytes - std::min(RequestBytes.size(), MaxRequestBytes))
                {
                    const auto Response = MakeErrorResponse(413, "request_too_large");
                    CancelReadDeadline(ReadDeadline);
                    co_await Net::async_write(*Socket, Net::buffer(Response),
                                              Net::redirect_error(Net::use_awaitable, Error));
                    co_return;
                }
                RequestBytes.append(Chunk.data(), Count);
                Status = ParseRequest(RequestBytes, Request);
            }

            CancelReadDeadline(ReadDeadline);
            boost::system::error_code Error;
            std::string Response;
            if (Status == ParseStatus::Oversized)
            {
                Response = MakeErrorResponse(413, "request_too_large");
            }
            else if (Status == ParseStatus::Malformed)
            {
                Response = MakeErrorResponse(400, "bad_request");
            }
            else
            {
                try
                {
                    Response = co_await Dispatch(State, Request);
                }
                catch (...)
                {
                    Response = MakeErrorResponse(500, "handler_failed");
                }
            }
            co_await Net::async_write(*Socket, Net::buffer(Response),
                                      Net::redirect_error(Net::use_awaitable, Error));
            boost::system::error_code CloseError;
            Socket->shutdown(Tcp::socket::shutdown_both, CloseError);
            Socket->close(CloseError);
        }

        template <typename StateValue>
        [[nodiscard]] auto AcceptLoop(std::shared_ptr<StateValue> State) -> Net::awaitable<void>
        {
            while (!State->StopRequested.load(std::memory_order_acquire))
            {
                boost::system::error_code Error;
                const auto Socket = std::make_shared<Tcp::socket>(State->Executor);
                co_await State->Acceptor.async_accept(
                    *Socket, Net::redirect_error(Net::use_awaitable, Error));
                if (Error)
                {
                    co_return;
                }
                if (State->StopRequested.load(std::memory_order_acquire))
                {
                    Socket->close(Error);
                    co_return;
                }
                State->ActiveSockets.push_back(Socket);
                State->ActiveConnections.fetch_add(1U, std::memory_order_acq_rel);
                Net::co_spawn(State->Executor, Serve(State, Socket), Net::detached);
            }
        }

        template <typename StateValue>
        [[nodiscard]] auto StartOnExecutor(const std::shared_ptr<StateValue> &State)
            -> HttpServer::StartResult
        {
            if (State->Started.load(std::memory_order_acquire) ||
                State->StopRequested.load(std::memory_order_acquire) ||
                State->Draining.load(std::memory_order_acquire) ||
                State->Drained.load(std::memory_order_acquire))
            {
                return std::unexpected(
                    make_error_code(boost::system::errc::operation_canceled));
            }
            if (!State->BindEndpoint.address().is_loopback())
            {
                return std::unexpected(
                    make_error_code(boost::system::errc::permission_denied));
            }
            boost::system::error_code Error;
            State->Acceptor.open(State->BindEndpoint.protocol(), Error);
            if (!Error)
            {
                State->Acceptor.set_option(Tcp::acceptor::reuse_address(true), Error);
            }
            if (!Error)
            {
                State->Acceptor.bind(State->BindEndpoint, Error);
            }
            if (!Error)
            {
                State->Acceptor.listen(Net::socket_base::max_listen_connections, Error);
            }
            if (Error)
            {
                boost::system::error_code CloseError;
                State->Acceptor.close(CloseError);
                return std::unexpected(Error);
            }
            State->LocalEndpoint = State->Acceptor.local_endpoint(Error);
            if (Error)
            {
                boost::system::error_code CloseError;
                State->Acceptor.close(CloseError);
                return std::unexpected(Error);
            }
            State->Started.store(true, std::memory_order_release);
            State->Running.store(true, std::memory_order_release);
            Net::co_spawn(State->Executor, AcceptLoop(State), Net::detached);
            return State->LocalEndpoint;
        }

    } // namespace

    auto ParseRequest(const std::string_view Raw, HttpRequest &Request) -> ParseStatus
    {
        Request = {};
        if (Raw.size() > MaxRequestBytes)
        {
            return ParseStatus::Oversized;
        }
        const auto HeadersEnd = Raw.find("\r\n\r\n");
        if (HeadersEnd == std::string_view::npos)
        {
            return Raw.size() >= MaxRequestBytes ? ParseStatus::Oversized : ParseStatus::Incomplete;
        }
        if (HeadersEnd + 4U != Raw.size())
        {
            return ParseStatus::Malformed;
        }
        const auto LineEnd = Raw.find("\r\n");
        if (LineEnd == std::string_view::npos)
        {
            return ParseStatus::Malformed;
        }
        if (LineEnd > MaxRequestLineBytes)
        {
            return ParseStatus::Oversized;
        }
        const auto RequestLine = Raw.substr(0, LineEnd);
        const auto FirstSpace = RequestLine.find(' ');
        const auto SecondSpace = FirstSpace == std::string_view::npos
                                     ? std::string_view::npos
                                     : RequestLine.find(' ', FirstSpace + 1U);
        if (FirstSpace == std::string_view::npos || SecondSpace == std::string_view::npos ||
            FirstSpace == 0U || SecondSpace <= FirstSpace + 1U || SecondSpace >= LineEnd ||
            RequestLine.find(' ', SecondSpace + 1U) != std::string_view::npos)
        {
            return ParseStatus::Malformed;
        }
        Request.Method = Raw.substr(0, FirstSpace);
        Request.Target = Raw.substr(FirstSpace + 1U, SecondSpace - FirstSpace - 1U);
        const auto Version = Raw.substr(SecondSpace + 1U, LineEnd - SecondSpace - 1U);
        if ((Request.Method != "GET" && Request.Method != "POST") || Request.Target.empty() ||
            Version != "HTTP/1.1")
        {
            return ParseStatus::Malformed;
        }
        for (const auto Character : Request.Target)
        {
            if (static_cast<unsigned char>(Character) < 0x21U || Character == 0x7f)
            {
                return ParseStatus::Malformed;
            }
        }

        bool HostSeen = false;
        bool ContentLengthSeen = false;
        bool TransferEncodingSeen = false;
        bool CorrelationSeen = false;
        std::size_t HeaderCount = 0;
        const auto HeaderBegin = LineEnd + 2U;
        const auto HeaderBlock = Raw.substr(HeaderBegin, HeadersEnd - HeaderBegin);
        std::size_t Offset = 0;
        while (Offset < HeaderBlock.size())
        {
            const auto End = HeaderBlock.find("\r\n", Offset);
            const auto Line = HeaderBlock.substr(
                Offset, End == std::string_view::npos ? HeaderBlock.size() - Offset : End - Offset);
            if (Line.empty() || Line.size() > MaxRequestLineBytes || ++HeaderCount > MaxHeaderCount)
            {
                return Line.size() > MaxRequestLineBytes ? ParseStatus::Oversized
                                                          : ParseStatus::Malformed;
            }
            const auto Colon = Line.find(':');
            if (Colon == std::string_view::npos || Colon == 0U)
            {
                return ParseStatus::Malformed;
            }
            const auto Name = Line.substr(0, Colon);
            for (const auto Character : Name)
            {
                if (!IsTokenCharacter(Character))
                {
                    return ParseStatus::Malformed;
                }
            }
            const auto RawValue = Line.substr(Colon + 1U);
            for (const auto Character : RawValue)
            {
                if (!IsFieldValueCharacter(Character))
                {
                    return ParseStatus::Malformed;
                }
            }
            const auto Value = Trim(RawValue);
            if (EqualsInsensitive(Name, "host"))
            {
                if (HostSeen || Value.empty())
                {
                    return ParseStatus::Malformed;
                }
                HostSeen = true;
            }
            else if (EqualsInsensitive(Name, "content-length"))
            {
                if (ContentLengthSeen || !ParseUnsigned(Value, Request.ContentLength) ||
                    Request.ContentLength != 0U)
                {
                    return ParseStatus::Malformed;
                }
                ContentLengthSeen = true;
            }
            else if (EqualsInsensitive(Name, "transfer-encoding"))
            {
                TransferEncodingSeen = true;
            }
            else if (EqualsInsensitive(Name, "x-correlation-id") ||
                     EqualsInsensitive(Name, "correlation-id"))
            {
                if (CorrelationSeen || Value.empty())
                {
                    return ParseStatus::Malformed;
                }
                CorrelationSeen = true;
                Request.Correlation = Value;
            }
            if (End == std::string_view::npos)
            {
                break;
            }
            Offset = End + 2U;
        }
        if (!HostSeen || TransferEncodingSeen)
        {
            return ParseStatus::Malformed;
        }
        Request.HeaderEnd = HeadersEnd + 4U;
        return ParseStatus::Complete;
    }

    struct HttpServer::State final
    {
        State(Net::any_io_executor ExecutorValue,
              Endpoint EndpointValue,
              const Router &RouterValue,
              const std::chrono::milliseconds ReadDeadlineValue)
            : Executor(std::move(ExecutorValue)),
              BindEndpoint(EndpointValue),
              OperationsRouter(RouterValue),
              ReadDeadline(ReadDeadlineValue),
              Acceptor(Executor),
              DrainTimer(Executor)
        {
        }

        Net::any_io_executor Executor;
        Endpoint BindEndpoint;
        Endpoint LocalEndpoint{};
        Router OperationsRouter;
        std::chrono::milliseconds ReadDeadline;
        std::vector<std::shared_ptr<Tcp::socket>> ActiveSockets;
        Tcp::acceptor Acceptor;
        Net::steady_timer DrainTimer;
        std::atomic<std::size_t> ActiveConnections{0};
        std::atomic<std::uint64_t> NextCorrelation{1};
        std::atomic<bool> Started{false};
        std::atomic<bool> Running{false};
        std::atomic<bool> StopRequested{false};
        std::atomic<bool> Draining{false};
        std::atomic<bool> Drained{false};
    };

    HttpServer::HttpServer(const Options &OptionsValue)
        : HttpServer(OptionsValue.Executor,
                     OptionsValue.BindEndpoint,
                     OptionsValue.OperationsRouter,
                     OptionsValue.ReadDeadline)
    {
    }

    HttpServer::HttpServer(Net::any_io_executor Executor,
                           Endpoint BindEndpoint,
                           const Router &OperationsRouter,
                           const std::chrono::milliseconds ReadDeadline)
        : State_(std::make_shared<State>(std::move(Executor),
                                          BindEndpoint,
                                          OperationsRouter,
                                          ReadDeadline))
    {
    }

    HttpServer::~HttpServer() noexcept
    {
        Stop();
    }

    auto HttpServer::Start() -> Net::awaitable<StartResult>
    {
        const auto StateValue = State_;
        co_await Net::post(StateValue->Executor, Net::use_awaitable);
        co_return StartOnExecutor(StateValue);
    }

    auto HttpServer::Stop() noexcept -> void
    {
        const auto StateValue = State_;
        if (StateValue->StopRequested.exchange(true, std::memory_order_acq_rel))
        {
            return;
        }
        try
        {
            Net::post(StateValue->Executor, [StateValue] { CloseOnExecutor(StateValue); });
        }
        catch (...)
        {
            CloseOnExecutor(StateValue);
        }
    }

    auto HttpServer::Close() noexcept -> void
    {
        Stop();
    }

    auto HttpServer::Drain() -> Net::awaitable<void>
    {
        const auto StateValue = State_;
        co_await Net::post(StateValue->Executor, Net::use_awaitable);
        StateValue->StopRequested.store(true, std::memory_order_release);
        StateValue->Draining.store(true, std::memory_order_release);
        CloseOnExecutor(StateValue);
        if (StateValue->ActiveConnections.load(std::memory_order_acquire) == 0U)
        {
            StateValue->Drained.store(true, std::memory_order_release);
            co_return;
        }
        StateValue->DrainTimer.expires_after(StateValue->ReadDeadline);
        while (StateValue->ActiveConnections.load(std::memory_order_acquire) != 0U)
        {
            boost::system::error_code Error;
            co_await StateValue->DrainTimer.async_wait(
                Net::redirect_error(Net::use_awaitable, Error));
            if (StateValue->ActiveConnections.load(std::memory_order_acquire) == 0U)
            {
                break;
            }
            co_return;
        }
        if (StateValue->ActiveConnections.load(std::memory_order_acquire) == 0U)
        {
            StateValue->Drained.store(true, std::memory_order_release);
        }
    }

    auto HttpServer::LocalEndpoint() const -> Endpoint
    {
        return State_->LocalEndpoint;
    }

    auto HttpServer::IsRunning() const noexcept -> bool
    {
        return State_->Running.load(std::memory_order_acquire) &&
               !State_->StopRequested.load(std::memory_order_acquire);
    }

} // namespace Preview::Operations
