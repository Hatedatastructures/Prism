/** @file Redaction.cpp @brief Operations 值快照脱敏实现。 */
#include <Prism/Operations/Redaction.hpp>
#include <Prism/Foundation/Utility/Text/Redaction.hpp>

#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>

namespace Prism::Operations
{

    [[nodiscard]] auto Redact(std::string_view Detail) -> std::string
    {
        return Prism::Text::RedactSensitiveText(Detail);
    }

    [[nodiscard]] auto Redact(const EventSnapshot &EventValue) -> EventSnapshot
    {
        auto Result = EventValue;
        Result.Detail = Redact(Result.Detail);
        return Result;
    }

    [[nodiscard]] auto Redact(const Prism::Statistics::EventPage &PageValue)
        -> Prism::Statistics::EventPage
    {
        auto Result = PageValue;
        for (auto &Item : Result.Items)
        {
            Item = Redact(Item);
        }
        return Result;
    }

    [[nodiscard]] auto Redact(const HealthSnapshot &Value) -> HealthSnapshot
    {
        return Value;
    }

    [[nodiscard]] auto Redact(const GenerationSnapshot &Value) -> GenerationSnapshot
    {
        return Value;
    }

    [[nodiscard]] auto Redact(const ProcessSnapshot &Value) -> ProcessSnapshot
    {
        return Value;
    }

    [[nodiscard]] auto Redact(const WorkerSnapshot &Value) -> WorkerSnapshot
    {
        return Value;
    }

    [[nodiscard]] auto Redact(const AccountSnapshot &Value) -> AccountSnapshot
    {
        auto Result = Value;
        Result.Label = Redact(Result.Label);
        return Result;
    }

    [[nodiscard]] auto Redact(const SessionSnapshot &Value) -> SessionSnapshot
    {
        auto Result = Value;
        Result.Protocol = Redact(Result.Protocol);
        Result.Target = Redact(Result.Target);
        return Result;
    }

    [[nodiscard]] auto Redact(const StreamSnapshot &Value) -> StreamSnapshot
    {
        auto Result = Value;
        Result.Protocol = Redact(Result.Protocol);
        return Result;
    }

    [[nodiscard]] auto Redact(const TaskSnapshot &Value) -> TaskSnapshot
    {
        return Value;
    }

    [[nodiscard]] auto Redact(const CommandResult &Value) -> CommandResult
    {
        auto Result = Value;
        Result.Message = Redact(Result.Message);
        return Result;
    }

    [[nodiscard]] auto Redact(const MetricsSnapshot &Value) -> MetricsSnapshot
    {
        return Value;
    }

    [[nodiscard]] auto Redact(const ConfigurationSnapshot &Value) -> ConfigurationSnapshot
    {
        return Value;
    }

    [[nodiscard]] auto Redact(const LatencySummary &Value) -> LatencySummary
    {
        auto Result = Value;
        Result.Name = Redact(Result.Name);
        Result.Protocol = Redact(Result.Protocol);
        return Result;
    }

    [[nodiscard]] auto Redact(const MemoryAllocationSnapshot &Value) -> MemoryAllocationSnapshot
    {
        auto Result = Value;
        Result.Coverage = Redact(Result.Coverage);
        return Result;
    }

    [[nodiscard]] auto Redact(const WorkerMemorySnapshot &Value) -> WorkerMemorySnapshot
    {
        auto Result = Value;
        Result.Allocations = Redact(Result.Allocations);
        return Result;
    }

    [[nodiscard]] auto Redact(const MemorySnapshot &Value) -> MemorySnapshot
    {
        auto Result = Value;
        Result.ProcessAllocations = Redact(Result.ProcessAllocations);
        for (auto &Worker : Result.WorkerAllocations)
        {
            Worker = Redact(Worker);
        }
        return Result;
    }

    [[nodiscard]] auto Redact(const IngressSnapshot &Value) -> IngressSnapshot
    {
        auto Result = Value;
        Result.Id = Redact(Result.Id);
        Result.Transport = Redact(Result.Transport);
        Result.ConfiguredAddress = Redact(Result.ConfiguredAddress);
        if (Result.BoundAddress)
        {
            *Result.BoundAddress = Redact(*Result.BoundAddress);
        }
        for (auto &Protocol : Result.Protocols)
        {
            Protocol = Redact(Protocol);
        }
        for (auto &Carrier : Result.Carriers)
        {
            Carrier = Redact(Carrier);
        }
        return Result;
    }

    [[nodiscard]] auto Redact(const ProtocolSnapshot &Value) -> ProtocolSnapshot
    {
        auto Result = Value;
        Result.Id = Redact(Result.Id);
        Result.Name = Redact(Result.Name);
        if (Result.Latency)
        {
            *Result.Latency = Redact(*Result.Latency);
        }
        return Result;
    }

    [[nodiscard]] auto Redact(const GroupSnapshot &Value) -> GroupSnapshot
    {
        auto Result = Value;
        Result.Id = Redact(Result.Id);
        Result.Name = Redact(Result.Name);
        return Result;
    }

    [[nodiscard]] auto Redact(const OperationSnapshot &Value) -> OperationSnapshot
    {
        auto Result = Value;
        Result.Command = Redact(Result.Command);
        Result.Status = Redact(Result.Status);
        Result.Message = Redact(Result.Message);
        return Result;
    }

    [[nodiscard]] auto Redact(const TraceSpanSnapshot &Value) -> TraceSpanSnapshot
    {
        auto Result = Value;
        Result.Name = Redact(Result.Name);
        Result.Status = Redact(Result.Status);
        Result.Stage = Redact(Result.Stage);
        Result.Outcome = Redact(Result.Outcome);
        return Result;
    }

    [[nodiscard]] auto Redact(const TracePageSnapshot &Value) -> TracePageSnapshot
    {
        auto Result = Value;
        for (auto &Span : Result.Items)
        {
            Span = Redact(Span);
        }
        Result.NextCursor = Redact(Result.NextCursor);
        return Result;
    }

    [[nodiscard]] auto Redact(const OverviewSnapshot &Value) -> OverviewSnapshot
    {
        auto Result = Value;
        Result.Phase = Redact(Result.Phase);
        Result.RecognitionAdmission = Redact(Result.RecognitionAdmission);
        for (auto &Stage : Result.LatencyStages)
        {
            Stage = Redact(Stage);
        }
        Result.Memory = Redact(Result.Memory);
        for (auto &Protocol : Result.Protocols)
        {
            Protocol = Redact(Protocol);
        }
        return Result;
    }

    [[nodiscard]] auto Redact(const ManagementPayload &Value) -> ManagementPayload
    {
        auto Result = Value;
        std::visit([](auto &Payload) { Payload = Redact(Payload); }, Result);
        return Result;
    }

    [[nodiscard]] auto Redact(const QueryResult &Value) -> QueryResult
    {
        auto Result = Value;
        Result.Message = Redact(Result.Message);
        std::visit(
            [](auto &Payload)
            {
                using PayloadType = std::remove_cvref_t<decltype(Payload)>;
                if constexpr (!std::is_same_v<PayloadType, std::monostate>)
                {
                    Payload = Redact(Payload);
                }
            },
            Result.Value);
        return Result;
    }

} // namespace Prism::Operations
