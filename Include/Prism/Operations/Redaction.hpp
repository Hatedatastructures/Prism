/**
 * @file Redaction.hpp
 * @brief Operations API 的值快照脱敏。
 */

#pragma once

#include <Prism/Operations/Metrics.hpp>
#include <Prism/Operations/Models.hpp>
#include <Prism/Operations/ScopedCollectionModels.hpp>
#include <Prism/Statistics/EventRing.hpp>
#include <string>
#include <string_view>

namespace Prism::Operations
{

    [[nodiscard]] auto Redact(std::string_view Detail) -> std::string;

    [[nodiscard]] auto Redact(const EventSnapshot &EventValue) -> EventSnapshot;

    [[nodiscard]] auto Redact(const Prism::Statistics::EventPage &PageValue)
        -> Prism::Statistics::EventPage;

    [[nodiscard]] auto Redact(const HealthSnapshot &Value) -> HealthSnapshot;

    [[nodiscard]] auto Redact(const GenerationSnapshot &Value) -> GenerationSnapshot;

    [[nodiscard]] auto Redact(const ProcessSnapshot &Value) -> ProcessSnapshot;

    [[nodiscard]] auto Redact(const WorkerSnapshot &Value) -> WorkerSnapshot;

    [[nodiscard]] auto Redact(const AccountSnapshot &Value) -> AccountSnapshot;

    [[nodiscard]] auto Redact(const SessionSnapshot &Value) -> SessionSnapshot;

    [[nodiscard]] auto Redact(const StreamSnapshot &Value) -> StreamSnapshot;

    [[nodiscard]] auto Redact(const TaskSnapshot &Value) -> TaskSnapshot;

    template <typename Value>
    [[nodiscard]] auto Redact(const Page<Value> &PageValue) -> Page<Value>
    {
        auto Result = PageValue;
        for (auto &Item : Result.Items)
        {
            Item = Redact(Item);
        }
        return Result;
    }

    [[nodiscard]] auto Redact(const CommandResult &Value) -> CommandResult;

    /** @brief 只含数值计数与实际历史的 metrics 快照不含凭据字段。 */
    [[nodiscard]] auto Redact(const MetricsSnapshot &Value) -> MetricsSnapshot;

    /** @brief 配置响应只含 PublicConfiguration DTO，保留其非凭据 JSON 字节。 */
    [[nodiscard]] auto Redact(const ConfigurationSnapshot &Value) -> ConfigurationSnapshot;

    [[nodiscard]] auto Redact(const LatencySummary &Value) -> LatencySummary;

    [[nodiscard]] auto Redact(const MemoryAllocationSnapshot &Value) -> MemoryAllocationSnapshot;

    [[nodiscard]] auto Redact(const WorkerMemorySnapshot &Value) -> WorkerMemorySnapshot;

    [[nodiscard]] auto Redact(const MemorySnapshot &Value) -> MemorySnapshot;

    [[nodiscard]] auto Redact(const IngressSnapshot &Value) -> IngressSnapshot;

    [[nodiscard]] auto Redact(const ProtocolSnapshot &Value) -> ProtocolSnapshot;

    [[nodiscard]] auto Redact(const GroupSnapshot &Value) -> GroupSnapshot;

    [[nodiscard]] auto Redact(const OperationSnapshot &Value) -> OperationSnapshot;

    [[nodiscard]] auto Redact(const TraceSpanSnapshot &Value) -> TraceSpanSnapshot;

    [[nodiscard]] auto Redact(const TracePageSnapshot &Value) -> TracePageSnapshot;

    [[nodiscard]] auto Redact(const OverviewSnapshot &Value) -> OverviewSnapshot;

    [[nodiscard]] auto Redact(const ManagementPayload &Value) -> ManagementPayload;

    [[nodiscard]] auto Redact(const QueryResult &Value) -> QueryResult;

} // namespace Prism::Operations
