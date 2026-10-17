/**
 * @file ManagementJson.hpp
 * @brief 新增管理查询的有界 owning JSON 序列化。
 */
#pragma once

#include <Preview/Operations/ManagementModels.hpp>
#include <Preview/Operations/Http/JsonWriter.hpp>
#include <Preview/Operations/Routes/JsonPrimitives.hpp>

#include <algorithm>
#include <type_traits>
#include <variant>

namespace Preview::Operations::HttpDetail
{

    [[nodiscard]] inline auto ManagementHealthName(
        const Preview::Statistics::HealthStatus Value) -> std::string_view
    {
        using Status = Preview::Statistics::HealthStatus;
        switch (Value)
        {
        case Status::Healthy: return "healthy";
        case Status::Degraded: return "degraded";
        case Status::Unhealthy: return "unhealthy";
        case Status::Draining: return "draining";
        case Status::Unknown: return "unknown";
        }
        return "unknown";
    }

    [[nodiscard]] inline auto AppendManagementHealth(
        JsonWriter &Writer,
        const Preview::Statistics::HealthSnapshot &Value) -> bool
    {
        return Writer.Append("{") && Writer.Key("status") &&
               Writer.String(ManagementHealthName(Value.Status)) && Writer.Append(",") &&
               Writer.Key("checked_at") && AppendUtcTimestamp(Writer, Value.CheckedAt) &&
               Writer.Append(",") && Writer.Key("active") && Writer.Decimal(Value.Active) &&
               Writer.Append(",") && Writer.Key("errors") && Writer.Decimal(Value.Errors) &&
               Writer.Append(",") && Writer.Key("ready") && Writer.Boolean(Value.Ready) &&
               Writer.Append(",") && Writer.Key("tcp_ready") && Writer.Boolean(Value.TcpReady) &&
               Writer.Append(",") && Writer.Key("udp_ready") && Writer.Boolean(Value.UdpReady) &&
               Writer.Append(",") && Writer.Key("udp_socket_ready") &&
               Writer.Boolean(Value.UdpSocketReady) && Writer.Append(",") &&
               Writer.Key("quic_ready") && Writer.Boolean(Value.QuicReady) &&
               Writer.Append(",") && Writer.Key("quic_socket_ready") &&
               Writer.Boolean(Value.QuicSocketReady) && Writer.Append(",") &&
               Writer.Key("quic_handshake_ready") && Writer.Boolean(Value.QuicHandshakeReady) &&
               Writer.Append(",") && Writer.Key("quic_protocol_ready") &&
               Writer.Boolean(Value.QuicProtocolReady) && Writer.Append("}");
    }

    [[nodiscard]] inline auto AppendManagementTraffic(
        JsonWriter &Writer,
        const Preview::Statistics::TrafficValue &Value) -> bool
    {
        return Writer.Append("{") && Writer.Key("up_bytes") && Writer.Decimal(Value.UpBytes) &&
               Writer.Append(",") && Writer.Key("down_bytes") && Writer.Decimal(Value.DownBytes) &&
               Writer.Append(",") && Writer.Key("events") && Writer.Decimal(Value.Events) &&
               Writer.Append(",") && Writer.Key("errors") && Writer.Decimal(Value.Errors) &&
               Writer.Append("}");
    }

    [[nodiscard]] inline auto AppendOverviewTraffic(
        JsonWriter &Writer, const Preview::Operations::OverviewSnapshot &Value) -> bool
    {
        const auto WriteMetric = [&Writer](const std::optional<std::uint64_t> Metric) -> bool
        { return Metric ? Writer.Decimal(*Metric) : Writer.Null(); };
        return Writer.Append("{") && Writer.Key("available") && Writer.Boolean(Value.Traffic.has_value()) &&
               Writer.Append(",") && Writer.Key("up_bytes") && WriteMetric(Value.Traffic
                   ? std::optional<std::uint64_t>{Value.Traffic->UpBytes} : std::nullopt) &&
               Writer.Append(",") && Writer.Key("down_bytes") && WriteMetric(Value.Traffic
                   ? std::optional<std::uint64_t>{Value.Traffic->DownBytes} : std::nullopt) &&
               Writer.Append(",") && Writer.Key("events") && WriteMetric(Value.Traffic
                   ? std::optional<std::uint64_t>{Value.Traffic->Events} : std::nullopt) &&
               Writer.Append(",") && Writer.Key("errors") && WriteMetric(Value.Traffic
                   ? std::optional<std::uint64_t>{Value.Traffic->Errors} : std::nullopt) &&
               Writer.Append(",") && Writer.Key("up_bytes_per_second") && WriteMetric(Value.UploadBytesPerSecond) &&
               Writer.Append(",") && Writer.Key("down_bytes_per_second") && WriteMetric(Value.DownloadBytesPerSecond) &&
               Writer.Append("}");
    }

    [[nodiscard]] inline auto AppendOptionalDecimal(
        JsonWriter &Writer,
        const std::optional<std::uint64_t> &Value) -> bool
    {
        return Value ? Writer.Decimal(*Value) : Writer.Null();
    }

    [[nodiscard]] inline auto AppendLatencySummary(
        JsonWriter &Writer,
        const Preview::Operations::LatencySummary &Value) -> bool
    {
        if (!Writer.Append("{") || !Writer.Key("name") || !Writer.String(Value.Name) ||
            !Writer.Append(",") || !Writer.Key("available") || !Writer.Boolean(Value.Available) ||
            !Writer.Append(",") || !Writer.Key("sample_count") || !Writer.Decimal(Value.SampleCount) ||
            !Writer.Append(",") || !Writer.Key("p50_ms") || !AppendOptionalDecimal(Writer, Value.P50Milliseconds) ||
            !Writer.Append(",") || !Writer.Key("p95_ms") || !AppendOptionalDecimal(Writer, Value.P95Milliseconds) ||
            !Writer.Append(",") || !Writer.Key("p99_ms") || !AppendOptionalDecimal(Writer, Value.P99Milliseconds) ||
            !Writer.Append(",") || !Writer.Key("max_ms") || !AppendOptionalDecimal(Writer, Value.MaximumMilliseconds))
        {
            return false;
        }
        if (Value.Worker && (!Writer.Append(",") || !Writer.Key("worker_id") ||
                             !AppendId(Writer, *Value.Worker)))
        {
            return false;
        }
        if (!Value.Protocol.empty() && (!Writer.Append(",") || !Writer.Key("protocol") ||
                                        !Writer.String(Value.Protocol)))
        {
            return false;
        }
        return Writer.Append("}");
    }

    [[nodiscard]] inline auto AppendMemoryPool(
        JsonWriter &Writer,
        const Preview::Operations::MemoryPoolSnapshot &Value) -> bool
    {
        return Writer.Append("{") && Writer.Key("available") && Writer.Boolean(Value.Available) &&
               Writer.Append(",") && Writer.Key("used_bytes") && Writer.Decimal(Value.UsedBytes) &&
               Writer.Append(",") && Writer.Key("capacity_bytes") && Writer.Decimal(Value.CapacityBytes) &&
               Writer.Append(",") && Writer.Key("available_blocks") && Writer.Decimal(Value.AvailableBlocks) &&
               Writer.Append(",") && Writer.Key("block_size") && Writer.Decimal(Value.BlockSize) &&
               Writer.Append(",") && Writer.Key("peak_used_bytes") && Writer.Decimal(Value.PeakUsedBytes) &&
               Writer.Append(",") && Writer.Key("allocation_count") && Writer.Decimal(Value.AllocationCount) &&
               Writer.Append(",") && Writer.Key("release_count") && Writer.Decimal(Value.ReleaseCount) &&
               Writer.Append("}");
    }

    [[nodiscard]] inline auto AppendMemoryAllocation(
        JsonWriter &Writer,
        const Preview::Operations::MemoryAllocationSnapshot &Value) -> bool
    {
        return Writer.Append("{") && Writer.Key("available") && Writer.Boolean(Value.Available) &&
               Writer.Append(",") && Writer.Key("current_bytes") && Writer.Decimal(Value.CurrentBytes) &&
               Writer.Append(",") && Writer.Key("peak_bytes") && Writer.Decimal(Value.PeakBytes) &&
               Writer.Append(",") && Writer.Key("allocation_count") && Writer.Decimal(Value.AllocationCount) &&
               Writer.Append(",") && Writer.Key("release_count") && Writer.Decimal(Value.ReleaseCount) &&
               Writer.Append(",") && Writer.Key("coverage") && Writer.String(Value.Coverage) &&
               Writer.Append("}");
    }

    [[nodiscard]] inline auto AppendIngress(
        JsonWriter &Writer,
        const Preview::Operations::IngressSnapshot &Value) -> bool
    {
        if (!Writer.Append("{") || !Writer.Key("id") || !Writer.String(Value.Id) ||
            !Writer.Append(",") || !Writer.Key("transport") || !Writer.String(Value.Transport) ||
            !Writer.Append(",") || !Writer.Key("configured_address") || !Writer.String(Value.ConfiguredAddress) ||
            !Writer.Append(",") || !Writer.Key("bound_address"))
        {
            return false;
        }
        if (Value.BoundAddress ? !Writer.String(*Value.BoundAddress) : !Writer.Null()) return false;
        if (!Writer.Append(",") || !Writer.Key("ready") || !Writer.Boolean(Value.Ready) ||
            !Writer.Append(",") || !Writer.Key("protocols") || !Writer.Append("["))
        {
            return false;
        }
        bool First = true;
        for (const auto &Protocol : Value.Protocols)
        {
            if (!AppendComma(Writer, First) || !Writer.String(Protocol)) return false;
        }
        if (!Writer.Append("],\"carriers\":[")) return false;
        First = true;
        for (const auto &Carrier : Value.Carriers)
        {
            if (!AppendComma(Writer, First) || !Writer.String(Carrier)) return false;
        }
        return Writer.Append("],\"active_connections\":") &&
               AppendOptionalDecimal(Writer, Value.ActiveConnections) && Writer.Append("}");
    }

    [[nodiscard]] inline auto AppendGroup(
        JsonWriter &Writer,
        const Preview::Operations::GroupSnapshot &Value) -> bool
    {
        return Writer.Append("{") && Writer.Key("id") && Writer.String(Value.Id) &&
               Writer.Append(",") && Writer.Key("name") && Writer.String(Value.Name) &&
               Writer.Append(",") && Writer.Key("configured_account_count") && Writer.Decimal(Value.ConfiguredAccounts) &&
               Writer.Append(",") && Writer.Key("active_account_count") && Writer.Decimal(Value.ActiveAccounts) &&
               Writer.Append(",") && Writer.Key("active_sessions") && AppendOptionalDecimal(Writer, Value.ActiveSessions) &&
               Writer.Append(",") && Writer.Key("traffic") &&
               (Value.Traffic ? AppendManagementTraffic(Writer, *Value.Traffic) : Writer.Null()) &&
               Writer.Append("}");
    }

    [[nodiscard]] inline auto AppendProtocol(
        JsonWriter &Writer,
        const Preview::Operations::ProtocolSnapshot &Value) -> bool
    {
        if (!Writer.Append("{") || !Writer.Key("id") || !Writer.String(Value.Id) ||
            !Writer.Append(",") || !Writer.Key("name") || !Writer.String(Value.Name) ||
            !Writer.Append(",") || !Writer.Key("configured_bindings") || !Writer.Decimal(Value.ConfiguredBindings) ||
            !Writer.Append(",") || !Writer.Key("active_sessions") || !AppendOptionalDecimal(Writer, Value.ActiveSessions) ||
            !Writer.Append(",") || !Writer.Key("traffic"))
        {
            return false;
        }
        if (Value.Traffic ? !AppendManagementTraffic(Writer, *Value.Traffic) : !Writer.Null()) return false;
        if (!Writer.Append(",") || !Writer.Key("latency")) return false;
        if (Value.Latency ? !AppendLatencySummary(Writer, *Value.Latency) : !Writer.Null()) return false;
        return Writer.Append(",") && Writer.Key("coverage") && Writer.String(Value.Coverage) &&
               Writer.Append("}");
    }

    [[nodiscard]] inline auto AppendOperation(
        JsonWriter &Writer,
        const Preview::Operations::OperationSnapshot &Value) -> bool
    {
        if (!Writer.Append("{") || !Writer.Key("id") || !Writer.Decimal(Value.Id) ||
            !Writer.Append(",") || !Writer.Key("command") || !Writer.String(Value.Command) ||
            !Writer.Append(",") || !Writer.Key("status") || !Writer.String(Value.Status) ||
            !Writer.Append(",") || !Writer.Key("correlation") || !AppendId(Writer, Value.Correlation) ||
            !Writer.Append(",") || !Writer.Key("accepted_at") || !AppendOptionalUtcTimestamp(Writer, Value.AcceptedAt) ||
            !Writer.Append(",") || !Writer.Key("updated_at") || !AppendOptionalUtcTimestamp(Writer, Value.UpdatedAt) ||
            !Writer.Append(",") || !Writer.Key("message") || !Writer.String(Value.Message))
        {
            return false;
        }
        const auto AppendOptionalId = [&Writer](const std::string_view Name, const auto Id) -> bool
        {
            if (!Id) return true;
            return Writer.Append(",") && Writer.Key(Name) && AppendId(Writer, Id);
        };
        return AppendOptionalId("process", Value.Process) &&
               AppendOptionalId("generation", Value.Generation) &&
               AppendOptionalId("worker", Value.Worker) &&
               AppendOptionalId("account", Value.Account) &&
               AppendOptionalId("session", Value.Session) &&
               AppendOptionalId("stream", Value.Stream) &&
               AppendOptionalId("task", Value.Task) && Writer.Append("}");
    }

    [[nodiscard]] inline auto AppendTraceSpan(
        JsonWriter &Writer,
        const Preview::Operations::TraceSpanSnapshot &Value) -> bool
    {
        if (!Writer.Append("{") || !Writer.Key("span_id") || !Writer.String(Value.SpanId) ||
            !Writer.Append(",") || !Writer.Key("parent_span_id") ||
            !(Value.ParentSpanId ? Writer.String(*Value.ParentSpanId) : Writer.Null()) ||
            !Writer.Append(",") || !Writer.Key("sequence") || !Writer.Decimal(Value.Sequence) ||
            !Writer.Append(",") || !Writer.Key("name") || !Writer.String(Value.Name) ||
            !Writer.Append(",") || !Writer.Key("start_time") ||
            !AppendUtcTimestamp(Writer, Value.StartTimeUnixNanoseconds / 1000000U) ||
            !Writer.Append(",") || !Writer.Key("duration_ms") ||
            !AppendOptionalDecimal(Writer, Value.DurationMilliseconds) ||
            !Writer.Append(",") || !Writer.Key("status") || !Writer.String(Value.Status) ||
            !Writer.Append(",") || !Writer.Key("process") || !AppendId(Writer, Value.Process) ||
            !Writer.Append(",") || !Writer.Key("generation") || !AppendId(Writer, Value.Generation) ||
            !Writer.Append(",") || !Writer.Key("session") || !AppendId(Writer, Value.Session))
        {
            return false;
        }
        const auto AppendOptionalId = [&Writer](const std::string_view Name, const auto Id) -> bool
        {
            if (!Id) return true;
            return Writer.Append(",") && Writer.Key(Name) && AppendId(Writer, Id);
        };
        if (Value.Worker && (!Writer.Append(",") || !Writer.Key("worker") || !AppendId(Writer, *Value.Worker)))
        {
            return false;
        }
        if (!AppendOptionalId("account", Value.Account) || !AppendOptionalId("task", Value.Task) ||
            !AppendOptionalId("parent_task", Value.ParentTask) || !AppendOptionalId("stream", Value.Stream))
        {
            return false;
        }
        return Writer.Append(",") && Writer.Key("attributes") && Writer.Append("{") &&
            Writer.Key("stage") && Writer.String(Value.Stage) && Writer.Append(",") &&
            Writer.Key("outcome") && Writer.String(Value.Outcome) && Writer.Append(",") &&
            Writer.Key("elapsed_ns") && Writer.Decimal(Value.ElapsedNanoseconds) && Writer.Append(",") &&
            Writer.Key("failure_code") &&
            (Value.FailureCode ? Writer.Decimal(static_cast<std::uint64_t>(*Value.FailureCode)) : Writer.Null()) &&
            Writer.Append("}}");
    }

    template <typename Value, typename Appender>
    [[nodiscard]] inline auto AppendManagementPage(
        JsonWriter &Writer,
        const Preview::Operations::Page<Value> &Page,
        Appender AppendItem) -> bool
    {
        if (!Writer.Append("{\"items\":[")) return false;
        bool First = true;
        for (const auto &Item : Page.Items)
        {
            if (!AppendComma(Writer, First) || !AppendItem(Writer, Item)) return false;
        }
        return Writer.Append("],\"next_cursor\":") && Writer.Decimal(Page.NextCursor) &&
               Writer.Append(",\"has_more\":") && Writer.Boolean(Page.HasMore) && Writer.Append("}");
    }

    [[nodiscard]] inline auto AppendOverview(
        JsonWriter &Writer,
        const Preview::Operations::OverviewSnapshot &Value) -> bool
    {
        if (!Writer.Append("{") || !Writer.Key("sampled_at") || !AppendUtcTimestamp(Writer, Value.SampledAt) ||
            !Writer.Append(",") || !Writer.Key("process") || !Writer.Append("{") ||
            !Writer.Key("id") || !AppendId(Writer, Value.Process) || !Writer.Append(",") ||
            !Writer.Key("generation") || !AppendId(Writer, Value.Generation) ||
            !Writer.Append(",") || !Writer.Key("phase") || !Writer.String(Value.Phase) ||
            !Writer.Append("}") || !Writer.Append(",") || !Writer.Key("health") ||
            !AppendManagementHealth(Writer, Value.Health) || !Writer.Append(",") || !Writer.Key("counts") ||
            !Writer.Append("{") || !Writer.Key("configured_accounts") || !Writer.Decimal(Value.ConfiguredAccounts) ||
            !Writer.Append(",") || !Writer.Key("active_accounts") || !Writer.Decimal(Value.ActiveAccounts) ||
            !Writer.Append(",") || !Writer.Key("ungrouped_accounts") || !Writer.Decimal(Value.UngroupedAccounts) ||
            !Writer.Append(",") || !Writer.Key("tcp_sessions") || !Writer.Decimal(Value.TcpSessions) ||
            !Writer.Append(",") || !Writer.Key("udp_connections") ||
            !AppendOptionalDecimal(Writer, Value.UdpConnections) ||
            !Writer.Append(",") || !Writer.Key("quic_connections") ||
            !AppendOptionalDecimal(Writer, Value.QuicConnections) ||
            !Writer.Append(",") || !Writer.Key("workers_total") || !Writer.Decimal(Value.WorkersTotal) ||
            !Writer.Append(",") || !Writer.Key("workers_accepting") || !Writer.Decimal(Value.WorkersAccepting) ||
            !Writer.Append("}") || !Writer.Append(",") || !Writer.Key("traffic") ||
            !AppendOverviewTraffic(Writer, Value) || !Writer.Append(",") || !Writer.Key("sample_interval_ms") ||
            !Writer.Decimal(Value.SampleIntervalMilliseconds) || !Writer.Append(",") ||
            !Writer.Key("latency") || !Writer.Append("{") ||
            !Writer.Key("recognition_admission") || !AppendLatencySummary(Writer, Value.RecognitionAdmission) ||
            !Writer.Append(",") || !Writer.Key("stages") || !Writer.Append("["))
        {
            return false;
        }
        bool First = true;
        for (const auto &Stage : Value.LatencyStages)
        {
            if (!AppendComma(Writer, First) || !AppendLatencySummary(Writer, Stage)) return false;
        }
        if (!Writer.Append("]}") || !Writer.Append(",") || !Writer.Key("memory") || !Writer.Append("{") ||
            !Writer.Key("process_available") || !Writer.Boolean(Value.Memory.ProcessAvailable) ||
            !Writer.Append(",") || !Writer.Key("process_rss_bytes") ||
            !(Value.Memory.ProcessAvailable ? Writer.Decimal(Value.Memory.ResidentBytes) : Writer.Null()) ||
            !Writer.Append(",") || !Writer.Key("working_set_bytes") ||
            !(Value.Memory.ProcessAvailable ? Writer.Decimal(Value.Memory.ResidentBytes) : Writer.Null()) ||
            !Writer.Append(",") || !Writer.Key("process_peak_rss_bytes") ||
            !(Value.Memory.ProcessAvailable ? Writer.Decimal(Value.Memory.PeakResidentBytes) : Writer.Null()) ||
            !Writer.Append(",") || !Writer.Key("byte_pool") || !AppendMemoryPool(Writer, Value.Memory.ProcessPool) ||
            !Writer.Append(",") || !Writer.Key("allocations") ||
            !AppendMemoryAllocation(Writer, Value.Memory.ProcessAllocations) ||
            !Writer.Append(",") || !Writer.Key("worker_allocations") || !Writer.Append("["))
        {
            return false;
        }
        First = true;
        for (std::size_t Index = 0; Index < Value.Memory.WorkerAllocations.size(); ++Index)
        {
            if (!AppendComma(Writer, First) || !Writer.Append("{") || !Writer.Key("worker_id") ||
                !AppendId(Writer, Value.Memory.WorkerAllocations[Index].Id) ||
                !Writer.Append(",") || !Writer.Key("allocation") ||
                !AppendMemoryAllocation(Writer, Value.Memory.WorkerAllocations[Index].Allocations) ||
                !Writer.Append("}"))
            {
                return false;
            }
        }
        if (!Writer.Append("]}") || !Writer.Append(",") || !Writer.Key("observations") || !Writer.Append("{") ||
            !Writer.Key("accepted") || !Writer.Decimal(Value.AcceptedObservations) ||
            !Writer.Append(",") || !Writer.Key("consumed") || !Writer.Decimal(Value.ConsumedObservations) ||
            !Writer.Append(",") || !Writer.Key("dropped") || !Writer.Decimal(Value.DroppedObservations) ||
            !Writer.Append(",") || !Writer.Key("aggregation_failures") || !Writer.Decimal(Value.AggregationFailures) ||
            !Writer.Append("}") || !Writer.Append(",") || !Writer.Key("history") || !Writer.Append("["))
        {
            return false;
        }
        First = true;
        for (const auto &Sample : Value.History)
        {
            if (!AppendComma(Writer, First) || !Writer.Append("{") || !Writer.Key("timestamp") ||
                !AppendUtcTimestamp(Writer, Sample.Timestamp) || !Writer.Append(",") ||
                !Writer.Key("traffic") || !AppendManagementTraffic(Writer, Sample.Value) || !Writer.Append("}"))
            {
                return false;
            }
        }
        if (!Writer.Append("],\"protocols\":[")) return false;
        First = true;
        for (const auto &Protocol : Value.Protocols)
        {
            if (!AppendComma(Writer, First) || !AppendProtocol(Writer, Protocol)) return false;
        }
        return Writer.Append("]}");
    }

    [[nodiscard]] inline auto AppendTracePage(
        JsonWriter &Writer, const Preview::Operations::TracePageSnapshot &Page) -> bool
    {
        if (!Writer.Append("{\"items\":[")) return false;
        bool First = true;
        for (const auto &Item : Page.Items)
        {
            if (!AppendComma(Writer, First) || !AppendTraceSpan(Writer, Item)) return false;
        }
        if (!Writer.Append("],\"next_cursor\":") || !Writer.String(Page.NextCursor) ||
            !Writer.Append(",\"has_more\":") || !Writer.Boolean(Page.HasMore) ||
            !Writer.Append(",\"lost\":") ||
            !Writer.Boolean(std::any_of(Page.Loss.begin(), Page.Loss.end(), [](const auto &Value)
                { return Value.LostSinceCursor != 0U || Value.ConcurrentReadSkips != 0U; })) ||
            !Writer.Append(",\"cursors\":["))
        {
            return false;
        }
        First = true;
        for (const auto &Cursor : Page.Cursors)
        {
            if (!AppendComma(Writer, First) || !Writer.Append("{\"worker_id\":") ||
                !AppendId(Writer, Cursor.Worker) || !Writer.Append(",\"sequence\":") ||
                !Writer.Decimal(Cursor.Sequence) || !Writer.Append("}")) return false;
        }
        if (!Writer.Append("],\"lost_ranges\":[")) return false;
        First = true;
        for (const auto &Loss : Page.Loss)
        {
            if (Loss.LostSinceCursor == 0U && Loss.ConcurrentReadSkips == 0U) continue;
            if (!AppendComma(Writer, First) || !Writer.Append("{\"worker_id\":") ||
                !AppendId(Writer, Loss.Worker) || !Writer.Append(",\"overwritten\":") ||
                !Writer.Decimal(Loss.Overwritten) || !Writer.Append(",\"lost_since_cursor\":") ||
                !Writer.Decimal(Loss.LostSinceCursor) || !Writer.Append(",\"concurrent_read_skips\":") ||
                !Writer.Decimal(Loss.ConcurrentReadSkips) || !Writer.Append("}")) return false;
        }
        return Writer.Append("]}");
    }

    template <typename Value>
    [[nodiscard]] inline auto AppendManagementPayloadValue(JsonWriter &Writer, const Value &Payload) -> bool
    {
        using ValueType = std::remove_cvref_t<Value>;
        if constexpr (std::is_same_v<ValueType, Preview::Operations::OverviewSnapshot>)
        {
            return AppendOverview(Writer, Payload);
        }
        else if constexpr (std::is_same_v<ValueType, Preview::Operations::Page<Preview::Operations::IngressSnapshot>>)
        {
            return AppendManagementPage(Writer, Payload, AppendIngress);
        }
        else if constexpr (std::is_same_v<ValueType, Preview::Operations::Page<Preview::Operations::GroupSnapshot>>)
        {
            return AppendManagementPage(Writer, Payload, AppendGroup);
        }
        else if constexpr (std::is_same_v<ValueType, Preview::Operations::Page<Preview::Operations::ProtocolSnapshot>>)
        {
            return AppendManagementPage(Writer, Payload, AppendProtocol);
        }
        else if constexpr (std::is_same_v<ValueType, Preview::Operations::Page<Preview::Operations::OperationSnapshot>>)
        {
            return AppendManagementPage(Writer, Payload, AppendOperation);
        }
        else if constexpr (std::is_same_v<ValueType, Preview::Operations::TracePageSnapshot>)
        {
            return AppendTracePage(Writer, Payload);
        }
        else return AppendManagementPage(Writer, Payload, AppendOperation);
    }

    [[nodiscard]] inline auto AppendManagementPayload(
        JsonWriter &Writer,
        const Preview::Operations::ManagementPayload &Payload) -> bool
    {
        return std::visit([&Writer](const auto &Value) { return AppendManagementPayloadValue(Writer, Value); }, Payload);
    }

} // namespace Preview::Operations::HttpDetail
