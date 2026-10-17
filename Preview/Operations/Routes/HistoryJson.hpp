/** @file HistoryJson.hpp @brief 历史结果的有界精确 JSON 输出。 */
#pragma once
#include <Preview/Statistics/Analysis/HistoryModels.hpp>
#include <Preview/Operations/Http/JsonWriter.hpp>
#include <Preview/Operations/Routes/JsonPrimitives.hpp>
#include <string_view>

namespace Preview::Operations::HttpDetail
{
    [[nodiscard]] inline auto HistoryScopeName(Preview::Statistics::HistoryScope Scope) -> std::string_view
    {
        using Type = Preview::Statistics::HistoryScope;
        switch (Scope)
        {
        case Type::Process: return "process";
        case Type::Worker: return "worker";
        case Type::Account: return "account";
        case Type::Group: return "group";
        case Type::Ingress: return "ingress";
        case Type::ProtocolType: return "protocol_type";
        case Type::ProtocolInstance: return "protocol_instance";
        }
        return "unknown";
    }

    [[nodiscard]] inline auto AppendHistoryOptional(JsonWriter &Writer, std::optional<std::uint64_t> Value) -> bool
    { return Value ? Writer.Decimal(*Value) : Writer.Null(); }

    [[nodiscard]] inline auto HistoryMetricName(Preview::Statistics::HistoryMetric Metric) -> std::string_view
    {
        using Type = Preview::Statistics::HistoryMetric;
        switch (Metric)
        {
        case Type::Traffic: return "traffic";
        case Type::RecognitionAdmission: return "recognition_admission";
        case Type::DnsResolution: return "dns_resolution";
        case Type::TcpConnect: return "tcp_connect";
        }
        return "unknown";
    }

    [[nodiscard]] inline auto AppendHistoryRecord(JsonWriter &Writer,
        const Preview::Statistics::HistoryRecord &Value) -> bool
    {
        return Writer.Append("{") && Writer.Key("scope") && Writer.String(HistoryScopeName(Value.Scope)) &&
            Writer.Append(",") && Writer.Key("metric") && Writer.String(HistoryMetricName(Value.Metric)) &&
            Writer.Append(",") && Writer.Key("key") && Writer.String(Value.Key) &&
            Writer.Append(",") && Writer.Key("instance_key") && Writer.String(Value.InstanceKey) &&
            Writer.Append(",") && Writer.Key("process_incarnation") && Writer.String(Value.Incarnation) &&
            Writer.Append(",") && Writer.Key("generation") && Writer.Decimal(Value.Generation) &&
            Writer.Append(",") && Writer.Key("time") && AppendUtcTimestamp(Writer, Value.Timestamp) &&
            Writer.Append(",") && Writer.Key("resolution_ms") && Writer.Decimal(Value.ResolutionMilliseconds) &&
            Writer.Append(",") && Writer.Key("up_bytes") && Writer.Decimal(Value.UpBytes) &&
            Writer.Append(",") && Writer.Key("down_bytes") && Writer.Decimal(Value.DownBytes) &&
            Writer.Append(",") && Writer.Key("events") && Writer.Decimal(Value.Events) &&
            Writer.Append(",") && Writer.Key("errors") && Writer.Decimal(Value.Errors) &&
            Writer.Append(",") && Writer.Key("active") && AppendHistoryOptional(Writer, Value.Active) &&
            Writer.Append(",") && Writer.Key("p50_us") && AppendHistoryOptional(Writer, Value.Latency.Percentile(50U)) &&
            Writer.Append(",") && Writer.Key("p95_us") && AppendHistoryOptional(Writer, Value.Latency.Percentile(95U)) &&
            Writer.Append(",") && Writer.Key("p99_us") && AppendHistoryOptional(Writer, Value.Latency.Percentile(99U)) &&
            Writer.Append(",") && Writer.Key("sample_count") && Writer.Decimal(Value.Latency.Count()) &&
            Writer.Append(",") && Writer.Key("quality") && Writer.Append("{") &&
            Writer.Key("dropped") && Writer.Decimal(Value.Quality.Dropped) && Writer.Append(",") &&
            Writer.Key("aggregation_failures") && Writer.Decimal(Value.Quality.AggregationFailures) && Writer.Append(",") &&
            Writer.Key("range_exceeded") && Writer.Decimal(Value.Latency.RangeExceeded) && Writer.Append(",") &&
            Writer.Key("incomplete") && Writer.Boolean(Value.Quality.Incomplete) && Writer.Append("}}");
    }

    [[nodiscard]] inline auto AppendHistory(JsonWriter &Writer,
        const Preview::Statistics::HistoryResult &Value) -> bool
    {
        if (!Writer.Append("{") || !Writer.Key("sampled_at") || !AppendUtcTimestamp(Writer, Value.SampledAt) ||
            !Writer.Append(",") || !Writer.Key("from") || !AppendUtcTimestamp(Writer, Value.From) ||
            !Writer.Append(",") || !Writer.Key("to") || !AppendUtcTimestamp(Writer, Value.To) ||
            !Writer.Append(",") || !Writer.Key("resolution_ms") || !Writer.Decimal(Value.ResolutionMilliseconds) ||
            !Writer.Append(",") || !Writer.Key("coverage") || !Writer.String(Value.Coverage) ||
            !Writer.Append(",") || !Writer.Key("available") || !Writer.Boolean(Value.Available) ||
            !Writer.Append(",") || !Writer.Key("failure") || !Writer.String(Value.Failure) ||
            !Writer.Append(",") || !Writer.Key("gaps") || !Writer.Append("[")) return false;
        bool First = true;
        for (const auto &Gap : Value.Gaps)
        {
            if (!First && !Writer.Append(",")) return false;
            First = false;
            if (!Writer.Append("{") || !Writer.Key("from") || !AppendUtcTimestamp(Writer, Gap.From) ||
                !Writer.Append(",") || !Writer.Key("to") || !AppendUtcTimestamp(Writer, Gap.To) ||
                !Writer.Append(",") || !Writer.Key("reason") || !Writer.String(Gap.Reason) || !Writer.Append("}")) return false;
        }
        if (!Writer.Append("],") || !Writer.Key("items") || !Writer.Append("[")) return false;
        First = true;
        for (const auto &Item : Value.Items)
        {
            if (!First && !Writer.Append(",")) return false;
            First = false;
            if (!AppendHistoryRecord(Writer, Item)) return false;
        }
        return Writer.Append("]}");
    }
}
