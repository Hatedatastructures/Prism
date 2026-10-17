/** @file MetricsJson.hpp @brief 真实采样与观察计数的有界 JSON 序列化。 */
#pragma once

#include <Preview/Operations/Http/JsonWriter.hpp>
#include <Preview/Operations/Metrics.hpp>
#include <Preview/Operations/Routes/TrafficJson.hpp>
#include <Preview/Operations/Routes/JsonPrimitives.hpp>

#include <optional>
#include <vector>

namespace Preview::Operations::HttpDetail
{
    /** @brief 只序列化 owner 交付的实际历史；不会补零、插值或生成占位点。 */
    [[nodiscard]] inline auto AppendHistory(
        JsonWriter& Writer, const std::vector<Preview::Statistics::TrafficSample>& Samples) -> bool
    {
        if (Samples.size() > Preview::Statistics::TrafficHistory::Capacity || !Writer.Append("["))
            return false;
        bool First = true;
        for (const auto& Sample : Samples)
        {
            if (!First && !Writer.Append(",")) return false;
            First = false;
            if (!Writer.Append("{") || !Writer.Key("timestamp") ||
                !AppendUtcTimestamp(Writer, Sample.Timestamp) || !Writer.Append(",") ||
                !Writer.Key("traffic") || !AppendTraffic(Writer, Sample.Value) || !Writer.Append("}"))
                return false;
        }
        return Writer.Append("]");
    }

    /** @brief 分别呈现入队、聚合、丢弃与退休失败，不能把观察失败计入业务 Errors。 */
    [[nodiscard]] inline auto AppendObservations(JsonWriter& Writer, const MetricsSnapshot& Value) -> bool
    {
        return Writer.Append("{") && Writer.Key("accepted") && Writer.Decimal(Value.AcceptedObservations) &&
            Writer.Append(",") && Writer.Key("consumed") && Writer.Decimal(Value.ConsumedObservations) &&
            Writer.Append(",") && Writer.Key("dropped") && Writer.Decimal(Value.DroppedObservations) &&
            Writer.Append(",") && Writer.Key("aggregation_failures") && Writer.Decimal(Value.AggregationFailures) &&
            Writer.Append(",") && Writer.Key("recognition_latency_queue_dropped") &&
            Writer.Decimal(Value.RecognitionLatencyQueueDrops) &&
            Writer.Append(",") && Writer.Key("recognition_latency_aggregation_failures") &&
            Writer.Decimal(Value.RecognitionLatencyAggregationFailures) &&
            Writer.Append(",") && Writer.Key("retirement_failures") && Writer.Append("{") &&
            Writer.Key("session") && Writer.Decimal(Value.RetirementFailures.Session) &&
            Writer.Append(",") && Writer.Key("stream") && Writer.Decimal(Value.RetirementFailures.Stream) &&
            Writer.Append(",") && Writer.Key("task") && Writer.Decimal(Value.RetirementFailures.Task) &&
            Writer.Append("}}");
    }

    /** @brief 无样本时明确输出 JSON null，不用零值冒充实际分位数。 */
    [[nodiscard]] inline auto AppendOptionalMicroseconds(
        JsonWriter &Writer,
        const std::optional<std::uint64_t> Value) -> bool
    {
        if (Value)
        {
            return Writer.Decimal(*Value);
        }
        return Writer.Null();
    }

    /** @brief 写入指定代次真实样本、近似分位数和已发布的近期值。 */
    [[nodiscard]] inline auto AppendRecognitionLatency(
        JsonWriter &Writer,
        const Preview::Statistics::RecognitionLatencySnapshot &Value) -> bool
    {
        if (Value.RecentCount > Value.RecentMicroseconds.size() ||
            !Writer.Append("{") || !Writer.Key("sample_boundary") ||
            !Writer.String("recognition_admission") || !Writer.Append(",") ||
            !Writer.Key("unit") || !Writer.String("microseconds") ||
            !Writer.Append(",") || !Writer.Key("generation") ||
            !Writer.Decimal(Value.Generation.Value()) || !Writer.Append(",") ||
            !Writer.Key("ready") || !Writer.Boolean(Value.SampleCount != 0U) ||
            !Writer.Append(",") || !Writer.Key("sample_count") ||
            !Writer.Decimal(Value.SampleCount) || !Writer.Append(",") ||
            !Writer.Key("tracer_written") || !Writer.Decimal(Value.TracerWrittenCount) ||
            !Writer.Append(",") || !Writer.Key("tracer_dropped") ||
            !Writer.Decimal(Value.TracerDroppedCount) || !Writer.Append(",") ||
            !Writer.Key("histogram_range_exceeded") ||
            !Writer.Decimal(Value.HistogramRangeExceeded) || !Writer.Append(",") ||
            !Writer.Key("recent_us") || !Writer.Append("["))
        {
            return false;
        }
        for (std::size_t Index = 0; Index < Value.RecentCount; ++Index)
        {
            if ((Index != 0U && !Writer.Append(",")) ||
                !Writer.Decimal(Value.RecentMicroseconds[Index]))
            {
                return false;
            }
        }
        return Writer.Append("]") && Writer.Append(",") &&
            Writer.Key("p50_bucket_lower_bound_us") &&
            AppendOptionalMicroseconds(Writer, Value.P50BucketLowerBoundMicroseconds) &&
            Writer.Append(",") && Writer.Key("p95_bucket_lower_bound_us") &&
            AppendOptionalMicroseconds(Writer, Value.P95BucketLowerBoundMicroseconds) &&
            Writer.Append(",") && Writer.Key("p99_bucket_lower_bound_us") &&
            AppendOptionalMicroseconds(Writer, Value.P99BucketLowerBoundMicroseconds) &&
            Writer.Append(",") && Writer.Key("max_observed_us") &&
            AppendOptionalMicroseconds(Writer, Value.MaximumObservedMicroseconds) &&
            Writer.Append("}");
    }

    /** @brief 拒绝跨代、虚构无样本分位数或超出真实样本边界的快照。 */
    [[nodiscard]] inline auto IsValidRecognitionLatency(
        const Preview::Statistics::RecognitionLatencySnapshot &Value,
        const Preview::GenerationId Generation) noexcept -> bool
    {
        if (Value.Generation != Generation ||
            Value.RecentCount > Value.RecentMicroseconds.size() ||
            Value.TracerWrittenCount > Value.SampleCount ||
            Value.TracerDroppedCount > Value.SampleCount ||
            Value.HistogramRangeExceeded > Value.SampleCount)
        {
            return false;
        }
        if (Value.SampleCount == 0U)
        {
            return Value.TracerWrittenCount == 0U && Value.TracerDroppedCount == 0U &&
                Value.HistogramRangeExceeded == 0U && Value.RecentCount == 0U &&
                !Value.P50BucketLowerBoundMicroseconds &&
                !Value.P95BucketLowerBoundMicroseconds &&
                !Value.P99BucketLowerBoundMicroseconds &&
                !Value.MaximumObservedMicroseconds;
        }
        if (!Value.P50BucketLowerBoundMicroseconds ||
            !Value.P95BucketLowerBoundMicroseconds ||
            !Value.P99BucketLowerBoundMicroseconds ||
            !Value.MaximumObservedMicroseconds ||
            Value.RecentCount > Value.TracerWrittenCount ||
            *Value.P50BucketLowerBoundMicroseconds > *Value.P95BucketLowerBoundMicroseconds ||
            *Value.P95BucketLowerBoundMicroseconds > *Value.P99BucketLowerBoundMicroseconds ||
            *Value.P99BucketLowerBoundMicroseconds > *Value.MaximumObservedMicroseconds)
        {
            return false;
        }
        for (std::size_t Index = 0; Index < Value.RecentCount; ++Index)
        {
            if (Value.RecentMicroseconds[Index] > *Value.MaximumObservedMicroseconds)
            {
                return false;
            }
        }
        return true;
    }

    /** @brief 值快照输出，不保存输入引用；空历史明确 history_ready=false。 */
    [[nodiscard]] inline auto AppendMetrics(JsonWriter& Writer, const MetricsSnapshot& Value) -> bool
    {
        if (!IsValidRecognitionLatency(Value.RecognitionLatency, Value.Generation))
        {
            return false;
        }
        return Writer.Append("{") && Writer.Key("process") && Writer.Decimal(Value.Process.Value()) &&
            Writer.Append(",") && Writer.Key("generation") && Writer.Decimal(Value.Generation.Value()) &&
            Writer.Append(",") && Writer.Key("checked_at") && AppendUtcTimestamp(Writer, Value.CheckedAt) &&
            Writer.Append(",") && Writer.Key("traffic") && AppendTraffic(Writer, Value.Traffic) &&
            Writer.Append(",") && Writer.Key("observations") && AppendObservations(Writer, Value) &&
            Writer.Append(",") && Writer.Key("sample_interval_ms") && Writer.Decimal(Value.SampleIntervalMilliseconds) &&
            Writer.Append(",") && Writer.Key("history_ready") && Writer.Boolean(!Value.History.empty()) &&
            Writer.Append(",") && Writer.Key("history") && AppendHistory(Writer, Value.History) &&
            Writer.Append(",") && Writer.Key("recognition_latency") &&
            AppendRecognitionLatency(Writer, Value.RecognitionLatency) && Writer.Append("}");
    }
}
