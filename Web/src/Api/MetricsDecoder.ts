import type { MetricsSnapshot, RecognitionLatency } from '../Services/AdminDataSource.ts';
import { DecodeTraffic } from './ResourceDecoders.ts';
import { Bool, Decimal, List, NullableDecimal, RecordValue, Text } from './Wire.ts';

/** @brief 识别延迟仅代表当前代次的准入阶段，分位数是微秒直方图桶下界。 */
function DecodeRecognitionLatency(Input: unknown, Generation: string): RecognitionLatency {
    const Value = RecordValue(Input);
    if (Value.sample_boundary !== 'recognition_admission' || Value.unit !== 'microseconds' || Decimal(Value.generation) !== Generation)
        throw new Error('识别延迟的范围或代次不符合合同');
    const Ready = Bool(Value.ready), Count = Decimal(Value.sample_count), Written = Decimal(Value.tracer_written);
    const Dropped = Decimal(Value.tracer_dropped), Exceeded = Decimal(Value.histogram_range_exceeded);
    const Recent = List(Value.recent_us).map(Decimal);
    const P50 = NullableDecimal(Value.p50_bucket_lower_bound_us), P95 = NullableDecimal(Value.p95_bucket_lower_bound_us);
    const P99 = NullableDecimal(Value.p99_bucket_lower_bound_us), Max = NullableDecimal(Value.max_observed_us);
    if (Ready !== (Count !== '0') || BigInt(Written) > BigInt(Count) || BigInt(Dropped) > BigInt(Count) ||
        BigInt(Exceeded) > BigInt(Count) || Recent.length > 8 || BigInt(Recent.length) > BigInt(Written))
        throw new Error('识别延迟的采样计数不符合合同');
    if (!Ready ? [P50, P95, P99, Max].some(Item => Item !== null) :
        P50 === null || P95 === null || P99 === null || Max === null ||
        BigInt(P50) > BigInt(P95) || BigInt(P95) > BigInt(P99) || BigInt(P99) > BigInt(Max) || Recent.some(Item => BigInt(Item) > BigInt(Max)))
        throw new Error('识别延迟的分布不符合合同');
    return { Boundary: 'recognition_admission', Unit: 'microseconds', GenerationId: Generation, Ready, SampleCount: Count,
        TracerWritten: Written, TracerDropped: Dropped, HistogramRangeExceeded: Exceeded, RecentUs: Recent,
        P50Us: P50, P95Us: P95, P99Us: P99, MaxObservedUs: Max };
}

/** @brief 解码公开 Metrics 快照；不把未提供的指标补成零。 */
export function DecodeMetrics(Input: unknown): MetricsSnapshot {
    const Value = RecordValue(Input), Observations = RecordValue(Value.observations);
    const Retirement = RecordValue(Observations.retirement_failures), Generation = Decimal(Value.generation);
    const Traffic = DecodeTraffic(Value.traffic);
    if (!Traffic) throw new Error('指标快照缺少进程流量');
    const History = List(Value.history).map(Item => {
        const Sample = RecordValue(Item), SampleTraffic = DecodeTraffic(Sample.traffic);
        if (!SampleTraffic) throw new Error('指标历史缺少流量');
        return { Time: Text(Sample.timestamp), Traffic: SampleTraffic };
    });
    const HistoryReady = Bool(Value.history_ready);
    if (HistoryReady !== (History.length > 0) || History.length > 1024) throw new Error('指标历史状态不符合合同');
    return { ProcessId: Decimal(Value.process), GenerationId: Generation, CheckedAt: Text(Value.checked_at), Traffic,
        Observations: { Accepted: Decimal(Observations.accepted), Consumed: Decimal(Observations.consumed),
            Dropped: Decimal(Observations.dropped), AggregationFailures: Decimal(Observations.aggregation_failures),
            RecognitionLatencyQueueDrops: Decimal(Observations.recognition_latency_queue_dropped),
            RecognitionLatencyAggregationFailures: Decimal(Observations.recognition_latency_aggregation_failures) },
        RetirementFailures: { Sessions: Decimal(Retirement.session), Streams: Decimal(Retirement.stream), Tasks: Decimal(Retirement.task) },
        SampleIntervalMs: Decimal(Value.sample_interval_ms), HistoryReady, History,
        RecognitionLatency: DecodeRecognitionLatency(Value.recognition_latency, Generation) };
}
