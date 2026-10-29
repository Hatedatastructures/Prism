import type { MetricsSnapshot, UInt64Value } from '../../Services/AdminDataSource.ts';

export type LatencyPoint = Readonly<{ Time: number; P50: number | null; P95: number | null; P99: number | null }>;
export type LatencyHistory = Readonly<{ Scope: string; LastTime: number; Samples: number; SampleTimes: readonly number[]; Points: readonly LatencyPoint[] }>;

function ChartValue(Value: UInt64Value | null): number | null {
    if (Value === null) return null;
    const Numeric = Number(Value);
    return Number.isSafeInteger(Numeric) && Numeric >= 0 ? Numeric : null;
}

/** @brief 保留同一进程实例和代次内的真实采样；中断或长间隔保留曲线缺口。 */
export function AppendLatencyPoint(Previous: LatencyHistory | null, Scope: string, Metrics: MetricsSnapshot, Gap: boolean): LatencyHistory | null {
    const Time = Date.parse(Metrics.CheckedAt);
    if (!Number.isFinite(Time)) return Previous;
    const SameScope = Previous?.Scope === Scope;
    if (SameScope && Time === Previous.LastTime) return Previous;
    const Reset = !SameScope || Time < Previous.LastTime;
    const Before = Reset ? null : Previous;
    const Points = [...(Before?.Points ?? [])];
    if (Before && (Gap || Time - Before.LastTime > 15_000))
        Points.push({ Time: Before.LastTime + (Time - Before.LastTime) / 2, P50: null, P95: null, P99: null });
    const Latency = Metrics.RecognitionLatency;
    Points.push({ Time, P50: ChartValue(Latency.P50Us), P95: ChartValue(Latency.P95Us), P99: ChartValue(Latency.P99Us) });
    const SampleTimes = [...(Before?.SampleTimes ?? []), Time].slice(-60);
    return { Scope, LastTime: Time, Samples: SampleTimes.length, SampleTimes, Points: Points.filter(Point => Point.Time >= SampleTimes[0]!) };
}
