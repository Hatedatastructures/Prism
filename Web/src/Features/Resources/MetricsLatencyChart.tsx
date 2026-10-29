import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { TimeSeriesChart } from '../../Components/TimeSeriesChart';
import { FormatTime } from '../../Components/Ui';
import type { BootstrapSnapshot, MetricsSnapshot } from '../../Services/AdminDataSource';
import { AppendLatencyPoint } from './MetricsLatencyHistory';
import type { LatencyHistory, LatencyPoint } from './MetricsLatencyHistory';

const Series = [
    { Key: 'P50', Label: 'P50', Color: 'var(--plot-line)' },
    { Key: 'P95', Label: 'P95', Color: 'var(--plot-line-soft)', Dash: '6 4' },
    { Key: 'P99', Label: 'P99', Color: 'var(--plot-line-faint)', Dash: '2 4' },
] as const;

export function MetricsLatencyChart(Input: Readonly<{ Metrics: MetricsSnapshot; Identity: BootstrapSnapshot; Failed: boolean }>): ReactNode {
    const [History, SetHistory] = useState<LatencyHistory | null>(null);
    const Last = useRef<{ Scope: string; Time: number } | null>(null);
    const Gap = useRef(false);
    const Scope = JSON.stringify([Input.Identity.InstanceKey, Input.Identity.Incarnation, Input.Metrics.ProcessId, Input.Metrics.GenerationId]);
    useEffect(() => {
        if (Input.Failed) { Gap.current = true; return; }
        const Time = Date.parse(Input.Metrics.CheckedAt);
        if (!Number.isFinite(Time)) { Gap.current = true; return; }
        if (Last.current?.Scope === Scope && Last.current.Time === Time) return;
        Last.current = { Scope, Time };
        const HadGap = Gap.current;
        SetHistory(Previous => AppendLatencyPoint(Previous, Scope, Input.Metrics, HadGap));
        Gap.current = false;
    }, [Input.Metrics, Input.Failed, Scope]);
    const Current = History?.Scope === Scope ? History : null;
    const Format = (Value: number): string => `${Value.toLocaleString('zh-CN', { maximumFractionDigits: 0 })} µs`;
    const Lines = Series.map(Line => ({ ...Line, Value: (Point: LatencyPoint) => Point[Line.Key], Format }));
    return <section className="min-w-0 rounded-md border px-3 py-2"><div className="flex flex-wrap items-baseline justify-between gap-2"><h3 className="text-sm font-semibold">识别准入延迟趋势</h3><p className="text-xs text-muted-foreground">本页最近 {Current?.Samples ?? 0} 次采样 · 累计分位桶下界 · µs</p></div>
        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground" aria-label="延迟趋势图例">{Series.map(Line => <span key={Line.Key} className="inline-flex items-center gap-1.5"><span className="inline-block w-4 border-t-2" style={{ borderColor: Line.Color, borderTopStyle: 'Dash' in Line ? 'dashed' : 'solid' }} aria-hidden="true" />{Line.Label}</span>)}</div>
        {!Input.Metrics.RecognitionLatency.Ready ? <p className="py-8 text-center text-sm text-muted-foreground">当前代次还没有识别准入样本。</p> : (Current?.Samples ?? 0) < 2 ? <p className="py-8 text-center text-sm text-muted-foreground">等待第二个指标快照后绘制曲线。</p> : <div className="mt-1 h-44 min-w-0"><TimeSeriesChart Points={Current!.Points} Series={Lines} AriaLabel="识别准入累计延迟分位桶下界，单位微秒" FormatTime={Value => FormatTime(new Date(Value).toISOString())} FormatAxis={Format} /></div>}
        <p className="text-xs text-muted-foreground">只展示本页打开期间同一实例和代次的快照；断线和长间隔断开，未提供样本时间的近期读数不被拼成曲线。</p></section>;
}
