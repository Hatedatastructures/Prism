import { useMemo } from 'react';
import type { ReactNode } from 'react';
import { Area, AreaChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { EmptyState, FormatCount, FormatTime, Panel, QueryState } from '../Components/Ui';
import type { HistoryScope, HistorySnapshot } from '../Services/AdminDataSource';
import { HistoryChartPoints } from '../Api/Analysis';
import { useHistory, useTimeRange } from './TimeRange';

export function HistoryPanel(Input: Readonly<{ Scope: HistoryScope; ResourceKey?: string; Kind?: 'traffic' | 'latency' | 'active'; Title?: string; ClassName?: string; Variant?: 'open' | 'banded' }>): ReactNode {
    const Kind = Input.Kind ?? 'traffic';
    const Range = useTimeRange();
    const Query = useHistory(Input.Scope, Input.ResourceKey ?? '', Kind === 'latency' ? 'recognition_admission' : Kind === 'active' ? 'active' : 'traffic');
    return <Panel Title={Input.Title ?? (Kind === 'latency' ? '识别准入延迟趋势' : Kind === 'active' ? '活动量趋势' : '流量趋势')}
        ClassName={Input.ClassName ?? ''} {...(Input.Variant === undefined ? {} : { Variant: Input.Variant })}
        Subtitle={Kind === 'latency' ? '准入耗时 · 窗口分位值' : Kind === 'active' ? `${Input.Scope === 'worker' ? '活动任务' : '活动量'} · 窗口采样` : '有效载荷 · 同一窗口与覆盖范围'}
        Action={Query.data && Kind !== 'latency' ? <HistoryLegend Kind={Kind} /> : null}>
        {Range.InvalidReason ? <div className="notice notice-warning" role="alert"><strong>时间区间无法查询</strong><span>{Range.InvalidReason} 请在上方时间控件修正。</span></div>
            : <QueryState Pending={Query.isPending} Error={Query.error} HasData={Query.data !== undefined} Label="窗口历史" Children={Query.data ? <HistoryPlot Value={Query.data} Kind={Kind} /> : null} />}
    </Panel>;
}
export function HistoryPlot(Input: Readonly<{ Value: HistorySnapshot; Kind: 'traffic' | 'latency' | 'active' }>): ReactNode {
    const Data = useMemo(() => HistoryChartPoints(Input.Value.Items, Input.Value.ResolutionMs, Input.Value.Gaps), [Input.Value.Items, Input.Value.ResolutionMs, Input.Value.Gaps]);
    const HasData = Data.some(Point => Input.Kind === 'latency' ? Point.P95 !== null : Input.Kind === 'active' ? Point.Active !== null : Point.Up !== null || Point.Down !== null);
    if (!HasData) return <EmptyState Title="这个区间尚无有效样本" Detail="缺测不会显示为零；更改时间范围或检查采集状态。" />;
    function TooltipValue(Value: unknown): string {
        if (typeof Value !== 'number' || !Number.isFinite(Value)) return '未采集';
        if (Input.Kind === 'traffic') return ShortRate(Value, 1);
        return `${Value.toLocaleString('zh-CN', { maximumFractionDigits: 2 })}${Input.Kind === 'latency' ? ' ms' : ''}`;
    }
    const Axis = <><CartesianGrid stroke="var(--line)" strokeDasharray="2 5" vertical={false} />
        <XAxis dataKey="Time" type="number" domain={['dataMin', 'dataMax']} scale="time" tickFormatter={Value => FormatTime(new Date(Number(Value)).toISOString())} interval="preserveStartEnd" minTickGap={40} tickLine={false} axisLine={false} tickMargin={10} tick={{ fill: 'var(--muted)', fontSize: 13 }} />
        <YAxis tick={{ fill: 'var(--muted)', fontSize: 13 }} tickLine={false} axisLine={false} width={Input.Kind === 'latency' ? 36 : 76} tickMargin={8} tickFormatter={Value => Input.Kind === 'traffic' ? ShortRate(Number(Value)) : String(Value)} />
        <Tooltip contentStyle={{ background: 'var(--surface)', border: '1px solid var(--line)', borderRadius: 10, fontSize: 13 }}
            formatter={(Value, Name) => [TooltipValue(Value), String(Name ?? '').replace(/ (B\/s|ms)$/, '')]}
            labelFormatter={Value => FormatTime(new Date(Number(Value)).toISOString(), true)} /></>;
    return <>{Input.Kind === 'latency' && <LatencyReadings Point={Data.at(-1)} />}
        <div className={`history-plot${Input.Kind === 'latency' ? ' history-plot-latency' : ''}`} role="img" aria-label={Input.Kind === 'latency' ? '准入延迟窗口趋势，单位毫秒' : Input.Kind === 'active' ? '活动量窗口趋势' : '流量窗口趋势，单位字节每秒'}>
        <ResponsiveContainer width="100%" height="100%">
            {Input.Kind === 'traffic' ? <AreaChart data={Data} syncId="operations-time" syncMethod="value" margin={{ top: 8, right: 36, left: 0, bottom: 0 }}>{Axis}
                <Area dataKey="Down" name="下行 B/s" stroke="var(--chart-down)" fill="var(--chart-down)" fillOpacity={.07} strokeWidth={2.5} type="linear" isAnimationActive={false} connectNulls={false} />
                <Area dataKey="Up" name="上行 B/s" stroke="var(--chart-up)" strokeDasharray="5 4" fill="var(--chart-up)" fillOpacity={0} strokeWidth={2} type="linear" isAnimationActive={false} connectNulls={false} />
            </AreaChart> : <LineChart data={Data} syncId="operations-time" syncMethod="value" margin={{ top: 8, right: 36, left: 0, bottom: 0 }}>{Axis}
                {Input.Kind === 'latency' ? <><Line dataKey="P50" name="P50 ms" stroke="var(--muted-light)" strokeWidth={1.5} dot={false} isAnimationActive={false} connectNulls={false} />
                    <Line dataKey="P95" name="P95 ms" stroke="var(--chart-down)" strokeWidth={2.5} dot={false} isAnimationActive={false} connectNulls={false} />
                    <Line dataKey="P99" name="P99 ms" stroke="var(--amber)" strokeDasharray="4 4" strokeWidth={1.5} dot={false} isAnimationActive={false} connectNulls={false} /></>
                    : <Line dataKey="Active" name="活动量" stroke="var(--chart-down)" strokeWidth={2} dot={false} isAnimationActive={false} connectNulls={false} />}
            </LineChart>}
        </ResponsiveContainer></div>
        <div className="history-caption"><span>分辨率 {Number(Input.Value.ResolutionMs) / 1000}s · {Input.Value.Coverage}</span>
            <span>采样 {FormatTime(Input.Value.SampledAt)}{Input.Kind === 'latency' ? ` · 区间 ${FormatCount(Input.Value.Items.reduce((Sum, Item) => Sum + BigInt(Item.SampleCount), 0n).toString())} 个样本` : ''}</span></div>
        {Input.Value.Gaps.length > 0 && <div className="notice notice-warning" role="status">区间包含 {Input.Value.Gaps.length} 段缺测：{[...new Set(Input.Value.Gaps.map(Gap => Gap.Reason))].join('；')}</div>}
    </>;
}
function HistoryLegend(Input: Readonly<{ Kind: 'traffic' | 'active' }>): ReactNode {
    return <ul className="history-series-legend" aria-label="图例">
        <li><span className="history-series-line series-down" aria-hidden="true" />{Input.Kind === 'traffic' ? '下行' : '活动量'}</li>
        {Input.Kind === 'traffic' && <li><span className="history-series-line series-up" aria-hidden="true" />上行</li>}
    </ul>;
}
function LatencyReadings(Input: Readonly<{ Point: ReturnType<typeof HistoryChartPoints>[number] | undefined }>): ReactNode {
    const Point = Input.Point;
    const Rows = [{ Name: 'P50', Value: Point?.P50 ?? null }, { Name: 'P95', Value: Point?.P95 ?? null }, { Name: 'P99', Value: Point?.P99 ?? null }];
    return <div className="latency-window"><dl className="latency-readings" aria-label="末次返回窗口的分位延迟">
        {Rows.map(Row => <div key={Row.Name} className={`latency-reading latency-${Row.Name.toLowerCase()}`}>
            <dt><span className="latency-series-key" aria-hidden="true" />{Row.Name}</dt>
            <dd>{Row.Value === null ? <span className="latency-unavailable">未采集</span> : <>{Row.Value.toLocaleString('zh-CN', { maximumFractionDigits: 2 })}<small>ms</small></>}</dd>
        </div>)}
    </dl><p className="latency-window-time">{Point ? `窗口 ${FormatTime(new Date(Point.Time).toISOString())} · ${FormatCount(Point.Samples)} 个样本` : '尚未返回窗口'}</p></div>;
}
function ShortRate(Value: number, Precision = 0): string { return Value >= 1048576 ? `${(Value / 1048576).toFixed(1)} MiB/s` : Value >= 1024 ? `${(Value / 1024).toFixed(Precision)} KiB/s` : `${Value.toFixed(Precision)} B/s`; }
