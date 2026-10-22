import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { EmptyState, FormatCount, FormatTime, Panel, QueryState } from '../Components/Ui';
import type { HistoryScope, HistorySnapshot } from '../Services/AdminDataSource';
import { HistoryChartPoints } from '../Api/Analysis';
import { TimeSeriesChart } from '../Components/TimeSeriesChart';
import { useHistory, useTimeRange } from './TimeRange';

export function HistoryPanel(Input: Readonly<{ Scope: HistoryScope; ResourceKey?: string; Kind?: 'traffic' | 'latency' | 'active'; Title?: string; ClassName?: string; Variant?: 'open' | 'banded' }>): ReactNode {
    const Kind = Input.Kind ?? 'traffic';
    const Range = useTimeRange();
    const [ActiveSeries, SetActiveSeries] = useState<string | null>(null);
    const [PinnedSeries, SetPinnedSeries] = useState<string | null>(null);
    const EffectiveSeries = ActiveSeries ?? PinnedSeries;
    const Query = useHistory(Input.Scope, Input.ResourceKey ?? '', Kind === 'latency' ? 'recognition_admission' : Kind === 'active' ? 'active' : 'traffic');
    return <Panel Title={Input.Title ?? (Kind === 'latency' ? '识别准入延迟趋势' : Kind === 'active' ? '活动量趋势' : '流量趋势')}
        ClassName={Input.ClassName ?? ''} {...(Input.Variant === undefined ? {} : { Variant: Input.Variant })}
        Subtitle={Kind === 'latency' ? '准入耗时 · 窗口分位值' : Kind === 'active' ? `${Input.Scope === 'worker' ? '活动任务' : '活动量'} · 窗口采样` : '有效载荷 · 同一窗口与覆盖范围'}
        Action={Query.data ? <HistoryLegend Kind={Kind} Active={EffectiveSeries}
            OnHover={SetActiveSeries} OnToggle={Value => SetPinnedSeries(Current => Current === Value ? null : Value)} /> : null}>
        {Range.InvalidReason ? <div className="notice notice-warning" role="alert"><strong>时间区间无法查询</strong><span>{Range.InvalidReason} 请在上方时间控件修正。</span></div>
            : <QueryState Pending={Query.isPending} Error={Query.error} HasData={Query.data !== undefined} Label="窗口历史"
                Children={Query.data ? <HistoryPlot Value={Query.data} Kind={Kind} ActiveSeries={EffectiveSeries} /> : null} />}
    </Panel>;
}
export function HistoryPlot(Input: Readonly<{
    Value: HistorySnapshot; Kind: 'traffic' | 'latency' | 'active'; ActiveSeries?: string | null;
}>): ReactNode {
    const Data = useMemo(() => HistoryChartPoints(Input.Value.Items, Input.Value.ResolutionMs, Input.Value.Gaps), [Input.Value.Items, Input.Value.ResolutionMs, Input.Value.Gaps]);
    const HasData = Data.some(Point => Input.Kind === 'latency' ? Point.P95 !== null : Input.Kind === 'active' ? Point.Active !== null : Point.Up !== null || Point.Down !== null);
    if (!HasData) return <EmptyState Title="这个区间尚无有效样本" Detail="缺测不会显示为零；更改时间范围或检查采集状态。" />;
    const Format = (Value: number): string => Input.Kind === 'traffic' ? ShortRate(Value, 1)
        : `${Value.toLocaleString('zh-CN', { maximumFractionDigits: 2 })}${Input.Kind === 'latency' ? ' ms' : ''}`;
    return <>{Input.Kind === 'latency' && <LatencyReadings Point={Data.at(-1)} />}
        <div className={`history-plot history-plot-${Input.Kind}`} role="img" aria-label={Input.Kind === 'latency' ? '准入延迟窗口趋势，单位毫秒' : Input.Kind === 'active' ? '活动量窗口趋势' : '流量窗口趋势，单位字节每秒'}>
            <TimeSeriesChart Points={Data} AriaLabel={Input.Kind === 'latency' ? '准入延迟窗口趋势' : Input.Kind === 'active' ? '活动量窗口趋势' : '流量窗口趋势'}
                ActiveSeries={Input.ActiveSeries ?? null}
                FormatAxis={Value => Input.Kind === 'traffic' ? ShortAxisRate(Value) : String(Math.round(Value))}
                FormatTime={Time => FormatTime(new Date(Time).toISOString())}
                Series={Input.Kind === 'traffic' ? [
                    { Key: 'Down', Label: '下行', Color: 'var(--plot-line)', Value: Point => Point.Down, Format, Area: true },
                    { Key: 'Up', Label: '上行', Color: 'var(--plot-line-soft)', Value: Point => Point.Up, Format },
                ] : Input.Kind === 'latency' ? [
                    { Key: 'P95', Label: 'P95', Color: 'var(--plot-line)', Value: Point => Point.P95, Format, Area: true },
                    { Key: 'P99', Label: 'P99', Color: 'var(--plot-line-soft)', Value: Point => Point.P99, Format },
                    { Key: 'P50', Label: 'P50', Color: 'var(--plot-line-faint)', Value: Point => Point.P50, Format },
                ] : [
                    { Key: 'Active', Label: '活动量', Color: 'var(--plot-line)', Value: Point => Point.Active, Format, Area: true },
                ]} />
        </div>
        <div className="history-caption"><span>采样 {FormatTime(Input.Value.SampledAt)} · {Input.Value.Coverage}</span>
            <span>分辨率 {Number(Input.Value.ResolutionMs) / 1000}s{Input.Kind === 'latency' ? ` · ${FormatCount(Input.Value.Items.reduce((Sum, Item) => Sum + BigInt(Item.SampleCount), 0n).toString())} 个样本` : ''}</span></div>
        {Input.Value.Gaps.length > 0 && <div className="notice notice-warning" role="status">区间包含 {Input.Value.Gaps.length} 段缺测：{[...new Set(Input.Value.Gaps.map(Gap => Gap.Reason))].join('；')}</div>}
    </>;
}
function HistoryLegend(Input: Readonly<{
    Kind: 'traffic' | 'latency' | 'active'; Active: string | null;
    OnHover: (Value: string | null) => void; OnToggle: (Value: string) => void;
}>): ReactNode {
    const Items = Input.Kind === 'traffic'
        ? [{ Key: 'Down', Label: '下行' }, { Key: 'Up', Label: '上行' }]
        : Input.Kind === 'latency'
            ? [{ Key: 'P95', Label: 'P95' }, { Key: 'P99', Label: 'P99' }, { Key: 'P50', Label: 'P50' }]
            : [{ Key: 'Active', Label: '活动量' }];
    return <ul className="history-series-legend" aria-label="图例">
        {Items.map(Item => <li key={Item.Key}>
            <button type="button" className={`history-series-button series-${Item.Key.toLowerCase()}`}
                data-active={Input.Active === Item.Key} aria-pressed={Input.Active === Item.Key}
                onClick={() => Input.OnToggle(Item.Key)}
                onMouseEnter={() => Input.OnHover(Item.Key)} onMouseLeave={() => Input.OnHover(null)}
                onFocus={() => Input.OnHover(Item.Key)} onBlur={() => Input.OnHover(null)}>
                <span className={`history-series-line series-${Item.Key.toLowerCase()}`} aria-hidden="true" />{Item.Label}
            </button>
        </li>)}
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
function ShortAxisRate(Value: number): string {
    if (Value >= 1048576) return `${(Value / 1048576).toFixed(1)}M`;
    if (Value >= 1024) return `${Math.round(Value / 1024)}K`;
    return `${Math.round(Value)}`;
}
