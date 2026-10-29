import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { CapabilityNotice, EmptyState, FormatCount, FormatTime, Panel, QueryState } from '../Components/Ui';
import type { HistoryMetric, HistoryScope, HistorySnapshot } from '../Services/AdminDataSource';
import { HistoryChartPoints } from '../Api/Analysis';
import { TimeSeriesChart } from '../Components/TimeSeriesChart';
import { useAdminServices, useBootstrapIdentity } from './UseOperations';
import { useHistory, useTimeRange } from './TimeRange';

export function HistoryPanel(Input: Readonly<{
    Scope: HistoryScope; ResourceKey?: string; Kind?: 'traffic' | 'latency';
    Metric?: Exclude<HistoryMetric, 'traffic'>; Title?: string;
    ClassName?: string; Variant?: 'open' | 'banded'; Summary?: ReactNode;
}>): ReactNode {
    const Kind = Input.Kind ?? 'traffic';
    const Range = useTimeRange();
    const Services = useAdminServices();
    const Bootstrap = useBootstrapIdentity();
    const HasHistory = Services.Mode === 'demo' || Bootstrap.data?.Capabilities.includes('history.read') === true;
    const CanReadHistory = HasHistory && !Bootstrap.error;
    const CapabilityState: ReactNode = Services.Mode === 'demo' ? null
        : Bootstrap.error ? <CapabilityNotice Title="无法确认窗口历史能力" Detail="当前实例能力读取失败，未请求历史接口，也不显示旧数据冒充当前趋势。" Compact />
            : Bootstrap.isPending && !Bootstrap.data ? <CapabilityNotice Title="正在核对窗口历史能力" Detail="确认当前实例支持后才读取历史趋势。" Compact />
                : !HasHistory ? <CapabilityNotice Title="此实例未开放窗口历史" Detail="当前管理接口未提供历史查询；累计值不会被画成趋势。" Compact /> : null;
    const [ActiveSeries, SetActiveSeries] = useState<string | null>(null);
    const [PinnedSeries, SetPinnedSeries] = useState<string | null>(null);
    const EffectiveSeries = ActiveSeries ?? PinnedSeries;
    const Metric = Input.Metric ?? (Kind === 'latency' ? 'recognition_admission' : 'traffic');
    const Query = useHistory(Input.Scope, Input.ResourceKey ?? '', Metric, CanReadHistory);
    return <Panel Title={Input.Title ?? (Kind === 'latency' ? '识别准入延迟趋势' : '流量趋势')}
        ClassName={Input.ClassName ?? ''} {...(Input.Variant === undefined ? {} : { Variant: Input.Variant })}
        Subtitle={Kind === 'latency' ? `${LatencyLabel(Metric)} · 窗口分位值` : '有效载荷 · 同一窗口与覆盖范围'}
        Action={Query.data && !CapabilityState ? <HistoryLegend Kind={Kind} Active={EffectiveSeries}
            OnHover={SetActiveSeries} OnToggle={Value => SetPinnedSeries(Current => Current === Value ? null : Value)} /> : null}>
        {Input.Summary}
        {CapabilityState ?? (Range.InvalidReason ? <div className="notice notice-warning" role="alert"><strong>时间区间无法查询</strong><span>{Range.InvalidReason} 请在上方时间控件修正。</span></div>
            : <QueryState Pending={Query.isPending} Error={Query.error} HasData={Query.data !== undefined} Label="窗口历史"
                Children={Query.data ? <HistoryPlot Value={Query.data} Kind={Kind} ActiveSeries={EffectiveSeries} /> : null} />)}
    </Panel>;
}
export function HistoryPlot(Input: Readonly<{
    Value: HistorySnapshot; Kind: 'traffic' | 'latency'; ActiveSeries?: string | null;
}>): ReactNode {
    const Data = useMemo(() => HistoryChartPoints(Input.Value.Items, Input.Value.ResolutionMs, Input.Value.Gaps), [Input.Value.Items, Input.Value.ResolutionMs, Input.Value.Gaps]);
    const HasData = Data.some(Point => Input.Kind === 'latency' ? Point.P95 !== null : Point.Up !== null || Point.Down !== null);
    if (!HasData) return <EmptyState Title="这个区间尚无有效样本" Detail="缺测不会显示为零；更改时间范围或检查采集状态。" />;
    const Format = (Value: number): string => Input.Kind === 'traffic' ? ShortRate(Value, 1)
        : `${Value.toLocaleString('zh-CN', { maximumFractionDigits: 2 })} ms`;
    return <>{Input.Kind === 'latency' && <LatencyReadings Point={Data.at(-1)} />}
        <div className={`history-plot history-plot-${Input.Kind} w-full min-w-0 ${Input.Kind === 'latency' ? 'h-44' : 'h-52'}`} role="group" aria-label={Input.Kind === 'latency' ? '延迟窗口趋势，单位毫秒' : '流量窗口趋势，单位字节每秒'}>
            <TimeSeriesChart Points={Data} AriaLabel={Input.Kind === 'latency' ? '延迟窗口趋势' : '流量窗口趋势'}
                ActiveSeries={Input.ActiveSeries ?? null}
                FormatAxis={Value => Input.Kind === 'traffic' ? ShortAxisRate(Value) : Value.toLocaleString('zh-CN', { maximumSignificantDigits: 3 })}
                FormatTime={Time => FormatTime(new Date(Time).toISOString())}
                Series={Input.Kind === 'traffic' ? [
                    { Key: 'Down', Label: '下行', Color: 'var(--plot-line)', Value: Point => Point.Down, Format, Area: true },
                    { Key: 'Up', Label: '上行', Color: 'var(--plot-line-soft)', Value: Point => Point.Up, Format, Dash: '6 4' },
                ] : [
                    { Key: 'P95', Label: 'P95', Color: 'var(--plot-line)', Value: Point => Point.P95, Format, Area: true },
                    { Key: 'P99', Label: 'P99', Color: 'var(--plot-line-soft)', Value: Point => Point.P99, Format, Dash: '6 4' },
                    { Key: 'P50', Label: 'P50', Color: 'var(--plot-line-faint)', Value: Point => Point.P50, Format, Dash: '2 4' },
                ]} />
        </div>
        <div className="history-caption mt-2 flex flex-wrap justify-between gap-x-4 gap-y-1 border-t pt-2 text-xs leading-5 text-muted-foreground"><span>采样 {FormatTime(Input.Value.SampledAt)} · {Input.Value.Coverage}</span>
            <span>分辨率 {Number(Input.Value.ResolutionMs) / 1000}s{Input.Kind === 'latency' ? ` · ${FormatCount(Input.Value.Items.reduce((Sum, Item) => Sum + BigInt(Item.SampleCount), 0n).toString())} 个样本` : ''}</span></div>
        {Input.Value.Gaps.length > 0 && <div className="notice notice-warning" role="status">区间包含 {Input.Value.Gaps.length} 段缺测：{[...new Set(Input.Value.Gaps.map(Gap => Gap.Reason))].join('；')}</div>}
    </>;
}
function HistoryLegend(Input: Readonly<{
    Kind: 'traffic' | 'latency'; Active: string | null;
    OnHover: (Value: string | null) => void; OnToggle: (Value: string) => void;
}>): ReactNode {
    const Items = Input.Kind === 'traffic'
        ? [{ Key: 'Down', Label: '下行', Color: 'var(--plot-line)', Dash: false }, { Key: 'Up', Label: '上行', Color: 'var(--plot-line-soft)', Dash: true }]
        : [{ Key: 'P95', Label: 'P95', Color: 'var(--plot-line)', Dash: false }, { Key: 'P99', Label: 'P99', Color: 'var(--plot-line-soft)', Dash: true }, { Key: 'P50', Label: 'P50', Color: 'var(--plot-line-faint)', Dash: true }];
    return <ul className="history-series-legend flex flex-wrap items-center justify-end gap-1.5 text-xs" aria-label="图例">
        {Items.map(Item => <li className="inline-flex" key={Item.Key}>
            <button type="button" className={`history-series-button series-${Item.Key.toLowerCase()} inline-flex items-center gap-1.5 rounded px-1.5 py-1 text-muted-foreground hover:bg-muted hover:text-foreground`}
                data-active={Input.Active === null ? undefined : Input.Active === Item.Key} aria-pressed={Input.Active === Item.Key}
                onClick={() => Input.OnToggle(Item.Key)}
                onMouseEnter={() => Input.OnHover(Item.Key)} onMouseLeave={() => Input.OnHover(null)}
                onFocus={() => Input.OnHover(Item.Key)} onBlur={() => Input.OnHover(null)}>
                <span className={`history-series-line series-${Item.Key.toLowerCase()} inline-block w-3 border-t-2 ${Item.Dash ? 'border-dashed' : ''}`} style={{ borderTopColor: Item.Color }} aria-hidden="true" />{Item.Label}
            </button>
        </li>)}
    </ul>;
}
function LatencyReadings(Input: Readonly<{ Point: ReturnType<typeof HistoryChartPoints>[number] | undefined }>): ReactNode {
    const Point = Input.Point;
    const Rows = [{ Name: 'P50', Value: Point?.P50 ?? null, Color: 'var(--plot-line-faint)' }, { Name: 'P95', Value: Point?.P95 ?? null, Color: 'var(--plot-line)' }, { Name: 'P99', Value: Point?.P99 ?? null, Color: 'var(--plot-line-soft)' }];
    return <div className="latency-window mb-2"><dl className="latency-readings grid grid-cols-3 gap-2 rounded-md border bg-muted/20 px-3 py-2" aria-label="末次返回窗口的分位延迟">
        {Rows.map(Row => <div key={Row.Name} className={`latency-reading latency-${Row.Name.toLowerCase()} min-w-0`}>
            <dt className="flex items-center gap-1.5 text-xs text-muted-foreground"><span className="latency-series-key size-1.5 rounded-full" style={{ backgroundColor: Row.Color }} aria-hidden="true" />{Row.Name}</dt>
            <dd className="mt-0.5 whitespace-nowrap font-mono text-sm font-semibold tabular-nums">{Row.Value === null ? <span className="latency-unavailable text-muted-foreground">未采集</span> : <>{Row.Value.toLocaleString('zh-CN', { maximumFractionDigits: 2 })}<small className="ml-0.5 text-xs font-normal text-muted-foreground">ms</small></>}</dd>
        </div>)}
    </dl><p className="latency-window-time mt-1 text-xs text-muted-foreground">{Point ? `窗口 ${FormatTime(new Date(Point.Time).toISOString())} · ${FormatCount(Point.Samples)} 个样本` : '尚未返回窗口'}</p></div>;
}
function ShortRate(Value: number, Precision = 0): string { return Value >= 1048576 ? `${(Value / 1048576).toFixed(1)} MiB/s` : Value >= 1024 ? `${(Value / 1024).toFixed(Precision)} KiB/s` : `${Value.toFixed(Precision)} B/s`; }
function ShortAxisRate(Value: number): string { return ShortRate(Value); }
function LatencyLabel(Metric: HistoryMetric): string { return Metric === 'dns_resolution' ? 'DNS 解析' : Metric === 'tcp_connect' ? 'TCP 建连' : '识别准入'; }
