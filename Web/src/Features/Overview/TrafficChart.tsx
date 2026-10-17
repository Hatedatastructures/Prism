import { TimeLink as Link } from '../TimeLink';
import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { Area, AreaChart, Brush, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

import { CalendarDays } from 'lucide-react';
import { EmptyState, FormatBytes, FormatCount, FormatRate, FormatTime, Panel } from '../../Components/Ui';
import { SelectField } from '../../Components/SelectField';
import type { OverviewSnapshot, TrafficSample } from '../../Services/AdminDataSource';

export type SamplePoint = Readonly<{ Time: string; Up: number | null; Down: number | null }>;
const Ranges = [
    { Value: '30', Label: '最近 30 秒' }, { Value: '60', Label: '最近 1 分钟' }, { Value: 'all', Label: '全部采样' },
] as const;
type SampleSelection = Readonly<{ Start: number; End: number }>;

/** @brief 速率仅来自有效累计计数差；无效采样和计数回退保留为空，图表不连接缺口。 */
export function BuildTrafficSeries(History: readonly TrafficSample[]): SamplePoint[] {
    return History.slice(1).map((Sample, Index) => {
        const Previous = History[Index];
        if (!Previous) return { Time: Sample.Time, Up: null, Down: null };
        const Seconds = (Date.parse(Sample.Time) - Date.parse(Previous.Time)) / 1000;
        return { Time: Sample.Time, Up: CounterRate(Previous.Traffic.Up, Sample.Traffic.Up, Seconds),
            Down: CounterRate(Previous.Traffic.Down, Sample.Traffic.Down, Seconds) };
    });
}

function CounterRate(Previous: string | number, Current: string | number, Seconds: number): number | null {
    if (!Number.isFinite(Seconds) || Seconds <= 0) return null;
    try {
        const Difference = BigInt(Current) - BigInt(Previous);
        return Difference < 0n ? null : Number(Difference) / Seconds;
    } catch { return null; }
}

export function TrafficPanel(Input: Readonly<{ Snapshot: OverviewSnapshot }>): ReactNode {
    const [Range, SetRange] = useState('60');
    const [Selection, SetSelection] = useState<SampleSelection | null>(null);
    const [RangeOpen, SetRangeOpen] = useState(false);
    const Points = useMemo(() => BuildTrafficSeries(Input.Snapshot.History), [Input.Snapshot.History]);
    const LastTime = Date.parse(Points.at(-1)?.Time ?? '');
    const Visible = useMemo(() => Range === 'all' ? Points
        : Points.filter(Point => Date.parse(Point.Time) >= LastTime - Number(Range) * 1000), [Points, Range, LastTime]);
    const Selected = Selection ?? { Start: 0, End: Math.max(1, Visible.length - 1) };
    const ChartPoints = Visible.slice(Selected.Start, Selected.End + 1);
    function ChangeRange(Value: string): void { SetRange(Value); SetSelection(null); }
    const Interval = FormatCount(Input.Snapshot.SampleIntervalMs);
    return <Panel ClassName="traffic-panel" Title="流量趋势"
        Action={<div className="traffic-controls" title={`采样间隔 ${Interval} ms`}>
            <div className="chart-legend"><span><i className="legend-dot legend-down" />下行</span><span><i className="legend-dot legend-up" />上行</span></div>
            <SelectField Label="流量图时间范围" Value={Range} Options={Ranges} OnChange={ChangeRange} />
            {Visible.length >= 2 && <details className="chart-range-detail" onToggle={Event => SetRangeOpen(Event.currentTarget.open)}
                onKeyDown={Event => { if (Event.key === 'Escape') { Event.currentTarget.open = false; Event.currentTarget.querySelector('summary')?.focus(); } }}>
                <summary><CalendarDays size={15} />选择采样区间<span className="sr-only">{ChartPoints.length} 个采样点</span></summary>
                {RangeOpen && <div className="chart-range-popover"><RangeChart Points={Visible} Selection={Selected} OnChange={SetSelection} />
                    <small>已选 {ChartPoints.length} 个采样点</small></div>}
            </details>}
        </div>}>
        {Visible.length < 2 ? <EmptyState Title="流量样本不足" Detail="至少需要两个有效采样点才能计算速率。" /> : <>
            <div className="traffic-chart" role="group" aria-label="流量趋势。聚焦图表后可使用左右方向键查看采样点。">
                <ResponsiveContainer width="100%" height="100%" minWidth={0}>
                    <AreaChart data={ChartPoints} margin={{ top: 12, right: 8, bottom: 0, left: 0 }} accessibilityLayer>
                        <defs><linearGradient id="traffic-down" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="var(--chart-down)" stopOpacity={.2} /><stop offset="100%" stopColor="var(--chart-down)" stopOpacity={.02} />
                        </linearGradient><linearGradient id="traffic-up" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="var(--chart-up)" stopOpacity={.12} /><stop offset="100%" stopColor="var(--chart-up)" stopOpacity={0} />
                        </linearGradient></defs>
                        <CartesianGrid vertical={false} stroke="var(--line)" strokeDasharray="3 4" />
                        <XAxis dataKey="Time" tickFormatter={Value => FormatTime(String(Value))} axisLine={false} tickLine={false} minTickGap={40}
                            tick={{ fill: 'var(--muted)', fontSize: 12 }} dy={4} height={26} />
                        <YAxis tickFormatter={AxisRate} axisLine={false} tickLine={false} width={70} tickCount={4}
                            tick={{ fill: 'var(--muted)', fontSize: 12 }} />
                        <Tooltip content={<TrafficTooltip />} cursor={{ stroke: 'var(--muted-light)', strokeDasharray: '3 3' }} isAnimationActive={false} />
                        <Area type="monotone" dataKey="Down" name="下行" stroke="var(--chart-down)" fill="url(#traffic-down)" strokeWidth={2}
                            connectNulls={false} isAnimationActive={false} activeDot={{ r: 4, strokeWidth: 3, stroke: 'var(--surface)' }} />
                        <Area type="monotone" dataKey="Up" name="上行" stroke="var(--chart-up)" fill="url(#traffic-up)" strokeWidth={2}
                            connectNulls={false} isAnimationActive={false} activeDot={{ r: 4, strokeWidth: 3, stroke: 'var(--surface)' }} />
                    </AreaChart>
                </ResponsiveContainer>
            </div>
        </>}
        <div className="dashboard-protocols" aria-label="协议会话与绑定"><span>协议会话</span>
            {Input.Snapshot.Protocols.map(Protocol => <Link key={Protocol.Id}
                to={'/sessions?protocol=' + encodeURIComponent(Protocol.Name)}
                title={`${Protocol.Coverage} · ${FormatCount(Protocol.ConfiguredBindings)} 个绑定`}>
                {Protocol.Name}<strong>{Protocol.ActiveSessions === null ? '—' : FormatCount(Protocol.ActiveSessions)}</strong>
            </Link>)}
        </div>
    </Panel>;
}

function AxisRate(Value: number): string { return Value === 0 ? '0' : `${FormatBytes(Math.round(Value)).replace(' ', '')}/s`; }

function TrafficTooltip(Input: Readonly<{
    active?: boolean; label?: unknown;
    payload?: readonly Readonly<{ name?: string | number; value?: string | number | readonly (string | number)[]; color?: string }>[];
}>): ReactNode {
    if (!Input.active || !Input.payload?.length) return null;
    return <div className="traffic-tooltip"><time>{typeof Input.label === 'string' ? FormatTime(Input.label) : ''}</time>
        {Input.payload.map(Item => <div key={String(Item.name)}><span><i style={{ background: Item.color }} />{Item.name}</span>
            <strong>{typeof Item.value === 'number' ? FormatRate(Math.round(Item.value)) : '未提供'}</strong></div>)}
    </div>;
}

/** @brief 区间状态只保存在图表 owner 中，拖动不会改写原始累计采样。 */
function RangeChart(Input: Readonly<{
    Points: readonly SamplePoint[]; Selection: SampleSelection; OnChange: (Value: SampleSelection) => void;
}>): ReactNode {
    const Selection = Input.Selection;
    return <div className="range-chart"><p>{FormatTime(Input.Points[Selection.Start]?.Time)} — {FormatTime(Input.Points[Selection.End]?.Time)}</p>
        <ResponsiveContainer width="100%" height={76} minWidth={0}><AreaChart data={Input.Points}>
            <Area dataKey="Down" stroke="var(--chart-down)" fill="var(--mint-soft)" isAnimationActive={false} />
            <Brush dataKey="Time" tickFormatter={Value => FormatTime(String(Value))} height={26} stroke="var(--chart-down)" fill="var(--surface)"
                startIndex={Selection.Start} endIndex={Selection.End} onChange={Range => {
                    if (Range.startIndex !== undefined && Range.endIndex !== undefined) Input.OnChange({ Start: Range.startIndex, End: Range.endIndex });
                }} />
        </AreaChart></ResponsiveContainer>
    </div>;
}
