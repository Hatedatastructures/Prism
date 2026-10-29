import { useMemo } from 'react';
import type { ReactNode } from 'react';
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/ui/card';
import { FormatRate, FormatTime } from '../../Components/Ui';
import type { TrafficSample } from '../../Services/AdminDataSource';
import { BuildTrafficSeries } from './TrafficChart';

/** @brief 按累计计数的相邻采样展示速率，缺失和回退保持断线。 */
export function OverviewChart(Input: Readonly<{ History: readonly TrafficSample[]; ClassName?: string }>): ReactNode {
    const Points = useMemo(() => BuildTrafficSeries(Input.History), [Input.History]);
    const HasValues = Points.some(Point => Point.Up !== null || Point.Down !== null);
    return <Card className={`min-w-0 ${Input.ClassName ?? ''}`}>
        <CardHeader className="px-5"><CardTitle>流量趋势</CardTitle><CardDescription>根据相邻累计采样计算的上行与下行速率</CardDescription></CardHeader>
        <CardContent className="px-5">
            {HasValues ? <>
                <div className="flex flex-wrap gap-5 pb-3 text-xs text-muted-foreground" aria-label="图例">
                    <span className="flex items-center gap-2"><span className="h-0.5 w-4 bg-[var(--chart-down)]" />下行</span>
                    <span className="flex items-center gap-2"><span className="h-0.5 w-4 bg-[var(--chart-up)]" />上行</span>
                </div>
                <div className="h-48 min-w-0" role="img" aria-label="历史流量速率图，显示下行及上行采样">
                    <ResponsiveContainer width="100%" height="100%"><LineChart data={Points} margin={{ top: 8, right: 8, left: 4, bottom: 0 }}>
                        <CartesianGrid stroke="var(--chart-grid)" strokeDasharray="3 3" vertical={false} />
                        <XAxis dataKey="Time" tickFormatter={Value => FormatTime(String(Value))} tick={{ fill: 'var(--plot-axis)', fontSize: 11 }} tickLine={false} axisLine={false} minTickGap={28} />
                        <YAxis width={90} tickFormatter={Value => FormatRate(Math.round(Number(Value)))} tick={{ fill: 'var(--plot-axis)', fontSize: 11 }} tickLine={false} axisLine={false} />
                        <Tooltip labelFormatter={Value => FormatTime(String(Value), true)} formatter={(Value, Name) => [typeof Value === 'number' ? FormatRate(Math.round(Value)) : '—', Name === 'Down' ? '下行' : '上行']} contentStyle={{ background: 'var(--surface)', borderColor: 'var(--line)', borderRadius: 'var(--radius)', color: 'var(--ink)' }} />
                        <Line type="monotone" dataKey="Down" stroke="var(--chart-down)" strokeWidth={2} dot={false} connectNulls={false} />
                        <Line type="monotone" dataKey="Up" stroke="var(--chart-up)" strokeWidth={2} strokeDasharray="5 3" dot={false} connectNulls={false} />
                    </LineChart></ResponsiveContainer>
                </div>
            </> : <div className="flex h-48 items-center justify-center text-center text-sm text-muted-foreground">需要至少两次有效采样才能显示流量趋势。</div>}
        </CardContent>
    </Card>;
}
