import { useMemo } from 'react';
import type { ReactNode } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/ui/card';
import { TimeSeriesChart } from '../../Components/TimeSeriesChart';
import { FormatRate, FormatTime } from '../../Components/Ui';
import { HistoryChartPoints } from '../../Api/Analysis';
import type { TrafficSample } from '../../Services/AdminDataSource';
import { BuildTrafficSeries } from './TrafficChart';
import { useHistory, useTimeRange } from '../TimeRange';
import { useAdminServices, useBootstrapIdentity } from '../UseOperations';

type TrafficPoint = Readonly<{ Time: number; Up: number | null; Down: number | null }>;

/** @brief 优先读取受能力控制的窗口历史；未开放时只用概览随附的真实采样。 */
export function OverviewChart(Input: Readonly<{ History: readonly TrafficSample[]; ClassName?: string }>): ReactNode {
    const Services = useAdminServices();
    const Bootstrap = useBootstrapIdentity();
    const Range = useTimeRange();
    const HasHistory = Services.Mode === 'demo' || Bootstrap.data?.Capabilities.includes('history.read') === true;
    const CanReadHistory = HasHistory && !Bootstrap.error;
    const Window = useHistory('process', '', 'traffic', CanReadHistory);
    const SnapshotPoints = useMemo(() => SnapshotTrafficPoints(Input.History, Range.From, Range.To, Range.Valid),
        [Input.History, Range.From, Range.To, Range.Valid]);
    const WindowPoints = useMemo(() => Window.data
        ? HistoryChartPoints(Window.data.Items, Window.data.ResolutionMs, Window.data.Gaps) : [],
    [Window.data]);
    const Points = CanReadHistory ? WindowPoints : SnapshotPoints;
    const HasValues = Points.some(Point => Point.Up !== null || Point.Down !== null);
    const Loading = CanReadHistory && Window.isPending;
    const Failed = CanReadHistory && Window.isError;
    const Description = CanReadHistory
        ? '有效载荷 · 当前时间窗口的采样范围'
        : '有效载荷 · 仅使用概览随附的真实采样，不请求窗口历史';
    const Series = [
        { Key: 'Down', Label: '下行', Color: 'var(--chart-down)', Value: (Point: TrafficPoint) => Point.Down, Format: FormatRate },
        { Key: 'Up', Label: '上行', Color: 'var(--chart-up)', Dash: '6 4', Value: (Point: TrafficPoint) => Point.Up, Format: FormatRate },
    ];
    return <Card className={`overview-traffic-v2 min-w-0 ${Input.ClassName ?? ''}`}>
        <CardHeader className="px-5"><CardTitle>流量趋势</CardTitle><CardDescription>{Description}</CardDescription></CardHeader>
        <CardContent className="px-5">
            <div className="mb-3 flex flex-wrap gap-5 text-xs text-muted-foreground" aria-label="图例">
                <span className="flex items-center gap-2"><span className="h-0.5 w-4 bg-[var(--chart-down)]" />下行</span>
                <span className="flex items-center gap-2"><span className="h-0.5 w-4 border-t-2 border-dashed border-[var(--chart-up)]" />上行</span>
            </div>
            <div className="h-48 min-w-0">
                {Loading ? <div className="flex h-full items-center justify-center text-sm text-muted-foreground">正在读取窗口流量样本…</div>
                    : Failed ? <div role="status" className="flex h-full items-center justify-center text-sm text-muted-foreground">窗口流量样本读取失败；请重试刷新。</div>
                        : HasValues ? <TimeSeriesChart Points={Points} Series={Series} AriaLabel="历史流量速率趋势，显示下行与上行采样"
                            FormatTime={Value => FormatTime(new Date(Value).toISOString())} FormatAxis={FormatRate} />
                            : <div className="flex h-full items-center justify-center text-center text-sm text-muted-foreground">
                                {Range.InvalidReason ?? (CanReadHistory ? '当前区间没有有效流量样本。' : '概览快照没有足够的流量样本。')}
                            </div>}
            </div>
            {CanReadHistory && Window.data && <p className="mt-2 text-xs text-muted-foreground">
                采样 {FormatTime(Window.data.SampledAt)} · 分辨率 {Number(Window.data.ResolutionMs) / 1000}s · {Window.data.Coverage}
            </p>}
            {CanReadHistory && (Window.data?.Gaps.length ?? 0) > 0 && <p role="status" className="mt-2 text-xs text-muted-foreground">
                区间包含 {Window.data!.Gaps.length} 段缺测；曲线保留断点。
            </p>}
        </CardContent>
    </Card>;
}

function SnapshotTrafficPoints(History: readonly TrafficSample[], From: string, To: string, Valid: boolean): TrafficPoint[] {
    if (!Valid) return [];
    const Begin = Date.parse(From), End = Date.parse(To);
    return BuildTrafficSeries(History).flatMap(Point => {
        const Time = Date.parse(Point.Time);
        return Number.isFinite(Time) && Time >= Begin && Time <= End ? [{ Time, Up: Point.Up, Down: Point.Down }] : [];
    });
}
