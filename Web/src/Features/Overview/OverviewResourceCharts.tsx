import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { ArrowRight } from 'lucide-react';
import { NavLink } from 'react-router';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/ui/card';
import { TimeSeriesChart } from '../../Components/TimeSeriesChart';
import { FormatBytes, FormatCount, FormatTime } from '../../Components/Ui';
import { ReadResourceSample, AppendResourceSample } from '../Resources/ResourceHistory';
import type { ResourceHistory, ResourcePoint } from '../Resources/ResourceHistory';
import { WithTime } from '../TimeRange';
import { useAdminQuery, useAdminServices } from '../UseOperations';

/** @brief 仅连接已核验实例的概览快照；页面离开后丢弃本地采样。 */
export function OverviewResourceCharts(Input: Readonly<{ Params: URLSearchParams }>): ReactNode {
    const Services = useAdminServices();
    const Query = useAdminQuery('overview-resource-sample', ReadResourceSample, { Scope: [Services.Mode] });
    const [History, SetHistory] = useState<ResourceHistory | null>(null);
    const Last = useRef<{ Scope: string; Time: number } | null>(null);
    const Gap = useRef(false);
    const Data = Query.data;
    const Scope = Data ? JSON.stringify([Data.Identity.InstanceKey, Data.Identity.Incarnation, Data.Snapshot.Process.Id, Data.Snapshot.Process.GenerationId]) : null;
    useEffect(() => {
        if (Services.Mode !== 'demo') return;
        const Timer = window.setInterval(() => { void Query.refetch(); }, 5000);
        return () => window.clearInterval(Timer);
    }, [Services.Mode, Query.refetch]);
    useEffect(() => {
        if (Query.error || !Data || !Scope) { Gap.current = true; return; }
        const Time = Date.parse(Data.Snapshot.SampledAt);
        if (!Number.isFinite(Time)) { Gap.current = true; return; }
        if (Last.current?.Scope === Scope && Last.current.Time === Time) return;
        Last.current = { Scope, Time };
        const HadGap = Gap.current;
        SetHistory(Previous => AppendResourceSample(Previous, Scope, Data.Snapshot, HadGap));
        Gap.current = false;
    }, [Data, Query.error, Scope]);
    const Current = History?.Scope === Scope ? History : null;
    const Snapshot = Data?.Snapshot;
    const Latency = Snapshot?.Latency.RecognitionAdmission;
    const P95 = Latency?.Available && Latency.P95Ms !== null ? `${FormatCount(Latency.P95Ms)} ms` : '未采集';
    const Rss = Snapshot?.Memory.ProcessAvailable && Snapshot.Memory.ProcessRssBytes !== null ? FormatBytes(Snapshot.Memory.ProcessRssBytes) : '未采集';
    const State = Query.error ? Data ? '读取失败，显示上次成功采样' : '采样读取失败' : Query.isPending ? '正在读取采样' : `本页采样 ${Current?.Samples.length ?? 0} 次`;
    return <>
        <TrendCard Title="延迟趋势" Value={P95} Detail={Latency?.Available ? `识别准入 P95 桶下界 · ${FormatCount(Latency.SampleCount)} 个累计样本` : '识别准入暂无可用样本'}
            State={State} Points={Current?.Points ?? []} Samples={Current?.Samples.length ?? 0} Kind="latency" Params={Input.Params} />
        <TrendCard Title="进程 RSS" Value={Rss} Detail="当前进程驻留内存" State={State} Points={Current?.Points ?? []}
            Samples={Current?.Samples.length ?? 0} Kind="memory" Params={Input.Params} />
    </>;
}

function TrendCard(Input: Readonly<{ Title: string; Value: string; Detail: string; State: string; Points: readonly ResourcePoint[]; Samples: number; Kind: 'latency' | 'memory'; Params: URLSearchParams }>): ReactNode {
    const IsLatency = Input.Kind === 'latency';
    const Format = (Value: number): string => IsLatency ? `${Value.toLocaleString('zh-CN', { maximumFractionDigits: 1 })} ms` : FormatBytes(Math.round(Value));
    const Series = IsLatency ? [
        { Key: 'p50', Label: '识别 P50', Color: 'var(--chart-up)', Dash: '5 3', Value: (Point: ResourcePoint) => Point.P50Ms, Format },
        { Key: 'p95', Label: '识别 P95', Color: 'var(--plot-line)', Value: (Point: ResourcePoint) => Point.P95Ms, Format },
        { Key: 'p99', Label: '识别 P99', Color: 'var(--chart-down)', Dash: '2 3', Value: (Point: ResourcePoint) => Point.P99Ms, Format },
    ] : [{ Key: 'rss', Label: '进程 RSS', Color: 'var(--plot-line)', Value: (Point: ResourcePoint) => Point.RssBytes, Format }];
    const HasValues = Input.Points.some(Point => Series.some(Line => Line.Value(Point) !== null));
    return <Card className="min-w-0 gap-0 py-0"><CardHeader className="px-5 pt-4 pb-0"><div className="flex items-start justify-between gap-3"><div className="min-w-0"><CardTitle>{Input.Title}</CardTitle><CardDescription className="mt-1">{Input.Detail}</CardDescription></div><NavLink className="shrink-0 rounded-sm text-muted-foreground hover:text-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring" aria-label={`查看${Input.Title}资源详情`} to={WithTime('/resources', Input.Params)}><ArrowRight className="size-4" aria-hidden="true" /></NavLink></div><p className="mt-3 font-mono text-xl font-semibold tabular-nums">{Input.Value}</p></CardHeader>
        <CardContent className="min-w-0 px-5 pt-2 pb-4">{IsLatency && <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground"><span>识别 P50 · 虚线</span><span>识别 P95 · 实线</span><span>识别 P99 · 点线</span></div>}<div className="h-44 min-w-0">{Input.Samples >= 2 && HasValues ? <TimeSeriesChart Points={Input.Points} Series={Series} AriaLabel={`${Input.Title}趋势，${IsLatency ? '识别准入累计分位数桶下界，单位毫秒' : '进程驻留内存'}`} FormatTime={Value => FormatTime(new Date(Value).toISOString())} FormatAxis={Format} /> : <div className="flex h-full items-center justify-center text-center text-sm text-muted-foreground">{!HasValues && Input.Samples >= 2 ? '当前没有可绘制的数据' : '等待连续采样后显示趋势'}</div>}</div>{IsLatency && <p className="text-xs text-muted-foreground">Worker 延迟：未采集 · 内存分配延迟：未采集</p>}<p className="mt-2 text-xs text-muted-foreground">{Input.State} · 断线不连接</p></CardContent>
    </Card>;
}
