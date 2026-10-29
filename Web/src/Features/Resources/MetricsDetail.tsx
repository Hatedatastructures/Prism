import { useEffect } from 'react';
import type { ReactNode } from 'react';
import { RefreshCw } from 'lucide-react';
import { Button } from '@/Components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/ui/card';
import { FormatCount, FormatTime, QueryState } from '../../Components/Ui';
import type { BootstrapSnapshot, MetricsSnapshot, OverviewSnapshot, UInt64Value } from '../../Services/AdminDataSource';
import { useAdminQuery, useAdminServices } from '../UseOperations';
import { ReadMetricsDetail } from './ReadMetricsDetail';
import { MetricsLatencyChart } from './MetricsLatencyChart';

export function MetricsDetail(Input: Readonly<{ Snapshot: OverviewSnapshot; Identity: BootstrapSnapshot }>): ReactNode {
    const Services = useAdminServices();
    const Query = useAdminQuery('resource-metrics-detail', ReadMetricsDetail, { Scope: [Services.Mode] });
    useEffect(() => {
        if (Services.Mode !== 'demo') return;
        const Timer = window.setInterval(() => { void Query.refetch(); }, 5000);
        return () => window.clearInterval(Timer);
    }, [Services.Mode, Query.refetch]);
    const Data = Query.data;
    const Matching = Data && Data.Identity.InstanceKey === Input.Identity.InstanceKey && Data.Identity.Incarnation === Input.Identity.Incarnation &&
        Data.Metrics.ProcessId === Input.Snapshot.Process.Id && Data.Metrics.GenerationId === Input.Snapshot.Process.GenerationId;
    return <Card><CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3"><div><CardTitle>识别准入与观测明细</CardTitle><CardDescription className="mt-1">来自独立 Metrics 快照；延迟为协议识别准入，不是内存分配延迟。</CardDescription></div><Button variant="outline" size="sm" disabled={Query.isFetching} onClick={() => void Query.refetch()}><RefreshCw className={Query.isFetching ? 'animate-spin' : ''} aria-hidden="true" />刷新指标</Button></CardHeader>
        <CardContent><QueryState Pending={Query.isPending} Error={Query.error} Label="详细指标" HasData={Data !== undefined} Retry={() => void Query.refetch()} Retrying={Query.isFetching} Children={Data ? Matching ? <MetricsValues Metrics={Data.Metrics} Identity={Data.Identity} Failed={!!Query.error} /> : <p className="text-sm text-muted-foreground">指标与资源快照的进程或代次不同，等待同一实例的快照。</p> : null} /></CardContent>
    </Card>;
}

function MetricsValues(Input: Readonly<{ Metrics: MetricsSnapshot; Identity: BootstrapSnapshot; Failed: boolean }>): ReactNode {
    const Value = Input.Metrics, Latency = Value.RecognitionLatency, Observations = Value.Observations, Retirement = Value.RetirementFailures;
    const Microseconds = (Item: UInt64Value | null): string => Item === null ? '未采集' : `${FormatCount(Item)} µs`;
    return <div className="space-y-4"><p className="text-xs text-muted-foreground">读取于 {FormatTime(Value.CheckedAt, true)} · Process {Value.ProcessId} · Generation {Value.GenerationId} · 后端统计周期 {FormatCount(Value.SampleIntervalMs)} ms</p>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4" aria-label="识别准入延迟分布">{([['P50 桶下界', Latency.P50Us], ['P95 桶下界', Latency.P95Us], ['P99 桶下界', Latency.P99Us], ['最大观测值', Latency.MaxObservedUs]] as const).map(([Label, Amount]) => <div key={Label} className="rounded-md border bg-muted/20 px-3 py-2"><p className="text-xs text-muted-foreground">{Label}</p><p className="mt-1 font-mono text-sm font-semibold tabular-nums">{Microseconds(Amount)}</p></div>)}</div>
        <MetricsLatencyChart Metrics={Value} Identity={Input.Identity} Failed={Input.Failed} />
        <div className="grid gap-4 lg:grid-cols-3"><DetailList Title="识别采样（当前代次）" Items={[[ '有效样本', FormatCount(Latency.SampleCount) ], [ '追踪写入', FormatCount(Latency.TracerWritten) ], [ '追踪丢弃', FormatCount(Latency.TracerDropped) ], [ '超出直方图范围', FormatCount(Latency.HistogramRangeExceeded) ]]} />
            <DetailList Title="观测队列（进程累计）" Items={[[ '已入队', FormatCount(Observations.Accepted) ], [ '已消费', FormatCount(Observations.Consumed) ], [ '入队丢弃', FormatCount(Observations.Dropped) ], [ '其中识别延迟丢弃', FormatCount(Observations.RecognitionLatencyQueueDrops) ], [ '聚合失败', FormatCount(Observations.AggregationFailures) ], [ '识别延迟归属失败', FormatCount(Observations.RecognitionLatencyAggregationFailures) ]]} />
            <DetailList Title="统计退休失败（进程累计）" Items={[[ 'Session', FormatCount(Retirement.Sessions) ], [ 'Stream', FormatCount(Retirement.Streams) ], [ 'Task', FormatCount(Retirement.Tasks) ]]} /></div>
        <div className="rounded-md border px-3 py-2"><p className="text-sm font-medium">近期识别准入样本</p><p className="mt-1 text-xs text-muted-foreground">最多 8 个实际读数，按新到旧排列；接口不提供各点时间。</p>{Latency.RecentUs.length ? <ol className="mt-2 flex flex-wrap gap-1.5" aria-label="近期识别准入样本（新到旧）">{Latency.RecentUs.map((Sample, Index) => <li key={Index} className="rounded bg-muted px-2 py-1 font-mono text-xs tabular-nums">{Microseconds(Sample)}</li>)}</ol> : <p className="mt-2 text-sm text-muted-foreground">{Latency.Ready ? '当前快照没有可读取的近期样本。' : '当前代次还没有识别准入样本。'}</p>}</div>
        <p className="text-xs text-muted-foreground">分位值是累计直方图桶下界；追踪丢弃与队列丢弃属于不同阶段。识别延迟入队丢弃已包含在总入队丢弃中；统计退休失败不代表业务关闭失败。</p>
    </div>;
}

function DetailList(Input: Readonly<{ Title: string; Items: readonly (readonly [string, string])[] }>): ReactNode {
    return <section><h3 className="border-b pb-2 text-sm font-semibold">{Input.Title}</h3><dl className="divide-y text-sm">{Input.Items.map(([Label, Value]) => <div key={Label} className="flex justify-between gap-3 py-1.5"><dt className="text-muted-foreground">{Label}</dt><dd className="font-mono font-medium tabular-nums">{Value}</dd></div>)}</dl></section>;
}
