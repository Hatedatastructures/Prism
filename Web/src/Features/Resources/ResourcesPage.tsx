/** @file 基于 shadcn-admin Dashboard / Table 重建的资源分析页。 */
import { useEffect } from 'react';
import type { ReactNode } from 'react';
import { Activity, Boxes, Cpu, MemoryStick, RefreshCw } from 'lucide-react';
import { NavLink } from 'react-router';
import { Button } from '@/Components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/ui/card';
import { Progress } from '@/Components/ui/progress';
import { OverviewStat } from '../../Components/OverviewStat';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/Components/ui/table';
import { EmptyState, FormatCount, FormatTime, PageHeader, QueryState } from '../../Components/Ui';
import type { OverviewSnapshot, UInt64Value } from '../../Services/AdminDataSource';
import { useAdminQuery, useAdminServices } from '../UseOperations';
import { WorkerTargetPath } from '../Workers/WorkerIdentity';
import { AvailableBytes as Bytes, AvailableCount as Count, DecideBytePoolUsage } from './ResourceAvailability';
import { ResourceHistoryPanel } from './ResourceHistoryPanel';
import { ReadResourceSample } from './ResourceHistory';
import { MetricsDetail } from './MetricsDetail';

export default function ResourcesPage(): ReactNode {
    const Services = useAdminServices();
    const Query = useAdminQuery('resource-sample', ReadResourceSample, { Scope: [Services.Mode] });
    useEffect(() => {
        if (Services.Mode !== 'demo') return;
        const Timer = window.setInterval(() => { void Query.refetch(); }, 5000);
        return () => window.clearInterval(Timer);
    }, [Services.Mode, Query.refetch]);
    const Snapshot = Query.data?.Snapshot, Memory = Snapshot?.Memory, Observations = Snapshot?.Observations;
    const Refresh = (): void => { void Query.refetch(); };
    return <div className="space-y-4"><PageHeader Title="资源分析" Description="进程 RSS、受追踪 PMR、BytePool 与观测质量分开呈现，不能相加。" Actions={<Button variant="outline" disabled={Query.isFetching} onClick={Refresh}><RefreshCw className={Query.isFetching ? 'animate-spin' : ''} aria-hidden="true" />刷新快照</Button>} />
        <QueryState Pending={Query.isPending} Error={Query.error} Label="资源快照" HasData={Query.data !== undefined} Retry={Refresh} Retrying={Query.isFetching} Children={Snapshot && Memory && Observations ? <><div className="flex flex-wrap items-center gap-x-6 gap-y-1 border-b pb-3 text-sm text-muted-foreground"><span>采样于 <strong className="text-foreground">{FormatTime(Snapshot.SampledAt, true)}</strong></span><span>采样间隔 <strong className="text-foreground">{FormatCount(Snapshot.SampleIntervalMs)} ms</strong></span><span>Process <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-foreground">{Snapshot.Process.Id}</code> · G{Snapshot.Process.GenerationId}</span></div>
            <section className="grid grid-cols-2 gap-3 xl:grid-cols-4" aria-label="资源摘要">
                <OverviewStat Label="进程 RSS" Value={Bytes(Memory.ProcessAvailable, Memory.ProcessRssBytes)} Detail={`峰值 ${Bytes(Memory.ProcessAvailable, Memory.ProcessPeakRssBytes)}`} Icon={<Cpu aria-hidden="true" />} />
                <OverviewStat Label="PMR 受追踪分配" Value={Bytes(Memory.Allocations.Available, Memory.Allocations.CurrentBytes)} Detail="当前请求量" Icon={<MemoryStick aria-hidden="true" />} />
                <OverviewStat Label="BytePool 使用" Value={Bytes(Memory.BytePool.Available, Memory.BytePool.UsedBytes)} Detail={`容量 ${Bytes(Memory.BytePool.Available, Memory.BytePool.CapacityBytes)}`} Icon={<Boxes aria-hidden="true" />} />
                <OverviewStat Label="观测丢弃" Value={FormatCount(Observations.Dropped)} Detail={`聚合失败 ${FormatCount(Observations.AggregationFailures)}`} Icon={<Activity aria-hidden="true" />} />
            </section>
            <div className="grid min-w-0 items-start gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(22rem,0.75fr)]"><ResourceHistoryPanel Snapshot={Snapshot} Bootstrap={Query.data!.Identity} Failed={!!Query.error} /><LatencySnapshot Snapshot={Snapshot} /></div>
            <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(22rem,0.9fr)]"><Card><CardHeader><CardTitle>Worker 受追踪分配</CardTitle><CardDescription>当前、峰值和调用次数按 Worker 展示。</CardDescription></CardHeader><CardContent>{Memory.WorkerAllocations.length === 0 ? <EmptyState Title="没有 Worker 分配记录" Detail="当前快照没有返回可列举的受追踪分配。" /> : <Table><TableHeader><TableRow><TableHead>Worker</TableHead><TableHead>当前请求量</TableHead><TableHead>峰值请求量</TableHead><TableHead>成功分配次数</TableHead><TableHead>释放次数</TableHead><TableHead>统计范围</TableHead></TableRow></TableHeader><TableBody>{Memory.WorkerAllocations.map(Row => <TableRow key={Row.WorkerId}><TableCell><NavLink className="font-medium underline-offset-4 hover:underline" to={WorkerTargetPath('workers', { Id: Row.WorkerId, ProcessId: Snapshot.Process.Id, GenerationId: Snapshot.Process.GenerationId })}>{Row.WorkerId}</NavLink></TableCell><TableCell>{Bytes(Row.Allocation.Available, Row.Allocation.CurrentBytes)}</TableCell><TableCell>{Bytes(Row.Allocation.Available, Row.Allocation.PeakBytes)}</TableCell><TableCell>{Count(Row.Allocation.Available, Row.Allocation.AllocationCount)}</TableCell><TableCell>{Count(Row.Allocation.Available, Row.Allocation.ReleaseCount)}</TableCell><TableCell className="max-w-72 whitespace-normal text-muted-foreground"><details><summary className="cursor-pointer whitespace-nowrap font-medium text-foreground">范围</summary><p className="mt-1">{Row.Allocation.Coverage || '未提供'}</p></details></TableCell></TableRow>)}</TableBody></Table>}<details className="mt-3 border-t pt-3 text-sm"><summary className="cursor-pointer font-medium">Process PMR 调用与统计范围</summary><p className="mt-2">分配 {Count(Memory.Allocations.Available, Memory.Allocations.AllocationCount)} · 释放 {Count(Memory.Allocations.Available, Memory.Allocations.ReleaseCount)} · 峰值 {Bytes(Memory.Allocations.Available, Memory.Allocations.PeakBytes)}</p><p className="mt-1 text-xs text-muted-foreground">{Memory.Allocations.Coverage || '统计范围未提供'}</p></details></CardContent></Card>
                <div className="space-y-4"><Card><CardHeader><CardTitle>BytePool 容量</CardTitle><CardDescription>使用率只在服务端同时提供用量与容量时计算。</CardDescription></CardHeader><CardContent className="space-y-4"><PoolUsage Available={Memory.BytePool.Available} Used={Memory.BytePool.UsedBytes} Capacity={Memory.BytePool.CapacityBytes} /><Facts Items={[['峰值使用', Bytes(Memory.BytePool.Available, Memory.BytePool.PeakUsedBytes)], ['可用块', Count(Memory.BytePool.Available, Memory.BytePool.AvailableBlocks)], ['单块大小', Bytes(Memory.BytePool.Available, Memory.BytePool.BlockSize)], ['分配 / 释放', `${Count(Memory.BytePool.Available, Memory.BytePool.AllocationCount)} / ${Count(Memory.BytePool.Available, Memory.BytePool.ReleaseCount)}`]]} /></CardContent><CardContent className="border-t pt-4"><details><summary className="cursor-pointer text-sm font-semibold">观测质量与统计范围</summary><p className="mt-2 text-xs text-muted-foreground">事件丢失会降低可观测范围，但不改变账户额度账本。</p><div className="mt-3"><Facts Items={[['已入队观测', FormatCount(Observations.Accepted)], ['已消费观测', FormatCount(Observations.Consumed)], ['累计丢弃', FormatCount(Observations.Dropped)], ['聚合失败', FormatCount(Observations.AggregationFailures)], ['PMR 覆盖', Memory.Allocations.Coverage]]} /></div></details></CardContent></Card></div></div>
            <details className="rounded-xl border bg-card"><summary className="cursor-pointer px-4 py-3 text-sm font-semibold">诊断明细 <span className="ml-2 font-normal text-muted-foreground">观测计数、近期样本与完整口径</span></summary><div className="border-t p-3"><MetricsDetail Snapshot={Snapshot} Identity={Query.data!.Identity} /></div></details>
        </> : null} />
    </div>;
}

function LatencySnapshot(Input: Readonly<{ Snapshot: OverviewSnapshot }>): ReactNode {
    const Latency = Input.Snapshot.Latency.RecognitionAdmission;
    const Time = (Value: string | null): string => Latency.Available && Value !== null ? `${FormatCount(Value)} ms` : '未采集';
    return <Card><CardHeader><CardTitle>识别准入延迟</CardTitle><CardDescription>当前代次累计分位桶下界 · {Latency.Available ? FormatCount(Latency.SampleCount) : '未采集'} 个样本</CardDescription></CardHeader><CardContent><dl className="grid grid-cols-2 gap-x-4 gap-y-3 sm:grid-cols-4"><LatencyFact Label="P50" Value={Time(Latency.P50Ms)} /><LatencyFact Label="P95" Value={Time(Latency.P95Ms)} /><LatencyFact Label="P99" Value={Time(Latency.P99Ms)} /><LatencyFact Label="最大值" Value={Time(Latency.MaxMs)} /></dl><p className="mt-4 text-xs text-muted-foreground">内存分配耗时未采集；分位值为整数毫秒桶下界。</p></CardContent></Card>;
}
function LatencyFact(Input: Readonly<{ Label: string; Value: string }>): ReactNode { return <div className="min-w-0"><dt className="text-sm text-muted-foreground">{Input.Label}</dt><dd className="mt-1 text-lg font-semibold tabular-nums">{Input.Value}</dd></div>; }

function PoolUsage(Input: Readonly<{ Available: boolean; Used: UInt64Value | null; Capacity: UInt64Value | null }>): ReactNode { const Usage = DecideBytePoolUsage(Input.Available, Input.Used, Input.Capacity); if (Usage.Value === null) return <p className="text-sm text-muted-foreground">{Usage.State === 'unavailable' ? 'BytePool 使用率未采集。' : Usage.State === 'zero-capacity' ? '容量为 0，无法计算使用率。' : '用量或容量缺失，无法计算使用率。'}</p>; return <div className="space-y-2"><div className="flex justify-between text-sm"><span>使用率</span><strong>{Usage.Value.toFixed(1)}%</strong></div><Progress value={Usage.Value} aria-label="BytePool 使用率" /></div>; }
function Facts(Input: Readonly<{ Items: readonly (readonly [string, string])[] }>): ReactNode { return <dl className="grid gap-3 text-sm">{Input.Items.map(([Label, Value]) => <div key={Label} className="flex items-start justify-between gap-4 border-b pb-3 last:border-0 last:pb-0"><dt className="text-muted-foreground">{Label}</dt><dd className="text-right font-medium">{Value}</dd></div>)}</dl>; }
