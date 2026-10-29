import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/Components/ui/tabs';
import { TimeSeriesChart } from '../../Components/TimeSeriesChart';
import { FormatBytes, FormatTime } from '../../Components/Ui';
import type { BootstrapSnapshot, OverviewSnapshot } from '../../Services/AdminDataSource';
import { AppendResourceSample } from './ResourceHistory';
import type { ResourceHistory, ResourcePoint } from './ResourceHistory';

type ChartKind = 'memory' | 'pmr' | 'pool' | 'latency';
type ChartLine = Readonly<{ Key: keyof ResourcePoint; Label: string; Color: string; Dash?: string }>;
const Lines: Record<ChartKind, readonly ChartLine[]> = {
    memory: [{ Key: 'RssBytes', Label: '进程 RSS', Color: 'var(--plot-line)' }, { Key: 'PmrBytes', Label: 'Process PMR 请求量', Color: 'var(--plot-line-soft)', Dash: '6 4' }, { Key: 'PoolBytes', Label: 'BytePool 整块占用', Color: 'var(--plot-line-faint)', Dash: '2 4' }],
    pmr: [{ Key: 'PmrAllocateRate', Label: '分配', Color: 'var(--plot-line)' }, { Key: 'PmrReleaseRate', Label: '释放', Color: 'var(--plot-line-soft)', Dash: '6 4' }],
    pool: [{ Key: 'PoolAllocateRate', Label: '成功租约', Color: 'var(--plot-line)' }, { Key: 'PoolReleaseRate', Label: '归还租约', Color: 'var(--plot-line-soft)', Dash: '6 4' }],
    latency: [{ Key: 'P50Ms', Label: 'P50', Color: 'var(--plot-line)' }, { Key: 'P95Ms', Label: 'P95', Color: 'var(--plot-line-soft)', Dash: '6 4' }, { Key: 'P99Ms', Label: 'P99', Color: 'var(--plot-line-faint)', Dash: '2 4' }],
};
const Descriptions: Record<ChartKind, string> = {
    memory: '三个值覆盖范围不同，不能相加；PMR 是请求字节，BytePool 是整块预约量。',
    pmr: '相邻快照的成功分配、释放次数之差除以实际间隔；仅覆盖 Process TrackingResource。',
    pool: '相邻快照的成功租约及归还次数之差除以实际间隔；不包含失败的准入请求。',
    latency: '识别准入的累计分位桶下界，单位为向下取整的整数毫秒；不是内存分配耗时。',
};

export function ResourceHistoryPanel(Input: Readonly<{ Snapshot: OverviewSnapshot; Bootstrap: BootstrapSnapshot; Failed: boolean }>): ReactNode {
    const [History, SetHistory] = useState<ResourceHistory | null>(null);
    const [Kind, SetKind] = useState<ChartKind>('memory');
    const Gap = useRef(false);
    const LastAccepted = useRef<{ Scope: string; Time: number } | null>(null);
    const Scope = Input.Bootstrap.ProcessId === Input.Snapshot.Process.Id
        ? `${Input.Bootstrap.InstanceKey}:${Input.Bootstrap.Incarnation}:${Input.Snapshot.Process.GenerationId}` : null;
    useEffect(() => {
        if (Input.Failed || !Scope) { Gap.current = true; return; }
        const Time = Date.parse(Input.Snapshot.SampledAt);
        if (!Number.isFinite(Time)) { Gap.current = true; return; }
        if (LastAccepted.current?.Scope === Scope && LastAccepted.current.Time === Time) return;
        LastAccepted.current = { Scope, Time };
        const HadGap = Gap.current;
        SetHistory(Previous => AppendResourceSample(Previous, Scope, Input.Snapshot, HadGap));
        Gap.current = false;
    }, [Input.Snapshot, Input.Failed, Scope]);
    const Points = Scope && History?.Scope === Scope ? History.Points : [];
    const Samples = Scope && History?.Scope === Scope ? History.Samples.length : 0;
    return <Card className="min-w-0"><CardHeader><CardTitle>实时资源采样</CardTitle><CardDescription>本页已采集 {Samples} 个快照；断线不连接曲线。</CardDescription></CardHeader>
        <CardContent><Tabs value={Kind} onValueChange={Value => SetKind(Value as ChartKind)}><TabsList className="max-w-full overflow-x-auto" aria-label="资源趋势类型"><TabsTrigger value="memory">内存用量</TabsTrigger><TabsTrigger value="pmr">PMR 次数 / 秒</TabsTrigger><TabsTrigger value="pool">字节池次数 / 秒</TabsTrigger><TabsTrigger value="latency">识别准入延迟</TabsTrigger></TabsList>
            {(Object.keys(Lines) as ChartKind[]).map(Value => <TabsContent key={Value} value={Value} className="mt-3"><p className="text-xs text-muted-foreground">{Descriptions[Value]}</p>
                {!Scope ? <p className="py-10 text-center text-sm text-muted-foreground">正在核对实例身份；身份不可确认时不拼接采样。</p>
                    : Samples < 2 ? <p className="py-3 text-sm text-muted-foreground">等待下一次采样，也可点击“刷新快照”。</p>
                    : <ResourceChart Points={Points} Kind={Value} />}
            </TabsContent>)}
        </Tabs></CardContent></Card>;
}

function ResourceChart(Input: Readonly<{ Points: readonly ResourcePoint[]; Kind: ChartKind }>): ReactNode {
    const Format = (Value: number): string => Input.Kind === 'memory' ? FormatBytes(Math.round(Value))
        : `${Value.toLocaleString('zh-CN', { maximumFractionDigits: 1 })}${Input.Kind === 'latency' ? ' ms' : ' 次/秒'}`;
    const Series = Lines[Input.Kind].map(Line => ({ Key: Line.Key, Label: Line.Label, Color: Line.Color,
        Value: (Point: ResourcePoint) => Point[Line.Key], Format, ...(Line.Dash ? { Dash: Line.Dash } : {}) }));
    return <><div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground" aria-label="图例">{Lines[Input.Kind].map(Line => <span key={Line.Key} className="inline-flex items-center gap-1.5"><span className="inline-block w-4 border-t-2" style={{ borderColor: Line.Color, borderTopStyle: Line.Dash ? 'dashed' : 'solid' }} aria-hidden="true" />{Line.Label}</span>)}</div>
        <div className="mt-2 h-52 min-w-0"><TimeSeriesChart Points={Input.Points} Series={Series} AriaLabel={`资源采样：${Descriptions[Input.Kind]}`} FormatTime={Value => FormatTime(new Date(Value).toISOString())} FormatAxis={Format} /></div></>;
}
