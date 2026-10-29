/** @file 以协议清单、覆盖范围和选中对象历史组织协议分析页。 */
import { useMemo } from 'react';
import type { ReactNode } from 'react';
import { ArrowRight, Layers, Network, RefreshCw } from 'lucide-react';
import { NavLink, useSearchParams } from 'react-router';
import { Button } from '@/Components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/ui/card';
import { Input } from '@/Components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/Components/ui/table';
import { Badge, EmptyState, FormatBytes, FormatCount, PageHeader, QueryState } from '../../Components/Ui';
import type { ProtocolRecord } from '../../Services/AdminDataSource';
import { ProtocolHistoryTypeKey } from '../../Api/ProtocolIdentity';
import { HistoryPanel } from '../HistoryPanel';
import { TimeRangeControl, WithTime } from '../TimeRange';
import { useAdminInfiniteQuery, useAdminServices, useBootstrapIdentity } from '../UseOperations';
import { SummarizeProtocols } from './ProtocolSummary';

type ProtocolView = 'all' | 'types' | 'instances';

export default function ProtocolsPage(): ReactNode {
    const [Params, SetParams] = useSearchParams();
    const Services = useAdminServices();
    const Bootstrap = useBootstrapIdentity();
    const Query = useAdminInfiniteQuery('protocols', (Source, Page) => Source.GetProtocols
        ? Source.GetProtocols(Page)
        : Source.GetOverview().then(Value => ({ Items: Value.Protocols, NextCursor: '0', HasMore: false })));
    const Rows = Query.data?.pages.flatMap(Page => Page.Items) ?? [];
    const Search = Params.get('protocol_q') ?? '';
    const SelectedId = Params.get('protocol') ?? '';
    const RequestedView = Params.get('protocol_view');
    const View: ProtocolView = RequestedView === 'types' || RequestedView === 'instances' ? RequestedView : 'all';
    const CanReadHistory = Services.Mode === 'demo' || Bootstrap.data?.Capabilities.includes('history.read') === true;
    const Filtered = useMemo(() => {
        const Needle = Search.trim().toLocaleLowerCase();
        return Rows.filter(Row => {
            const KindMatches = View === 'all' || View === 'instances' && Row.Kind === 'instance' || View === 'types' && Row.Kind !== 'instance';
            const SearchMatches = !Needle || `${Row.Name} ${Row.Id} ${Row.TypeKey ?? ''} ${Row.Coverage}`.toLocaleLowerCase().includes(Needle);
            return KindMatches && SearchMatches;
        });
    }, [Rows, Search, View]);
    const Selected = Rows.find(Row => Row.Id === SelectedId) ?? null;
    const Types = Rows.filter(Row => Row.Kind !== 'instance');
    const Instances = Rows.filter(Row => Row.Kind === 'instance');
    const Summary = SummarizeProtocols(Types, Query.hasNextPage ?? false);
    const Set = (Key: string, Value: string): void => {
        const Next = new URLSearchParams(Params);
        if (Value) Next.set(Key, Value); else Next.delete(Key);
        SetParams(Next, { replace: Key === 'protocol_q' });
    };
    const SelectProtocol = (Row: ProtocolRecord): void => {
        const Next = new URLSearchParams(Params);
        if (SelectedId === Row.Id) Next.delete('protocol'); else Next.set('protocol', Row.Id);
        SetParams(Next);
    };
    const Refresh = async (): Promise<void> => { await Promise.all([Query.refetch(), Bootstrap.refetch()]); };

    return <div className="space-y-4">
        <PageHeader Title="协议" Description="并排比较类型、配置实例、活动 Session、累计流量和后端覆盖范围；选中一行查看它自己的历史。"
            Actions={<><TimeRangeControl /><Button type="button" variant="outline" disabled={Query.isFetching} onClick={() => void Refresh()}><RefreshCw className={Query.isFetching ? 'animate-spin' : ''} aria-hidden="true" />刷新快照</Button></>} />
        <dl className="grid grid-cols-2 gap-x-5 border-y py-2 sm:grid-cols-3" aria-label="协议汇总">
            <Reading Label="已载入协议类型" Value={Query.data ? `${FormatCount(Summary.Types)}${Summary.Partial ? '+' : ''}` : '—'} Detail="同类型配置只计一次" Icon={<Layers aria-hidden="true" />} />
            <Reading Label="配置实例" Value={Query.data ? `${FormatCount(Instances.length)}${Query.hasNextPage ? '+' : ''}` : '—'} Detail="服务端明确返回的实例行" Icon={<Network aria-hidden="true" />} />
            <Reading Label="活动 TCP Session" Value={Summary.Active === null ? '未提供' : FormatCount(Summary.Active)} Detail={Summary.Partial ? '已知类型小计；可能仍有分页' : '按类型统计的可观测值'} Icon={<Network aria-hidden="true" />} />
        </dl>

        <Card className="min-w-0"><CardHeader className="gap-3 pb-3">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"><div><CardTitle>协议与配置</CardTitle><CardDescription>每行保留自己的统计范围；类型值不可与配置实例重复相加。</CardDescription></div><span className="text-xs text-muted-foreground">显示 {Filtered.length} / 已载入 {Rows.length}{Query.hasNextPage ? '+' : ''}</span></div>
            <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                <Input aria-label="搜索协议" value={Search} onChange={Event => Set('protocol_q', Event.target.value)} placeholder="搜索名称、配置 ID 或统计覆盖" className="lg:max-w-sm" />
                <div className="flex flex-wrap gap-2" role="group" aria-label="协议范围筛选">{(['all', 'types', 'instances'] as const).map(Value => <Button key={Value} type="button" size="sm" variant={View === Value ? 'default' : 'outline'} onClick={() => Set('protocol_view', Value === 'all' ? '' : Value)}>
                    {Value === 'all' ? '全部' : Value === 'types' ? '类型统计' : '配置实例'}
                </Button>)}</div>
            </div>
        </CardHeader><CardContent className="pt-0"><QueryState Pending={Query.isPending} Error={Query.error} Label="协议记录" HasData={Query.data !== undefined} Retry={() => void Query.refetch()} Retrying={Query.isFetching}
            Children={Filtered.length === 0 ? <EmptyState Title="当前范围没有协议" Detail="调整搜索或范围筛选，也可以载入更多分页记录。" /> : <>
                <div className="overflow-x-auto"><ProtocolTable Rows={Filtered} SelectedId={SelectedId} OnSelect={SelectProtocol} /></div>
                <p className="mt-2 text-xs text-muted-foreground">流量为累计字节；延迟摘要为服务端返回的累计分位桶下界。窗口趋势会显示独立的采样范围。</p>
                {Query.hasNextPage && <Button className="mt-3" variant="outline" disabled={Query.isFetchingNextPage} onClick={() => void Query.fetchNextPage()}>{Query.isFetchingNextPage ? '正在载入…' : '载入更多协议'}</Button>}
            </>} /></CardContent></Card>

        {Selected && <ProtocolDetails Row={Selected} CanReadHistory={CanReadHistory} Params={Params} />}
    </div>;
}

function ProtocolTable(Input: Readonly<{ Rows: readonly ProtocolRecord[]; SelectedId: string; OnSelect: (Row: ProtocolRecord) => void }>): ReactNode {
    return <Table className="min-w-[1120px]"><TableHeader><TableRow><TableHead>协议 / 配置</TableHead><TableHead>范围</TableHead><TableHead>绑定数</TableHead><TableHead>活动 Session</TableHead><TableHead>累计上行</TableHead><TableHead>累计下行</TableHead><TableHead>累计 P95</TableHead><TableHead>统计覆盖</TableHead></TableRow></TableHeader>
        <TableBody>{Input.Rows.map(Row => <TableRow key={Row.Id} data-state={Row.Id === Input.SelectedId ? 'selected' : undefined} className="cursor-pointer" onClick={() => Input.OnSelect(Row)}>
            <TableCell><button type="button" className="max-w-60 text-left font-medium hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring" onClick={Event => { Event.stopPropagation(); Input.OnSelect(Row); }}>
                {Row.Name}<span className="block break-all font-mono text-xs font-normal text-muted-foreground">{Row.Id}</span></button></TableCell>
            <TableCell><Badge Tone={Row.Kind === 'instance' ? 'info' : 'neutral'}>{Row.Kind === 'instance' ? '配置实例' : '类型统计'}</Badge></TableCell>
            <TableCell>{FormatCount(Row.ConfiguredBindings)}</TableCell><TableCell>{Row.ActiveSessions === null ? '未提供' : FormatCount(Row.ActiveSessions)}</TableCell>
            <TableCell>{Row.Traffic === null ? '未提供' : FormatBytes(Row.Traffic.Up)}</TableCell><TableCell>{Row.Traffic === null ? '未提供' : FormatBytes(Row.Traffic.Down)}</TableCell>
            <TableCell>{Row.Latency?.Available && Row.Latency.P95Ms !== null ? `${FormatCount(Row.Latency.P95Ms)} ms` : '未提供'}</TableCell>
            <TableCell className="max-w-80 whitespace-normal text-muted-foreground">{Row.Coverage || '未提供'}</TableCell>
        </TableRow>)}</TableBody></Table>;
}

function ProtocolDetails(Input: Readonly<{ Row: ProtocolRecord; CanReadHistory: boolean; Params: URLSearchParams }>): ReactNode {
    const Row = Input.Row;
    const IsInstance = Row.Kind === 'instance';
    const Scope = IsInstance ? 'protocol_instance' : 'protocol_type';
    const Key = IsInstance ? Row.Id : Row.TypeKey ?? ProtocolHistoryTypeKey(Row.Name);
    const SessionProtocol = ProtocolHistoryTypeKey(Row.Name) === null ? Row.Name : Row.Name.toLowerCase();
    const SessionPath = WithTime(`/sessions?protocol=${encodeURIComponent(SessionProtocol)}`, Input.Params);
    return <section className="space-y-3" aria-label={`${Row.Name} 协议详情`}>
        <div className="flex flex-wrap items-center justify-between gap-3"><div><div className="flex flex-wrap items-center gap-2"><h2 className="text-lg font-semibold">{Row.Name}</h2><Badge Tone={IsInstance ? 'info' : 'neutral'}>{IsInstance ? '配置实例' : '类型统计'}</Badge></div><p className="font-mono text-xs text-muted-foreground">{Row.Id}{!IsInstance && Key ? ` · 历史键 ${Key}` : ''}</p></div>
            <NavLink className="inline-flex h-9 items-center rounded-md border px-3 text-sm font-medium hover:bg-muted" to={SessionPath}>查看关联连接<ArrowRight className="ml-1 size-4" aria-hidden="true" /></NavLink>
        </div>
        <Card><CardHeader className="pb-2"><CardTitle>当前统计与归属范围</CardTitle><CardDescription>{Row.Coverage || '服务端未提供统计范围'}</CardDescription></CardHeader>
            <CardContent><dl className="grid grid-cols-2 border-t sm:grid-cols-3 xl:grid-cols-6 [&>div]:border-b [&>div]:py-3">
                <Fact Label="配置绑定" Value={FormatCount(Row.ConfiguredBindings)} /><Fact Label="活动 Session" Value={Row.ActiveSessions === null ? '未提供' : FormatCount(Row.ActiveSessions)} />
                <Fact Label="累计上行" Value={Row.Traffic ? FormatBytes(Row.Traffic.Up) : '未提供'} /><Fact Label="累计下行" Value={Row.Traffic ? FormatBytes(Row.Traffic.Down) : '未提供'} />
                <Fact Label="累计 P50" Value={LatencyValue(Row.Latency?.P50Ms ?? null)} /><Fact Label="累计 P95" Value={LatencyValue(Row.Latency?.P95Ms ?? null)} />
            </dl></CardContent>
        </Card>
        {Input.CanReadHistory && Key ? <section className="grid min-w-0 gap-3 xl:grid-cols-2" aria-label="协议窗口趋势">
            <HistoryPanel Scope={Scope} ResourceKey={Key} Title={`${Row.Name} 上下行速率`} Kind="traffic" />
            <HistoryPanel Scope={Scope} ResourceKey={Key} Title={`${Row.Name} 识别准入延迟`} Kind="latency" Metric="recognition_admission" />
        </section> : <div className="rounded-lg border px-4 py-3 text-sm text-muted-foreground" role="status">
            {!Input.CanReadHistory ? '当前实例未开放窗口历史，累计统计不会被画成趋势。' : '协议记录缺少可核对的历史身份键，因此没有发送趋势查询。'}
        </div>}
    </section>;
}

function Reading(Input: Readonly<{ Label: string; Value: string; Detail: string; Icon: ReactNode }>): ReactNode {
    return <div className="py-1.5"><dt className="flex items-center gap-1.5 text-xs text-muted-foreground">{Input.Icon}{Input.Label}</dt><dd className="mt-0.5 text-sm font-semibold tabular-nums">{Input.Value}</dd><dd className="mt-0.5 text-xs text-muted-foreground">{Input.Detail}</dd></div>;
}

function Fact(Input: Readonly<{ Label: string; Value: string }>): ReactNode {
    return <div className="min-w-0 px-3 first:pl-0"><dt className="text-xs text-muted-foreground">{Input.Label}</dt><dd className="mt-1 text-sm font-semibold tabular-nums">{Input.Value}</dd></div>;
}

function LatencyValue(Value: string | null): string { return Value === null ? '未提供' : `${FormatCount(Value)} ms`; }
