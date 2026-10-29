/** @file 以横向监听清单和选中入口趋势构成的代理入口页。 */
import { useMemo } from 'react';
import type { ReactNode } from 'react';
import { CheckCircle2, Radio, RefreshCw, Router, Waypoints } from 'lucide-react';
import { useSearchParams } from 'react-router';
import { Button } from '@/Components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/ui/card';
import { Input } from '@/Components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/Components/ui/table';
import { Badge, EmptyState, FormatCount, LoadMoreButton, PageHeader, QueryState, StatusBadge } from '../../Components/Ui';
import type { IngressRecord } from '../../Services/AdminDataSource';
import { HistoryPanel } from '../HistoryPanel';
import { TimeRangeControl } from '../TimeRange';
import { useAdminInfiniteQuery } from '../UseOperations';
import { DecideIngressRowPresentation, PresentIngressRows } from './IngressPresentation';

export default function IngressesPage(): ReactNode {
    const [Params, SetParams] = useSearchParams();
    const Query = useAdminInfiniteQuery('ingresses', (Source, Page) => Source.GetIngresses(Page));
    const Pages = Query.data?.pages;
    const Rows = useMemo(() => Pages?.flatMap(Page => Page.Items) ?? [], [Pages]);
    const DisplayRows = useMemo(() => PresentIngressRows(Rows), [Rows]);
    const RuntimeRows = DisplayRows.filter(Row => Row.HasRuntimeState).map(Row => Row.Value);
    const Ready = RuntimeRows.filter(Row => Row.Ready).length;
    const Bound = RuntimeRows.filter(Row => Row.BoundAddress !== null).length;
    const MeasuredConnections = RuntimeRows.filter(Row => Row.ActiveConnections !== null);
    const Connections = MeasuredConnections.reduce((Total, Row) => Total + BigInt(Row.ActiveConnections!), 0n).toString();
    const Search = Params.get('ingress_q') ?? '';
    const Filtered = useMemo(() => {
        const Needle = Search.trim().toLocaleLowerCase();
        return Needle ? DisplayRows.filter(({ Value }) => `${Value.Id} ${Value.Transport} ${Value.ConfiguredAddress} ${Value.BoundAddress ?? ''} ${Value.Protocols.join(' ')} ${Value.Carriers.join(' ')}`.toLocaleLowerCase().includes(Needle)) : DisplayRows;
    }, [DisplayRows, Search]);
    const FocusId = Params.get('ingress') ?? '';
    const Focus = FocusId ? Filtered.find(Row => Row.Value.Id === FocusId) ?? null : null;
    const Select = (Row: IngressRecord): void => {
        const Next = new URLSearchParams(Params);
        if (Row.Id === FocusId) { Next.delete('ingress'); Next.delete('transport'); }
        else { Next.set('ingress', Row.Id); Next.set('transport', Row.Transport); }
        SetParams(Next);
    };
    const UpdateSearch = (Value: string): void => {
        const Next = new URLSearchParams(Params);
        if (Value) Next.set('ingress_q', Value); else Next.delete('ingress_q');
        SetParams(Next, { replace: true });
    };
    const Refresh = async (): Promise<void> => { await Query.refetch(); };

    return <div className="space-y-4">
        <PageHeader Title="代理入口" Description="用一张清单对照配置地址、实际绑定、连接数与就绪状态。选中入口后查看它自己的流量和准入延迟。"
            Actions={<><TimeRangeControl /><Button type="button" variant="outline" disabled={Query.isFetching} onClick={() => void Refresh()}><RefreshCw className={Query.isFetching ? 'animate-spin' : ''} aria-hidden="true" />刷新快照</Button></>} />
        <dl className="grid grid-cols-2 gap-x-5 border-y py-2 sm:grid-cols-4" aria-label="入口汇总">
            <Reading Label="已载入入口" Value={`${Rows.length}${Query.hasNextPage ? '+' : ''}`} />
            <Reading Label="运行态就绪" Value={RuntimeRows.length ? `${Ready} / ${RuntimeRows.length}` : '未提供'} />
            <Reading Label="有实际绑定" Value={FormatCount(Bound)} />
            <Reading Label="活动连接" Value={MeasuredConnections.length ? FormatCount(Connections) : '未提供'} Detail={MeasuredConnections.length < RuntimeRows.length ? `仅 ${MeasuredConnections.length} / ${RuntimeRows.length} 个 listener 提供连接数` : '已观测 listener 合计'} />
        </dl>

        <Card className="min-w-0">
            <CardHeader className="gap-3 pb-3"><div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"><div><CardTitle>监听清单</CardTitle><CardDescription>同一传输类型可能有多条配置；运行状态按后端实际返回范围展示。</CardDescription></div><span className="text-xs text-muted-foreground">当前载入 {Filtered.length} 条</span></div>
                <Input aria-label="搜索代理入口" value={Search} onChange={Event => UpdateSearch(Event.target.value)} placeholder="搜索传输、配置 ID、地址、协议或承载方式" />
            </CardHeader>
            <CardContent className="pt-0"><QueryState Pending={Query.isPending} Error={Query.error} Label="入口记录" HasData={Query.data !== undefined} Retry={() => void Query.refetch()} Retrying={Query.isFetching}
                Children={Filtered.length === 0 ? <EmptyState Title="没有匹配的入口" Detail="调整搜索词，或等待数据源返回监听配置。" /> : <>
                    <div className="overflow-x-auto"><IngressTable Rows={Filtered} FocusId={Focus?.Value.Id ?? ''} OnSelect={Select} /></div>
                    <LoadMoreButton HasMore={Query.hasNextPage ?? false} Busy={Query.isFetchingNextPage} OnLoad={() => void Query.fetchNextPage()} />
                </>} />
            </CardContent>
        </Card>

        {Focus && <IngressDetails Row={Focus.Value} HasRuntimeState={Focus.HasRuntimeState} />}
    </div>;
}

function IngressTable(Input: Readonly<{
    Rows: readonly ReturnType<typeof PresentIngressRows>[number][];
    FocusId: string;
    OnSelect: (Value: IngressRecord) => void;
}>): ReactNode {
    return <Table className="min-w-[1000px]"><TableHeader><TableRow><TableHead>传输 / 入口 ID</TableHead><TableHead>配置监听地址</TableHead><TableHead>实际绑定地址</TableHead><TableHead>代理协议</TableHead><TableHead>承载方式</TableHead><TableHead>活动连接</TableHead><TableHead>状态</TableHead></TableRow></TableHeader>
        <TableBody>{Input.Rows.map(({ Value, HasRuntimeState }) => {
            const Presentation = DecideIngressRowPresentation(Value, HasRuntimeState);
            return <TableRow key={Value.Id} data-state={Value.Id === Input.FocusId ? 'selected' : undefined} className="cursor-pointer" onClick={() => Input.OnSelect(Value)}>
                <TableCell><button type="button" className="text-left font-medium hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring" onClick={Event => { Event.stopPropagation(); Input.OnSelect(Value); }}>
                    {Value.Transport.toUpperCase()}<span className="block font-mono text-xs font-normal text-muted-foreground">{Value.Id}</span></button></TableCell>
                <TableCell><code className="whitespace-nowrap font-mono text-xs">{Value.ConfiguredAddress}</code></TableCell>
                <TableCell><code className="whitespace-nowrap font-mono text-xs">{Value.BoundAddress ?? '未提供'}</code></TableCell>
        <TableCell><TagList Values={Value.Protocols} /></TableCell><TableCell><TagList Values={Value.Carriers} /></TableCell>
                <TableCell className="tabular-nums">{HasRuntimeState && Value.ActiveConnections !== null ? FormatCount(Value.ActiveConnections) : '未提供'}</TableCell>
                <TableCell><StatusBadge Label={Presentation.Label} Tone={Presentation.Tone} />{Value.Reason && <span className="ml-2 max-w-48 text-xs text-muted-foreground">{Value.Reason}</span>}</TableCell>
            </TableRow>;
        })}</TableBody></Table>;
}

function IngressDetails(Input: Readonly<{ Row: IngressRecord; HasRuntimeState: boolean }>): ReactNode {
    const Row = Input.Row;
    const Presentation = DecideIngressRowPresentation(Row, Input.HasRuntimeState);
    return <section className="space-y-3" aria-label={`${Row.Id} 入口详情`}>
        <div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="text-lg font-semibold">{Row.Id}</h2><p className="text-sm text-muted-foreground">{Row.Transport.toUpperCase()} listener · 配置与运行态分开核对</p></div><StatusBadge Label={Presentation.Label} Tone={Presentation.Tone} /></div>
        <div className="grid min-w-0 gap-3 xl:grid-cols-[minmax(18rem,0.8fr)_minmax(0,1.2fr)]">
            <Card className="min-w-0"><CardHeader className="pb-2"><CardTitle>绑定与承载</CardTitle><CardDescription>选中入口 {Row.Id}</CardDescription></CardHeader><CardContent>
                <dl className="grid grid-cols-2 gap-x-4"><Fact Label="配置监听" Value={Row.ConfiguredAddress} /><Fact Label="实际绑定" Value={Row.BoundAddress ?? '未提供'} />
                    <Fact Label="活动连接" Value={Input.HasRuntimeState && Row.ActiveConnections !== null ? FormatCount(Row.ActiveConnections) : '未提供'} />
                    <Fact Label="期望状态" Value={Row.ExpectedState ?? '未提供'} /><Fact Label="实际状态" Value={Input.HasRuntimeState ? Row.ActualState ?? '未提供' : '未单独观测'} />
                    <Fact Label="状态起始" Value={Row.StateSince ?? '未提供'} /></dl>
                <div className="mt-3 grid gap-3 border-t pt-3 sm:grid-cols-2"><TagSection Title="代理协议" Values={Row.Protocols} /><TagSection Title="承载方式" Values={Row.Carriers} /></div>
                {Row.Reason && <p className="notice-warning mt-3 rounded-md px-3 py-2 text-sm">{Row.Reason}</p>}
            </CardContent></Card>
            <section className="grid min-w-0 gap-3 lg:grid-cols-2" aria-label="入口历史趋势">
                <HistoryPanel Scope="ingress" ResourceKey={Row.Id} Title={`${Row.Transport.toUpperCase()} 上下行速率`} Kind="traffic" />
                <HistoryPanel Scope="ingress" ResourceKey={Row.Id} Title="识别准入延迟" Kind="latency" Metric="recognition_admission" />
            </section>
        </div>
    </section>;
}

function TagSection(Input: Readonly<{ Title: string; Values: readonly string[] }>): ReactNode {
    return <section><h3 className="text-xs font-medium text-muted-foreground">{Input.Title}</h3><div className="mt-1.5 flex flex-wrap gap-1.5">{Input.Values.length ? Input.Values.map(Value => <Badge key={Value} Tone="neutral">{Value}</Badge>) : <span className="text-sm text-muted-foreground">未提供</span>}</div></section>;
}

function TagList(Input: Readonly<{ Values: readonly string[] }>): ReactNode {
    return Input.Values.length ? <div className="flex max-w-56 flex-wrap gap-1">{Input.Values.slice(0, 3).map(Value => <Badge key={Value} Tone="neutral" ClassName="font-normal">{Value}</Badge>)}{Input.Values.length > 3 && <Badge Tone="neutral">+{Input.Values.length - 3}</Badge>}</div> : <span className="text-xs text-muted-foreground">未提供</span>;
}

function Reading(Input: Readonly<{ Label: string; Value: string; Detail?: string }>): ReactNode {
    return <div className="py-1.5"><dt className="flex items-center gap-1.5 text-xs text-muted-foreground">{Input.Label === '已载入入口' ? <Router size={14} aria-hidden="true" /> : Input.Label === '运行态就绪' ? <CheckCircle2 size={14} aria-hidden="true" /> : Input.Label === '活动连接' ? <Waypoints size={14} aria-hidden="true" /> : <Radio size={14} aria-hidden="true" />}{Input.Label}</dt>
        <dd className="mt-0.5 text-sm font-semibold tabular-nums">{Input.Value}</dd>{Input.Detail && <dd className="mt-0.5 text-xs text-muted-foreground">{Input.Detail}</dd>}</div>;
}

function Fact(Input: Readonly<{ Label: string; Value: string }>): ReactNode {
    return <div className="min-w-0 border-b py-2"><dt className="text-xs text-muted-foreground">{Input.Label}</dt><dd className="mt-1 break-all font-mono text-xs">{Input.Value}</dd></div>;
}
