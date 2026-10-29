/** @file 以 Worker 清单、实时趋势和关联会话构成的运维工作台。 */
import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { ArrowRight, CircleAlert, Info, RefreshCw, ShieldCheck } from 'lucide-react';
import { NavLink, useSearchParams } from 'react-router';
import { Alert, AlertDescription, AlertTitle } from '@/Components/ui/alert';
import { Button } from '@/Components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/ui/card';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/Components/ui/dialog';
import { Input } from '@/Components/ui/input';
import { Popover, PopoverContent, PopoverTrigger } from '@/Components/ui/popover';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/Components/ui/table';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/Components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/Components/ui/tabs';
import { Badge, EmptyState, FormatBytes, FormatCount, LoadMoreButton, MobileMasterBack, PageHeader, QueryState, StatusBadge, ToneForState, useMobileMasterFocus } from '../../Components/Ui';
import type { HistoryMetric, SessionRecord, WorkerRecord } from '../../Services/AdminDataSource';
import { HistoryPanel } from '../HistoryPanel';
import { TimeRangeControl, WithTime } from '../TimeRange';
import { useAdminInfiniteQuery, useAdminMutation, useAdminQuery, useAdminServices, useBootstrapIdentity } from '../UseOperations';
import { CheckWorkerIdentity } from './WorkerIdentity';
import type { ExpectedWorkerIdentity } from './WorkerIdentity';
import { useWorkerActivityTrend, WorkerActivityTrend } from './WorkerActivityTrend';

type WorkerFilter = 'all' | 'accepting' | 'draining' | 'stopped';
type DelayMetric = Exclude<HistoryMetric, 'traffic'>;

export default function WorkersPage(): ReactNode {
    const [Params, SetParams] = useSearchParams();
    const [MobileView, SetMobileView] = useState<'list' | 'detail'>(() => Params.has('worker') ? 'detail' : 'list');
    useMobileMasterFocus(MobileView);
    const [DrainDialogOpen, SetDrainDialogOpen] = useState(false);
    const Services = useAdminServices();
    const Bootstrap = useBootstrapIdentity();
    const Query = useAdminInfiniteQuery('workers', (Source, Page) => Source.GetWorkers(Page));
    const Workers = Query.data?.pages.flatMap(Page => Page.Items) ?? [];
    const Search = Params.get('q') ?? '';
    const CandidateFilter = Params.get('state') ?? 'all';
    const Filter: WorkerFilter = CandidateFilter === 'accepting' || CandidateFilter === 'draining' || CandidateFilter === 'stopped' ? CandidateFilter : 'all';
    const Filtered = useMemo(() => Workers.filter(Worker => {
        const MatchesText = !Search || `${Worker.Id} ${Worker.Name}`.toLowerCase().includes(Search.toLowerCase());
        return MatchesText && (Filter === 'all' || Filter === 'accepting' && Worker.Accepting || Filter === 'draining' && Worker.State === 'draining' || Filter === 'stopped' && !Worker.Running);
    }), [Workers, Search, Filter]);

    const SelectedId = Params.get('worker') ?? '';
    const Expected: ExpectedWorkerIdentity = { Id: SelectedId, ProcessId: Params.get('process'), GenerationId: Params.get('generation') };
    const Exact = useAdminQuery('worker-target', Source => Source.GetWorkers({ Cursor: '0', Limit: 1, Id: SelectedId }), {
        Enabled: !!SelectedId, Scope: [SelectedId, Expected.ProcessId ?? '', Expected.GenerationId ?? ''],
    });
    const ExactWorker = Exact.data?.Items.find(Worker => Worker.Id === SelectedId) ?? null;
    const Identity = SelectedId ? CheckWorkerIdentity(Expected, ExactWorker) : 'verified';
    const Selected = SelectedId ? Identity === 'verified' ? ExactWorker : null : Filtered[0] ?? null;
    const SessionScope = [Selected?.ProcessId ?? '', Selected?.GenerationId ?? '', Selected?.Id ?? ''];
    const Sessions = useAdminInfiniteQuery('worker-sessions', (Source, Page) => Source.GetSessions({
        ...Page,
        ...(Selected ? { ProcessId: Selected.ProcessId, GenerationId: Selected.GenerationId, WorkerId: Selected.Id } : {}),
    }), SessionScope);
    const SessionPages = Sessions.data?.pages ?? [];
    const AllSessions = useMemo(() => SessionPages.flatMap(Page => Page.Items), [SessionPages]);
    const RelatedSessions = useMemo(() => AllSessions.filter(Session => Selected &&
        Session.WorkerId === Selected.Id && Session.ProcessId === Selected.ProcessId && Session.GenerationId === Selected.GenerationId),
    [AllSessions, Selected]);
    const FilterSupported = Services.Mode === 'demo' || Bootstrap.data?.Capabilities.includes('sessions.filter') === true;
    const SessionPartial = !FilterSupported || Sessions.hasNextPage === true;

    const Drain = useAdminMutation((Source, Worker: Pick<WorkerRecord, 'Id' | 'ProcessId' | 'GenerationId'>) => Source.DrainWorker(Worker));
    const RequestedMetric = Params.get('worker_latency');
    const DelayMetricValue: DelayMetric = RequestedMetric === 'dns_resolution' || RequestedMetric === 'tcp_connect'
        ? RequestedMetric : 'recognition_admission';
    const Update = (Key: string, Value: string): void => {
        const Next = new URLSearchParams(Params);
        if (Value && Value !== 'all') Next.set(Key, Value); else Next.delete(Key);
        SetParams(Next, { replace: Key === 'q' });
    };
    const SelectWorker = (Worker: WorkerRecord): void => {
        const Next = new URLSearchParams(Params);
        Next.set('worker', Worker.Id);
        Next.set('process', Worker.ProcessId);
        Next.set('generation', Worker.GenerationId);
        SetParams(Next);
        SetMobileView('detail');
    };
    const Refresh = async (): Promise<void> => { await Promise.all([Query.refetch(), Sessions.refetch(), Exact.refetch()]); };
    const ExecuteDrain = async (): Promise<void> => {
        if (!Selected) return;
        await Drain.mutateAsync(Selected);
        SetDrainDialogOpen(false);
    };
    const Accepting = Workers.filter(Worker => Worker.Accepting).length;
    const Draining = Workers.filter(Worker => Worker.State === 'draining').length;
    const Queue = Workers.reduce((Total, Worker) => Total + BigInt(Worker.QueueDepth), 0n).toString();
    const Failures = Workers.reduce((Total, Worker) => Total + BigInt(Worker.CommandsFailed), 0n).toString();

    return <div className="space-y-4">
        <PageHeader Title="工作线程" Description="先比较各 Worker 的负载与派发状态，再查看选中槽位的会话、用户和历史趋势。"
            Actions={<><TimeRangeControl /><Button type="button" variant="outline" onClick={() => void Refresh()} disabled={Query.isFetching || Sessions.isFetching}>
                <RefreshCw className={Query.isFetching || Sessions.isFetching ? 'animate-spin' : ''} aria-hidden="true" />刷新快照
            </Button></>} />
        <dl className="grid grid-cols-2 gap-x-5 border-y py-2 sm:grid-cols-4" aria-label="Worker 当前汇总">
            <CompactReading Label="接收新任务" Value={Query.data ? `${Accepting} / ${Workers.length}${Query.hasNextPage ? '+' : ''}` : '—'} />
            <CompactReading Label="排空中" Value={Query.data ? FormatCount(Draining) : '—'} />
            <CompactReading Label="待处理命令" Value={Query.data ? FormatCount(Queue) : '—'} />
            <CompactReading Label="命令失败 · 累计" Value={Query.data ? FormatCount(Failures) : '—'} />
        </dl>

        <div role="region" aria-label="Worker 清单" className={MobileView === 'detail' ? 'hidden md:block' : ''} data-mobile-master-list tabIndex={-1}><Card className="min-w-0">
            <CardHeader className="gap-3 pb-3">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <div><CardTitle>Worker 清单</CardTitle><CardDescription>选择任一行；下面的会话和趋势会按该槽位的完整身份读取。</CardDescription></div>
                    <Badge Tone="neutral">已载入 {Workers.length}{Query.hasNextPage ? '+' : ''}</Badge>
                </div>
                <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                    <Input aria-label="搜索 Worker" value={Search} onChange={Event => Update('q', Event.target.value)} placeholder="搜索 Worker ID 或名称" className="lg:max-w-sm" />
                    <div className="flex flex-wrap gap-2" role="group" aria-label="Worker 状态筛选">
                        {(['all', 'accepting', 'draining', 'stopped'] as const).map(Value => <Button key={Value} type="button" size="sm" variant={Filter === Value ? 'default' : 'outline'} onClick={() => Update('state', Value)}>{FilterLabel(Value)}</Button>)}
                    </div>
                </div>
            </CardHeader>
            <CardContent className="pt-0">
                <QueryState Pending={Query.isPending} Error={Query.error} Label="Worker 列表" HasData={Query.data !== undefined} Retry={() => void Query.refetch()} Retrying={Query.isFetching}
                    Children={Filtered.length === 0 ? <EmptyState Title="没有匹配的 Worker" Detail="更换搜索词、状态筛选或载入更多记录。" /> : <>
                        <p className="mb-2 text-xs text-muted-foreground sm:hidden">左右滑动表格，可查看任务、邮箱、流量与诊断计数。</p>
                        <div className="overflow-x-auto"><WorkerTable Rows={Filtered} Selected={Selected} OnSelect={SelectWorker} /></div>
                        <p className="mt-2 text-xs text-muted-foreground">任务、流量、派发失败和事件丢弃均按 Worker 返回；计数为累计值，流量为累计字节。</p>
                        <LoadMoreButton HasMore={Query.hasNextPage ?? false} Busy={Query.isFetchingNextPage} OnLoad={() => void Query.fetchNextPage()} />
                    </>} />
            </CardContent>
        </Card></div>

        <div role="region" aria-label="Worker 详情" className={MobileView === 'list' ? 'hidden md:block' : ''}>
        <div className="px-4 pt-4 md:hidden"><MobileMasterBack Label="返回 Worker 列表" OnClick={() => SetMobileView('list')} /></div>
        {Selected && <WorkerWorkspace key={`${Selected.ProcessId}:${Selected.GenerationId}:${Selected.Id}`} Worker={Selected} Identity={Identity} ExactPending={!!SelectedId && Exact.isPending}
            DemoMode={Services.Mode === 'demo'}
            Sessions={RelatedSessions} SessionPending={Sessions.isPending} SessionError={Sessions.error} SessionPartial={SessionPartial}
            SessionFilterSupported={FilterSupported}
            DataUpdatedAt={Sessions.dataUpdatedAt} HasMore={Sessions.hasNextPage ?? false} LoadingMore={Sessions.isFetchingNextPage}
            OnLoadMore={() => void Sessions.fetchNextPage()} DelayMetric={DelayMetricValue}
            OnDelayMetric={Value => Update('worker_latency', Value)} Params={Params}
            CanDrainCapability={Bootstrap.data?.Capabilities.includes('workers.drain') === true}
            DrainBusy={Drain.isPending} DialogOpen={DrainDialogOpen} SetDialogOpen={SetDrainDialogOpen}
            OnDrain={ExecuteDrain} ResultError={Drain.error?.message} ResultMessage={Drain.data?.Message ?? null}
            QueryReady={Query.isSuccess && !Query.isFetching} BootstrapError={Bootstrap.error} />}
        {!Selected && <Card><CardContent className="py-10"><EmptyState Title="没有可显示的 Worker" Detail={Identity === 'verified' ? '先载入 Worker 清单。' : '深链目标未通过身份核验，不会用同号槽位代替原目标。'} /></CardContent></Card>}
        </div>
    </div>;
}

function WorkerTable(Input: Readonly<{ Rows: readonly WorkerRecord[]; Selected: WorkerRecord | null; OnSelect: (Worker: WorkerRecord) => void }>): ReactNode {
    return <Table aria-label="Worker 列表" className="min-w-[940px]"><TableHeader><TableRow>
        <TableHead>Worker</TableHead><TableHead>状态</TableHead><TableHead>活动任务</TableHead><TableHead>命令邮箱</TableHead>
        <TableHead>累计上行</TableHead><TableHead>累计下行</TableHead><TableHead>派发拒绝</TableHead><TableHead>命令失败</TableHead><TableHead>事件丢弃</TableHead>
    </TableRow></TableHeader><TableBody>{Input.Rows.map(Worker => <TableRow key={`${Worker.ProcessId}-${Worker.GenerationId}-${Worker.Id}`}
        data-state={Input.Selected?.ProcessId === Worker.ProcessId && Input.Selected.GenerationId === Worker.GenerationId && Input.Selected.Id === Worker.Id ? 'selected' : undefined}
        className="cursor-pointer" onClick={() => Input.OnSelect(Worker)}>
        <TableCell><button type="button" className="text-left font-medium hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring" onClick={Event => { Event.stopPropagation(); Input.OnSelect(Worker); }}>
            {Worker.Name}<span className="block font-mono text-xs font-normal text-muted-foreground">Worker {Worker.Id} · Gen {Worker.GenerationId}</span></button></TableCell>
        <TableCell><StatusBadge Label={Worker.Accepting ? '接收中' : Worker.State === 'draining' ? '排空中' : '已停止'} Tone={Worker.Accepting ? 'good' : ToneForState(Worker.State)} /></TableCell>
        <TableCell className="tabular-nums">{FormatCount(Worker.ActiveTasks)}</TableCell>
        <TableCell className="tabular-nums">{FormatCount(Worker.QueueDepth)} / {FormatCount(Worker.QueueCapacity)}</TableCell>
        <TableCell>{Worker.Traffic ? FormatBytes(Worker.Traffic.Up) : '未提供'}</TableCell><TableCell>{Worker.Traffic ? FormatBytes(Worker.Traffic.Down) : '未提供'}</TableCell>
        <TableCell>{FormatCount(Rejections(Worker))}</TableCell><TableCell>{FormatCount(Worker.CommandsFailed)}</TableCell><TableCell>{FormatCount(Worker.DroppedEvents)}</TableCell>
    </TableRow>)}</TableBody></Table>;
}

function WorkerWorkspace(Input: Readonly<{
    Worker: WorkerRecord; Identity: ReturnType<typeof CheckWorkerIdentity>; ExactPending: boolean; DemoMode: boolean;
    Sessions: readonly SessionRecord[]; SessionPending: boolean; SessionError: Error | null; SessionPartial: boolean;
    SessionFilterSupported: boolean;
    DataUpdatedAt: number; HasMore: boolean; LoadingMore: boolean; OnLoadMore: () => void;
    DelayMetric: DelayMetric; OnDelayMetric: (Value: DelayMetric) => void; Params: URLSearchParams;
    CanDrainCapability: boolean; DrainBusy: boolean; DialogOpen: boolean; SetDialogOpen: (Open: boolean) => void; OnDrain: () => Promise<void>;
    ResultError: string | undefined; ResultMessage: string | null; QueryReady: boolean; BootstrapError: Error | null;
}>): ReactNode {
    const Worker = Input.Worker;
    const QueueRatio = BigInt(Worker.QueueCapacity) > 0n ? Number(BigInt(Worker.QueueDepth) * 10_000n / BigInt(Worker.QueueCapacity)) / 100 : null;
    const Active = Input.Sessions.filter(Session => Session.Active || Session.Draining);
    const Accounts = new Set(Active.map(Session => Session.AccountId)).size;
    const CountPrefix = Input.SessionPartial ? '≥ ' : '';
    const CanDrain = Worker.Running && Worker.Accepting && Input.QueryReady && Input.Identity === 'verified' && Input.CanDrainCapability;
    const HistoryIdentity = `${Worker.ProcessId}:${Worker.GenerationId}:${Worker.Id}:${Input.SessionPartial ? 'partial' : 'complete'}`;
    const [TrendView, SetTrendView] = useState<'traffic' | 'latency' | 'activity'>('traffic');
    const ActivityTrend = useWorkerActivityTrend({ Scope: HistoryIdentity, Sessions: Input.Sessions, DataUpdatedAt: Input.DataUpdatedAt,
        Partial: Input.SessionPartial, DemoMode: Input.DemoMode });
    const DetailLink = WithTime(`/sessions?worker=${encodeURIComponent(Worker.Id)}&process=${encodeURIComponent(Worker.ProcessId)}&generation=${encodeURIComponent(Worker.GenerationId)}`, Input.Params);

    if (Input.ExactPending) return <Card><CardContent className="py-8 text-center text-sm text-muted-foreground">正在按 Process、Generation 和 Worker ID 核验目标…</CardContent></Card>;
    if (Input.Identity !== 'verified') return <Alert variant="destructive"><CircleAlert aria-hidden="true" /><AlertTitle>Worker 身份未核验</AlertTitle><AlertDescription>深链目标与当前运行快照不一致，未加载它的会话或发送排空操作。</AlertDescription></Alert>;
    return <section className="min-w-0 space-y-3 border-t pt-3" aria-label={`${Worker.Name} 详细信息`}>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><h2 className="text-base font-semibold tracking-tight">{Worker.Name}</h2><StatusBadge Label={Worker.Accepting ? '接收中' : Worker.State === 'draining' ? '排空中' : '已停止'} Tone={Worker.Accepting ? 'good' : ToneForState(Worker.State)} /></div>
                    <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground"><span>Process <span className="font-mono text-foreground/80">{Worker.ProcessId}</span></span>
                        <Popover><PopoverTrigger asChild><Button type="button" variant="ghost" size="sm" className="h-6 px-1.5 text-muted-foreground" aria-label="查看 Worker 实例身份"><Info aria-hidden="true" />实例身份</Button></PopoverTrigger>
                            <PopoverContent align="start"><p className="font-medium">实例身份</p><p className="break-all font-mono text-xs">Process {Worker.ProcessId} · Generation {Worker.GenerationId} · Worker {Worker.Id}</p></PopoverContent>
                        </Popover>
                    </div>
                </div>
            <div className="flex shrink-0 flex-wrap items-center gap-2 sm:justify-end">
                <NavLink className="inline-flex h-8 items-center rounded-md border px-2.5 text-sm font-medium hover:bg-muted" to={DetailLink}>全部连接<ArrowRight className="ml-1 size-4" aria-hidden="true" /></NavLink>
                <Dialog open={Input.DialogOpen} onOpenChange={Input.SetDialogOpen}>
                    <DialogTrigger asChild><Button type="button" variant="outline" size="sm" disabled={!CanDrain}>{Worker.State === 'draining' ? '正在排空' : '排空 Worker'}</Button></DialogTrigger>
                    <DialogContent><DialogHeader><DialogTitle>排空 {Worker.Name}？</DialogTitle><DialogDescription>将停止新增派发并请求任务取消。目标是 Process {Worker.ProcessId} · Generation {Worker.GenerationId} · Worker {Worker.Id}。</DialogDescription></DialogHeader>
                        <DialogFooter><Button variant="outline" onClick={() => Input.SetDialogOpen(false)}>取消</Button><Button variant="destructive" disabled={Input.DrainBusy} onClick={() => void Input.OnDrain()}>{Input.DrainBusy ? '正在提交…' : '确认排空'}</Button></DialogFooter>
                    </DialogContent>
                </Dialog>
            </div>
        </div>

        <dl className="grid grid-cols-2 border-y sm:grid-cols-3 xl:grid-cols-6 [&>div]:border-b [&>div]:py-2.5 sm:[&>div:nth-child(odd)]:border-r xl:[&>div]:border-r xl:[&>div:nth-child(6n)]:border-r-0">
            <Reading Label="活动任务" Value={FormatCount(Worker.ActiveTasks)} />
            <Reading Label={Input.SessionPartial ? '已载入活动连接' : '活动连接'} Value={Input.SessionPending ? '读取中' : Input.SessionError ? '读取失败' : `${CountPrefix}${FormatCount(Active.length)}`} />
            <Reading Label={Input.SessionPartial ? '已载入唯一账户' : '唯一活动账户'} Value={Input.SessionPending ? '读取中' : Input.SessionError ? '读取失败' : `${CountPrefix}${FormatCount(Accounts)}`} />
            <Reading Label="命令邮箱" Value={`${FormatCount(Worker.QueueDepth)} / ${FormatCount(Worker.QueueCapacity)}`} Detail={QueueRatio === null
                ? Worker.QueueCapacity == null ? '容量未提供' : '容量为 0，无法计算使用率。'
                : `${QueueRatio}% 占用`} />
            <Reading Label="累计上行" Value={FormatBytes(Worker.Traffic?.Up)} />
            <Reading Label="累计下行" Value={FormatBytes(Worker.Traffic?.Down)} />
        </dl>

        {Input.ResultError && <Alert variant="destructive"><CircleAlert aria-hidden="true" /><AlertTitle>排空结果尚未确认</AlertTitle><AlertDescription>{Input.ResultError}</AlertDescription></Alert>}
        {Input.ResultMessage && <Alert><ShieldCheck aria-hidden="true" /><AlertTitle>排空请求已提交</AlertTitle><AlertDescription>{Input.ResultMessage} 请刷新快照确认最终状态。</AlertDescription></Alert>}

        <Tabs defaultValue="trends" className="gap-0">
            <TabsList variant="line" className="h-10 w-full justify-start gap-3 overflow-x-auto rounded-none border-b bg-transparent p-0">
                <TabsTrigger value="trends" className="flex-none px-3">趋势</TabsTrigger>
                <TabsTrigger value="sessions" className="flex-none gap-2 px-3">关联连接<span className="text-xs tabular-nums text-muted-foreground">{Input.SessionPending ? '…' : `${CountPrefix}${FormatCount(Active.length)}`}</span></TabsTrigger>
                <TabsTrigger value="diagnostics" className="flex-none px-3">任务与派发</TabsTrigger>
            </TabsList>
            <TabsContent value="trends" className="mt-3">
                {Input.BootstrapError && <Alert className="mb-3" variant="destructive"><CircleAlert aria-hidden="true" /><AlertTitle>历史范围无法核验</AlertTitle><AlertDescription>当前实例能力读取失败，不显示可能来自旧实例的趋势。</AlertDescription></Alert>}
                <Tabs value={TrendView} onValueChange={Value => {
                    if (Value === 'traffic' || Value === 'latency' || Value === 'activity') SetTrendView(Value);
                }} className="gap-0">
                    <TabsList className="h-8">
                        <TabsTrigger value="traffic" className="flex-none px-3">流量</TabsTrigger>
                        <TabsTrigger value="latency" className="flex-none px-3">延迟</TabsTrigger>
                        <TabsTrigger value="activity" className="flex-none px-3">连接与账户</TabsTrigger>
                    </TabsList>
                    <TabsContent value="traffic" className="mt-3">
                        <HistoryPanel Scope="worker" ResourceKey={Worker.Id} Title={`${Worker.Name} 上下行速率`} Kind="traffic"
                            ClassName="min-w-0 [&_[data-slot=card-header]]:px-0 [&_[data-slot=card-header]]:pt-0 [&_[data-slot=card-content]]:px-0 [&_[data-slot=card-content]]:pb-0 [&_.history-plot]:h-64 sm:[&_.history-plot]:h-72" />
                    </TabsContent>
                    <TabsContent value="latency" className="mt-3">
                        <div className="mb-3 flex flex-wrap items-center gap-2"><span className="text-xs text-muted-foreground">延迟阶段</span>
                            <Select value={Input.DelayMetric} onValueChange={Value => Input.OnDelayMetric(Value as DelayMetric)}><SelectTrigger aria-label="Worker 延迟指标" className="h-8 w-36"><SelectValue /></SelectTrigger><SelectContent>
                                <SelectItem value="recognition_admission">识别准入</SelectItem><SelectItem value="dns_resolution">DNS 解析</SelectItem><SelectItem value="tcp_connect">TCP 建连</SelectItem>
                            </SelectContent></Select>
                        </div>
                        <HistoryPanel Scope="worker" ResourceKey={Worker.Id} Title={`${Worker.Name} 延迟`} Kind="latency" Metric={Input.DelayMetric}
                            ClassName="min-w-0 [&_[data-slot=card-header]]:px-0 [&_[data-slot=card-header]]:pt-0 [&_[data-slot=card-content]]:px-0 [&_[data-slot=card-content]]:pb-0 [&_.history-plot]:h-64 sm:[&_.history-plot]:h-72" />
                    </TabsContent>
                    <TabsContent value="activity" className="mt-3"><WorkerActivityTrend Trend={ActivityTrend} /></TabsContent>
                </Tabs>
            </TabsContent>
            <TabsContent value="sessions" className="mt-3 space-y-3">
                <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-2">
                    <div><h3 className="text-sm font-semibold">当前关联连接</h3><p className="mt-1 text-xs text-muted-foreground">按 Process、Generation、Worker 精确筛选；账户按当前 Session 中的 Account ID 标识。</p></div>
                    <span className="text-xs text-muted-foreground">已载入 {Input.SessionPending ? '读取中' : `${Input.Sessions.length}${Input.HasMore ? '+' : ''}`}</span>
                </div>
                {Input.SessionError && <Alert variant="destructive"><CircleAlert aria-hidden="true" /><AlertTitle>会话读取失败</AlertTitle><AlertDescription>{Input.SessionError.message}</AlertDescription></Alert>}
                {!Input.SessionFilterSupported && <Alert><Info aria-hidden="true" /><AlertTitle>当前接口未开放 Worker 会话筛选</AlertTitle><AlertDescription>连接和账户数只覆盖已经载入的全局会话页；请载入更多后再判断范围。</AlertDescription></Alert>}
                {Input.SessionPartial && <p className="text-xs text-muted-foreground">当前只统计已载入的 Worker 会话；载入更多后会更新表格与连接趋势。</p>}
                <QueryState Pending={Input.SessionPending} Error={null} Label="关联连接" HasData={!Input.SessionPending} Children={Active.length === 0
                    ? <EmptyState Title="当前没有已载入的活动连接" Detail="可能没有活跃 Session，或当前分页还未覆盖到这个 Worker。" />
                    : <><p className="mb-2 text-xs text-muted-foreground sm:hidden">左右滑动表格，可查看连接来源、目标和流量。</p><div className="min-w-0 overflow-x-auto"><SessionTable Rows={Active} Params={Input.Params} /></div></>} />
                <LoadMoreButton HasMore={Input.HasMore} Busy={Input.LoadingMore} OnLoad={Input.OnLoadMore} />
            </TabsContent>
            <TabsContent value="diagnostics" className="mt-3 space-y-3">
                <div><h3 className="text-sm font-semibold">任务与派发</h3><p className="mt-1 text-xs text-muted-foreground">执行量、派发结果、命令和观测均为实例累计计数。</p></div>
                <div className="grid gap-4 sm:grid-cols-2 2xl:grid-cols-4"><DetailGroup Title="任务" Items={[
                ['活动任务', FormatCount(Worker.ActiveTasks)], ['已启动', FormatCount(Worker.StartedTasks)], ['已完成', FormatCount(Worker.CompletedTasks)], ['已取消', FormatCount(Worker.CancelledTasks)],
            ]} /><DetailGroup Title="派发" Items={[
                ['已接收', FormatCount(Worker.DispatchAccepted)], ['队列满', FormatCount(Worker.DispatchFull)], ['已关闭', FormatCount(Worker.DispatchClosed)],
                ['Worker 不可用', FormatCount(Worker.DispatchUnavailable)], ['代次不匹配', FormatCount(Worker.DispatchGenerationRejected)],
            ]} /><DetailGroup Title="命令" Items={[
                ['已执行', FormatCount(Worker.CommandsExecuted)], ['失败', FormatCount(Worker.CommandsFailed)],
            ]} /><DetailGroup Title="传输与观测" Items={[
                ['累计传输终态', FormatCount(Worker.Traffic?.Events)], ['累计传输失败', FormatCount(Worker.Traffic?.Errors)], ['累计事件丢弃', FormatCount(Worker.DroppedEvents)],
            ]} /></div>
            </TabsContent>
        </Tabs>
    </section>;
}

function SessionTable(Input: Readonly<{ Rows: readonly SessionRecord[]; Params: URLSearchParams }>): ReactNode {
    return <Table className="min-w-[1050px]"><TableHeader><TableRow><TableHead>连接 / 账户</TableHead><TableHead>协议</TableHead><TableHead>传输</TableHead><TableHead>来源</TableHead><TableHead>目标</TableHead><TableHead>活动任务</TableHead><TableHead>上行累计</TableHead><TableHead>下行累计</TableHead><TableHead>状态</TableHead></TableRow></TableHeader>
        <TableBody>{Input.Rows.map(Session => {
            const Params = new URLSearchParams(Input.Params);
            Params.set('session', Session.Id); Params.set('process', Session.ProcessId); Params.set('identity_worker', Session.WorkerId);
            Params.set('identity_account', Session.AccountId); Params.set('generation', Session.GenerationId);
            return <TableRow key={`${Session.ProcessId}:${Session.GenerationId}:${Session.WorkerId}:${Session.AccountId}:${Session.Id}`}>
                <TableCell><NavLink className="font-mono text-sm font-medium hover:underline" to={WithTime(`/sessions?${Params}`, Input.Params)}>{Session.Id}</NavLink><span className="block font-mono text-xs text-muted-foreground">Account {Session.AccountId}</span></TableCell>
                <TableCell>{Session.Protocol}</TableCell><TableCell>{Session.Transport.toUpperCase()}</TableCell>
                <TableCell className="max-w-44 truncate font-mono" title={Session.SourceAddress}>{Session.SourceAddress || '未提供'}</TableCell>
                <TableCell className="max-w-52 truncate font-mono" title={Session.Target}>{Session.Target || '未提供'}</TableCell>
                <TableCell>{FormatCount(Session.ActiveTasks)}</TableCell><TableCell>{FormatBytes(Session.Traffic?.Up)}</TableCell><TableCell>{FormatBytes(Session.Traffic?.Down)}</TableCell>
                <TableCell><StatusBadge Label={Session.Draining ? '排空中' : '活动中'} Tone={Session.Draining ? 'warning' : 'good'} /></TableCell>
            </TableRow>;
        })}</TableBody></Table>;
}

function CompactReading(Input: Readonly<{ Label: string; Value: string }>): ReactNode {
    return <div className="py-1.5"><dt className="text-xs text-muted-foreground">{Input.Label}</dt><dd className="mt-0.5 text-sm font-semibold tabular-nums">{Input.Value}</dd></div>;
}

function Reading(Input: Readonly<{ Label: string; Value: string; Detail?: string }>): ReactNode {
    return <div className="min-w-0 px-3 first:pl-0"><dt className="text-xs text-muted-foreground">{Input.Label}</dt><dd className="mt-1 truncate text-lg font-semibold tabular-nums" title={Input.Value}>{Input.Value}</dd>{Input.Detail && <dd className="mt-0.5 text-xs text-muted-foreground">{Input.Detail}</dd>}</div>;
}

function Rejections(Worker: WorkerRecord): string {
    return (BigInt(Worker.DispatchFull) + BigInt(Worker.DispatchClosed) + BigInt(Worker.DispatchUnavailable) + BigInt(Worker.DispatchGenerationRejected)).toString();
}

function FilterLabel(Value: WorkerFilter): string {
    return Value === 'accepting' ? '接收中' : Value === 'draining' ? '排空中' : Value === 'stopped' ? '已停止' : '全部';
}

function DetailGroup(Input: Readonly<{ Title: string; Items: readonly (readonly [string, string])[] }>): ReactNode {
    return <section className="min-w-0 border-t pt-3 sm:border-t-0 sm:pt-0"><h3 className="border-b pb-2 text-sm font-semibold">{Input.Title}</h3>
        <dl className="divide-y text-sm">{Input.Items.map(([Label, Value]) => <div key={Label} className="flex justify-between gap-3 py-1.5"><dt className="text-muted-foreground">{Label}</dt><dd className="text-right font-medium tabular-nums">{Value}</dd></div>)}</dl>
    </section>;
}
