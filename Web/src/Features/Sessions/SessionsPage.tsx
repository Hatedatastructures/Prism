/** @file 基于 shadcn-admin 数据表工作台重建的 Session 追踪页。 */
import { Children, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Ban, CircleAlert, Pause, Play, RefreshCw, RotateCcw, ShieldCheck } from 'lucide-react';
import { useLocation, useSearchParams } from 'react-router';
import { Alert, AlertDescription, AlertTitle } from '@/Components/ui/alert';
import { Button } from '@/Components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/ui/card';
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/Components/ui/dialog';
import { Input } from '@/Components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/Components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/Components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/Components/ui/tabs';
import { EmptyState, FormatBytes, FormatCount, FormatTime, LoadMoreButton, MobileMasterBack, PageHeader, QueryState, StatusBadge, ToneForState, useMobileMasterFocus } from '../../Components/Ui';
import type { AdminActionResult, CursorPage, EventPage, EventRecord, SessionIdentity, SessionRecord, SessionTraceSpan, StreamRecord, TaskRecord, TracePage } from '../../Services/AdminDataSource';
import { ReconcileSessionSnapshot, type SessionSnapshotLedger } from './SessionSnapshotLedger';
import { useAdminInfiniteQuery, useAdminMutation, useAdminQuery, useAdminServices, useBootstrapIdentity } from '../UseOperations';

type FilterState = 'all' | 'active' | 'draining' | 'closed';
type PendingAction = Readonly<{ Title: string; Description: string; Confirm: string; Run: () => Promise<unknown> }>;
type TraceResult = CursorPage<SessionTraceSpan> & Partial<Omit<TracePage, keyof CursorPage<SessionTraceSpan>>>;
type RelationState = Readonly<{ Pending: boolean; Error: Error | null; HasData: boolean; HasMore: boolean; Fetching: boolean; FetchingMore: boolean; Retry: () => void; LoadMore: () => void }>;

function RelationStatus(Query: Readonly<{ isPending: boolean; error: Error | null; data: unknown; hasNextPage: boolean; isFetching: boolean; isFetchingNextPage: boolean; refetch: () => Promise<unknown>; fetchNextPage: () => Promise<unknown> }>): RelationState {
    return { Pending: Query.isPending, Error: Query.error, HasData: Query.data !== undefined, HasMore: Query.hasNextPage, Fetching: Query.isFetching, FetchingMore: Query.isFetchingNextPage,
        Retry: () => void Query.refetch(), LoadMore: () => void Query.fetchNextPage() };
}

export default function SessionsPage(): ReactNode {
    const Services = useAdminServices(), Bootstrap = useBootstrapIdentity();
    const [RouteParams, SetParams] = useSearchParams();
    const Location = useLocation();
    const SearchInput = useRef<HTMLInputElement>(null);
    const [LocalParams, SetLocalParams] = useState<URLSearchParams | null>(null);
    const [SelectionIdentity, SetSelectionIdentity] = useState<SessionIdentity | null>(null);
    const Params = LocalParams ?? RouteParams;
    const [MobileView, SetMobileView] = useState<'list' | 'detail'>(() => RouteParams.has('session') ? 'detail' : 'list');
    const PreviousLocation = useRef(`${Location.pathname}${Location.search}`);
    useMobileMasterFocus(MobileView);
    const [Paused, SetPaused] = useState(false);
    const [Ledger, SetLedger] = useState<SessionSnapshotLedger | null>(null);
    const [Action, SetAction] = useState<PendingAction | null>(null);
    useEffect(() => {
        const CurrentLocation = `${Location.pathname}${Location.search}`;
        if (PreviousLocation.current === CurrentLocation) return;
        PreviousLocation.current = CurrentLocation;
        SetLocalParams(null);
        SetSelectionIdentity(null);
    }, [Location.pathname, Location.search]);
    const Search = Params.get('q') ?? '', Protocol = Params.get('protocol') ?? 'all', Account = Params.get('account') ?? '', Worker = Params.get('worker') ?? '';
    const RequestedState = Params.get('state') ?? 'all';
    const State: FilterState = RequestedState === 'active' || RequestedState === 'draining' || RequestedState === 'closed' ? RequestedState : 'all';
    const WorkerProcess = Worker ? Params.get('process') ?? '' : '', WorkerGeneration = Worker ? Params.get('generation') ?? '' : '';
    const Query = useAdminInfiniteQuery('sessions', (Source, Page) => Source.GetSessions(Page), [WorkerProcess, WorkerGeneration], { Refresh: !Paused });
    const Sessions = useMemo(() => Query.data?.pages.flatMap(Page => Page.Items) ?? [], [Query.data?.pages]);
    const Filtered = useMemo(() => Sessions.filter(Value => Matches(Value, { Search, Protocol, Account, Worker, WorkerProcess, WorkerGeneration, State })), [Sessions, Search, Protocol, Account, Worker, WorkerProcess, WorkerGeneration, State]);
    const RouteRequestedId = Params.get('session') ?? '';
    const RequestedId = RouteRequestedId || SelectionIdentity?.Id || '';
    const Identity = RouteRequestedId ? ReadIdentity(Params) : SelectionIdentity;
    const Exact = useAdminQuery('session-target', Source => Source.GetSessions({ Cursor: '0', Limit: 1, Id: RequestedId }), { Enabled: !!Identity, Scope: [RequestedId, Identity?.ProcessId ?? '', Identity?.WorkerId ?? '', Identity?.GenerationId ?? ''], StaleTime: 0 });
    const ExactMatch = (Identity && Exact.data?.Items.find(Value => IsSameIdentity(Value, Identity))) ?? null;
    const Selected = RequestedId ? ExactMatch : null;
    const IdentityMismatch = !!Identity && !!Exact.data?.Items.some(Value => Value.Id === RequestedId && !IsSameIdentity(Value, Identity));
    const RelationsEnabled = Selected !== null && !Exact.isFetching && !Exact.error;
    const RelationScope = Selected ? [Selected.ProcessId, Selected.Id, Selected.WorkerId, Selected.GenerationId] : ['unselected'];
    const TraceQuery = useAdminInfiniteQuery<TraceResult>('session-trace', (Source, Page) => Selected && RelationsEnabled ? Source.GetSessionTrace(Selected, Page) : Promise.resolve(EmptyCursorPage<SessionTraceSpan>()), RelationScope, { Refresh: RelationsEnabled });
    const StreamsQuery = useAdminInfiniteQuery<CursorPage<StreamRecord>>('session-streams', (Source, Page) => Selected && RelationsEnabled ? Source.GetStreams(Selected, Page) : Promise.resolve(EmptyCursorPage<StreamRecord>()), RelationScope, { Refresh: RelationsEnabled });
    const TasksQuery = useAdminInfiniteQuery<CursorPage<TaskRecord>>('session-tasks', (Source, Page) => Selected && RelationsEnabled ? Source.GetTasks(Selected, Page) : Promise.resolve(EmptyCursorPage<TaskRecord>()), RelationScope, { Refresh: RelationsEnabled });
    const EventsQuery = useAdminInfiniteQuery<EventPage>('session-events', (Source, Page) => Selected && RelationsEnabled ? Source.GetEvents(Page, { SessionId: Selected.Id, ProcessId: Selected.ProcessId, GenerationId: Selected.GenerationId }) : Promise.resolve(EmptyEventPage()), RelationScope, { Refresh: RelationsEnabled });
    const Cancel = useAdminMutation((Source, Value: SessionIdentity) => Source.CancelSession(Value));
    const ResetStream = useAdminMutation((Source, Value: StreamRecord) => Source.ResetStream(Value));
    const CancelTask = useAdminMutation((Source, Value: TaskRecord) => Source.CancelTask(Value));
    const FilterScope = JSON.stringify([Search, Protocol, Account, Worker, WorkerProcess, WorkerGeneration, State]);
    const SourceScope = Services.Mode === 'live' ? `${Services.Mode}:${Bootstrap.data?.ProcessId ?? 'unverified'}:${Bootstrap.data?.Incarnation ?? 'unverified'}` : Services.Mode;
    useEffect(() => {
        if (Services.Mode !== 'live' || !Query.isSuccess || Query.error || !Query.data) return;
        SetLedger(Previous => ReconcileSessionSnapshot({ Previous, Current: Sessions, SourceScope, FilterScope, SampledAt: Query.dataUpdatedAt || Date.now(), RetentionMs: 300_000, Limit: 20 }));
    }, [Services.Mode, Query.isSuccess, Query.error, Query.data, Query.dataUpdatedAt, Sessions, SourceScope, FilterScope]);
    const Recent = Ledger?.SourceScope === SourceScope && Ledger.FilterScope === FilterScope ? Ledger.Recent : [];
    const Snapshot = Services.Mode === 'live' && Params.get('snapshot') === 'recent' ? 'recent' : 'current';
    const DisplayRows = Snapshot === 'recent' ? Recent.map(Value => Value.Session) : Filtered;
    const InCurrentList = !!Selected && DisplayRows.some(Value => IsSameIdentity(Value, Selected));
    const Protocols = [...new Set(Sessions.map(Value => Value.Protocol))].sort();
    const CommitParams = (Next: URLSearchParams, Replace = false): void => { SetLocalParams(new URLSearchParams(Next)); SetParams(Next, Replace ? { replace: true } : undefined); };
    const Update = (Key: string, Value: string): void => { const Next = new URLSearchParams(Params); if (Value && Value !== 'all') Next.set(Key, Value); else Next.delete(Key); ClearIdentity(Next); SetSelectionIdentity(null); CommitParams(Next, Key === 'q'); };
    const SelectSession = (Value: SessionRecord): void => {
        if (IsSameIdentity(Value, Selected)) {
            SetSelectionIdentity(null);
            CommitParams(ClearSelection(Params));
            SetMobileView('list');
            return;
        }
        SetSelectionIdentity({ Id: Value.Id, ProcessId: Value.ProcessId, WorkerId: Value.WorkerId,
            AccountId: Value.AccountId, GenerationId: Value.GenerationId });
        CommitParams(IdentityParameters(Value, Params));
        SetMobileView('detail');
    };
    const CurrentActionResult = Cancel.data ?? ResetStream.data ?? CancelTask.data;
    const CurrentActionError = Cancel.error ?? ResetStream.error ?? CancelTask.error;
    const Busy = Cancel.isPending || ResetStream.isPending || CancelTask.isPending;
    const Active = Sessions.filter(Value => Value.Active).length, Draining = Sessions.filter(Value => Value.Draining).length;
    return <div className="space-y-4"><PageHeader Title="连接" Description="按账户、Worker、协议和状态扫描活动连接；选中一行后在列表下方检查 Trace、Stream、Task 与关联事件。" Actions={<div className="flex gap-2">{Services.Mode === 'live' && <Button type="button" variant="outline" aria-pressed={Paused} onClick={() => SetPaused(Value => !Value)}>{Paused ? <Play aria-hidden="true" /> : <Pause aria-hidden="true" />}{Paused ? '继续刷新' : '暂停刷新'}</Button>}<Button type="button" variant="outline" disabled={Query.isFetching} onClick={async () => { await Query.refetch(); if (Selected) await Exact.refetch(); }}><RefreshCw className={Query.isFetching ? 'animate-spin' : ''} aria-hidden="true" />刷新列表</Button></div>} />
        {Services.Mode === 'live' && <p role="note" className="text-sm text-muted-foreground">当前接口按 ID 从早到晚分页；已结束的短连接不在活动清单中，较新的活动连接需继续载入。</p>}
        {Paused && <Alert><Pause aria-hidden="true" /><AlertTitle>自动刷新已暂停</AlertTitle><AlertDescription>当前清单保持最后一次成功快照；恢复后才会查询新状态。</AlertDescription></Alert>}
        <dl className="grid grid-cols-2 gap-x-5 border-y py-2 sm:grid-cols-3" aria-label="连接快照汇总"><Reading Label="已载入连接" Value={Query.data ? `${FormatCount(Sessions.length)}${Query.hasNextPage ? '+' : ''}` : '—'} /><Reading Label="活动中" Value={Query.data ? FormatCount(Active) : '—'} /><Reading Label="排空中" Value={Query.data ? FormatCount(Draining) : '—'} /></dl>
        <Tabs value={Snapshot} onValueChange={Value => { const Next = new URLSearchParams(Params); if (Value === 'recent') Next.set('snapshot', 'recent'); else Next.delete('snapshot'); CommitParams(Next); }}><TabsList variant="line" className={Services.Mode === 'demo' ? 'hidden' : undefined}><TabsTrigger value="current">当前活动 {FormatCount(Filtered.length)}</TabsTrigger>{Services.Mode === 'live' && <TabsTrigger value="recent">最近离开 {FormatCount(Recent.length)}</TabsTrigger>}</TabsList>
            {Snapshot === 'recent' && <RecentSnapshotControls HasRecent={Recent.length > 0}
                OnClear={() => SetLedger(Previous => Previous ? { ...Previous, Current: [], Recent: [] } : Previous)} />}
            <TabsContent value={Snapshot} className="mt-5"><div className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-4 lg:grid-cols-[minmax(0,1.1fr)_minmax(24rem,.9fr)]"><div role="region" aria-label="Session 连接列表" className={MobileView === 'detail' ? 'hidden min-w-0 md:block' : 'min-w-0'} data-mobile-master-list tabIndex={-1}><Card><CardHeader className="gap-4"><div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"><div><CardTitle>连接清单</CardTitle><CardDescription>用 Protocol、状态或任意连接字段筛选当前已读取范围。</CardDescription></div><span className="text-xs text-muted-foreground">{DisplayRows.length} 条匹配</span></div><div className="grid gap-3 grid-cols-2 [&>input]:col-span-2"><div className="relative col-span-2"><Input ref={SearchInput} type="search" aria-label="搜索 Session" className="pr-16" value={Search} onChange={Event => Update('q', Event.target.value)} placeholder="搜索 Session、来源、目标、账户或 Worker" />{Search && <Button type="button" variant="ghost" size="sm" aria-label="清除搜索 Session" className="absolute right-1 top-1/2 h-7 -translate-y-1/2 px-2" onClick={() => { Update('q', ''); SearchInput.current?.focus(); }}>清除</Button>}</div><Select value={Protocol} onValueChange={Value => Update('protocol', Value)}><SelectTrigger aria-label="按协议筛选"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">全部协议</SelectItem>{Protocols.map(Value => <SelectItem key={Value} value={Value}>{Value}</SelectItem>)}</SelectContent></Select><Select value={State} onValueChange={Value => Update('state', Value)}><SelectTrigger aria-label="按 Session 状态筛选"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">全部状态</SelectItem><SelectItem value="active">活动中</SelectItem>{Services.Mode === 'demo' && <><SelectItem value="draining">排空中</SelectItem><SelectItem value="closed">已结束</SelectItem></>}</SelectContent></Select></div></CardHeader><CardContent><QueryState Pending={Query.isPending} Error={Query.error} Label="Session 列表" HasData={Query.data !== undefined} Retry={() => void Query.refetch()} Retrying={Query.isFetching} Children={DisplayRows.length === 0 ? <EmptyState Title={Snapshot === 'recent' ? '本页暂无最近离开的连接' : '当前范围没有 Session'} Detail="调整筛选条件或载入更多分页记录。" /> : <div className="min-w-0 overflow-x-auto"><SessionTable Rows={DisplayRows} Selected={Selected} OnSelect={SelectSession} Recent={Snapshot === 'recent'} /></div>} />{Snapshot === 'current' && Query.hasNextPage && <div className="mt-4 flex justify-center"><Button variant="outline" disabled={Query.isFetchingNextPage} onClick={() => void Query.fetchNextPage()}>{Query.isFetchingNextPage ? '正在载入…' : '载入更多 Session'}</Button></div>}</CardContent></Card></div><div role="region" aria-label={`Session ${(Selected?.Id ?? RequestedId) || '详情'} 详情`} className={MobileView === 'list' ? 'hidden min-w-0 md:block' : 'min-w-0'} data-mobile-detail tabIndex={-1}><div className="px-4 pt-4 md:hidden"><MobileMasterBack Label="返回连接列表" OnClick={() => SetMobileView('list')} /></div><SessionInspector Session={Selected} Requested={!!RequestedId} Identity={Identity} IdentityMismatch={IdentityMismatch} ExactPending={!!Identity && Exact.isPending} ExactFetching={!!Identity && Exact.isFetching && Exact.data !== undefined} ExactError={Exact.error} InCurrentList={InCurrentList} OnRecheck={() => void Exact.refetch()} RelationsEnabled={RelationsEnabled} Trace={TraceQuery.data?.pages.flatMap(Page => Page.Items) ?? []} Streams={StreamsQuery.data?.pages.flatMap(Page => Page.Items) ?? []} Tasks={TasksQuery.data?.pages.flatMap(Page => Page.Items) ?? []} Events={(EventsQuery.data?.pages.flatMap(Page => Page.Items) ?? []).filter(Event => Selected && Event.ProcessId === Selected.ProcessId && Event.GenerationId === Selected.GenerationId && Event.SessionId === Selected.Id)} TraceState={RelationStatus(TraceQuery)} StreamState={RelationStatus(StreamsQuery)} TaskState={RelationStatus(TasksQuery)} EventState={RelationStatus(EventsQuery)} TracePages={TraceQuery.data?.pages ?? []} EventPages={EventsQuery.data?.pages ?? []} Capabilities={Bootstrap.error || !RelationsEnabled ? [] : Bootstrap.data?.Capabilities ?? []} OnRequestAction={SetAction} OnCancel={Value => Cancel.mutateAsync(Value)} OnReset={Value => ResetStream.mutateAsync(Value)} OnCancelTask={Value => CancelTask.mutateAsync(Value)} /></div></div></TabsContent></Tabs>
        {CurrentActionError && <Alert variant="destructive"><CircleAlert aria-hidden="true" /><AlertTitle>管理操作尚未确认</AlertTitle><AlertDescription>{CurrentActionError.message}</AlertDescription></Alert>}{CurrentActionResult && <ActionResult Value={CurrentActionResult} />}
        <Dialog open={Action !== null} onOpenChange={Open => !Open && SetAction(null)}><DialogContent><DialogHeader><DialogTitle>{Action?.Title}</DialogTitle><DialogDescription>{Action?.Description}</DialogDescription></DialogHeader><DialogFooter><Button variant="outline" onClick={() => SetAction(null)}>取消</Button><Button variant="destructive" disabled={Busy} onClick={() => void Action?.Run().then(() => SetAction(null)).catch(() => undefined)}>{Busy ? '正在提交…' : Action?.Confirm}</Button></DialogFooter></DialogContent></Dialog>
    </div>;
}

function RecentSnapshotControls(Input: Readonly<{ HasRecent: boolean; OnClear: () => void }>): ReactNode {
    return <div className="flex flex-wrap justify-end gap-2">
        <Dialog>
            <DialogTrigger asChild><Button type="button" variant="outline">留存范围</Button></DialogTrigger>
            <DialogContent>
                <DialogHeader><DialogTitle>留存范围</DialogTitle><DialogDescription>留存只覆盖本页当前筛选范围。两次采样之间建立并结束的连接没有出现在任何快照中；未见于最新快照不代表已确认关闭。</DialogDescription></DialogHeader>
                <DialogFooter><DialogClose asChild><Button type="button" variant="outline">关闭</Button></DialogClose></DialogFooter>
            </DialogContent>
        </Dialog>
        <Button type="button" variant="outline" disabled={!Input.HasRecent} onClick={Input.OnClear}>清空本页留存</Button>
    </div>;
}
function SessionTable(Input: Readonly<{ Rows: readonly SessionRecord[]; Selected: SessionRecord | null; OnSelect: (Value: SessionRecord) => void; Recent: boolean }>): ReactNode {
    return <Table aria-label="Session 列表" className="min-w-[1100px]"><TableHeader><TableRow><TableHead>连接 / 协议</TableHead><TableHead>账户</TableHead><TableHead>Worker</TableHead><TableHead>活动任务</TableHead><TableHead>累计上行</TableHead><TableHead>累计下行</TableHead><TableHead>来源</TableHead><TableHead>目标</TableHead><TableHead>状态</TableHead></TableRow></TableHeader><TableBody>{Input.Rows.map(Value => <TableRow key={IdentityKey(Value)} data-state={IsSameIdentity(Value, Input.Selected) ? 'selected' : undefined} className="cursor-pointer" onClick={() => Input.OnSelect(Value)}>
        <TableCell><button type="button" className="text-left font-mono text-sm font-medium underline-offset-4 hover:underline focus-visible:outline focus-visible:outline-2" onClick={Event => { Event.stopPropagation(); Input.OnSelect(Value); }}>{Value.Id}</button><span className="block text-xs text-muted-foreground">{Value.Transport.toUpperCase()} / {Value.Protocol}</span></TableCell>
        <TableCell className="font-mono">{Value.AccountId}</TableCell><TableCell className="font-mono">{Value.WorkerId}<span className="block text-muted-foreground">Gen {Value.GenerationId}</span></TableCell>
        <TableCell>{FormatCount(Value.ActiveTasks)}</TableCell><TableCell>{FormatBytes(Value.Traffic?.Up)}</TableCell><TableCell>{FormatBytes(Value.Traffic?.Down)}</TableCell>
        <TableCell className="max-w-48 truncate font-mono" title={Value.SourceAddress}>{Value.SourceAddress || '未提供'}</TableCell><TableCell className="max-w-56 truncate font-mono" title={Value.Target}>{Value.Target || '未提供'}</TableCell>
        <TableCell><StatusBadge Label={Input.Recent ? '未见于最新快照' : Value.Draining ? '排空中' : Value.Active ? '活动中' : '已结束'} Tone={Input.Recent ? 'neutral' : Value.Draining ? 'warning' : Value.Active ? 'good' : 'neutral'} /></TableCell>
    </TableRow>)}</TableBody></Table>;
}

function SessionInspector(Input: Readonly<{ Session: SessionRecord | null; Requested: boolean; Identity: SessionIdentity | null; IdentityMismatch: boolean; ExactPending: boolean; ExactFetching: boolean; ExactError: Error | null; InCurrentList: boolean; OnRecheck: () => void; RelationsEnabled: boolean; Trace: readonly SessionTraceSpan[]; Streams: readonly StreamRecord[]; Tasks: readonly TaskRecord[]; Events: readonly EventRecord[]; TraceState: RelationState; StreamState: RelationState; TaskState: RelationState; EventState: RelationState; TracePages: readonly TraceResult[]; EventPages: readonly EventPage[]; Capabilities: readonly string[]; OnRequestAction: (Value: PendingAction) => void; OnCancel: (Value: SessionIdentity) => Promise<unknown>; OnReset: (Value: StreamRecord) => Promise<unknown>; OnCancelTask: (Value: TaskRecord) => Promise<unknown> }>): ReactNode {
    if (Input.ExactPending) return <Card><CardContent className="py-12 text-center text-sm text-muted-foreground">正在根据完整身份核验指定 Session…</CardContent></Card>;
    if (!Input.Session) return Input.Requested ? <Card><CardContent className="space-y-4 py-5"><Alert role="note"><AlertTitle>{!Input.Identity ? 'Session 身份字段不足' : Input.IdentityMismatch ? '当前清单中的同 ID 记录身份不同' : Input.ExactError ? 'Session 状态暂不可核验' : 'Session 已退出当前活动清单'}</AlertTitle><AlertDescription>{Input.ExactError?.message ?? '没有精确身份匹配的活动 Session；未选择同 ID 的其他记录，也未读取其子资源。'}</AlertDescription></Alert>{Input.Identity && <><dl aria-label="指定 Session 身份" className="grid grid-cols-2 gap-2 text-sm"><Fact Label="Session" Value={Input.Identity.Id} /><Fact Label="Process" Value={Input.Identity.ProcessId} /><Fact Label="Worker" Value={Input.Identity.WorkerId} /><Fact Label="账户" Value={Input.Identity.AccountId} /><Fact Label="Generation" Value={Input.Identity.GenerationId} /></dl><Button type="button" variant="outline" onClick={Input.OnRecheck}>重新核对此 Session</Button></>}</CardContent></Card> : null;
    const Session = Input.Session;
    return <Card><CardHeader><div className="flex items-start justify-between gap-3"><div><h2 className="font-mono text-base font-semibold">{Session.Id}</h2><CardDescription className="mt-1">Process {Session.ProcessId} · Generation {Session.GenerationId}</CardDescription></div><StatusBadge Label={Session.Draining ? '排空中' : Session.Active ? '活动中' : '已结束'} /></div></CardHeader><CardContent><Tabs defaultValue="summary"><TabsList variant="line" className="max-w-full overflow-x-auto"><TabsTrigger value="summary">概览</TabsTrigger><TabsTrigger value="trace">阶段 {RelationCount(Input.TraceState, Input.Trace.length)}</TabsTrigger><TabsTrigger value="streams">Streams {RelationCount(Input.StreamState, Input.Streams.length)}</TabsTrigger><TabsTrigger value="tasks">Tasks {RelationCount(Input.TaskState, Input.Tasks.length)}</TabsTrigger><TabsTrigger value="events">事件 {RelationCount(Input.EventState, Input.Events.length)}</TabsTrigger></TabsList>
        {Input.ExactFetching && <Alert role="status"><AlertTitle>正在复核 Session</AlertTitle><AlertDescription>保留最后一次成功快照；本次核验完成前暂停依赖当前状态的管理操作。</AlertDescription></Alert>}
        {Input.ExactError && <Alert variant="destructive"><AlertTitle>当前 Session 状态无法确认</AlertTitle><AlertDescription>精确查询失败：{Input.ExactError.message}。最后观察到的状态：{Session.Draining ? '排空中' : Session.Active ? '活动中' : '已结束'}；读取时间 {FormatTime(new Date().toISOString(), true)}。Streams 待核实；Tasks 待核实。</AlertDescription></Alert>}
        {!Session.Active && <p role="note" className="session-selection-context text-sm text-muted-foreground">Session 已退出当前活动清单。</p>}
        {Session.Active && !Input.InCurrentList && <p role="note" className="session-selection-context text-sm text-muted-foreground">所选 Session 不在当前列表结果中。</p>}
        <TabsContent value="summary" className="mt-5 space-y-5"><section aria-label="连接路径" className="rounded-lg border p-3"><h3 className="text-xs font-medium text-muted-foreground">连接路径 · {Session.Transport.toUpperCase()} / {Session.Protocol}</h3><div className="mt-2 grid gap-2 font-mono text-sm sm:grid-cols-2"><p className="break-all">{Session.SourceAddress || '来源未提供'}</p><p className="break-all">→ {Session.Target || '目标未提供'}</p></div></section><dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm min-[1920px]:grid-cols-3"><Fact Label="协议" Value={`${Session.Transport.toUpperCase()} / ${Session.Protocol}`} /><Fact Label="账户" Value={Session.AccountId} /><Fact Label="Worker" Value={Session.WorkerId} /><Fact Label="活动任务" Value={FormatCount(Session.ActiveTasks)} /><Fact Label="认证身份" Value={Session.Identity || '未提供'} /><Fact Label="开始时间" Value={FormatTime(Session.StartedAt, true)} /><Fact Label="累计上行" Value={FormatBytes(Session.Traffic?.Up)} /><Fact Label="累计下行" Value={FormatBytes(Session.Traffic?.Down)} /><Fact Label="传输终态" Value={FormatCount(Session.Traffic?.Events)} /><Fact Label="传输失败" Value={FormatCount(Session.Traffic?.Errors)} /></dl>{Input.RelationsEnabled ? <Button variant="destructive" type="button" disabled={!Session.Active || Session.Draining || !Input.Capabilities.includes('sessions.cancel')} title={!Input.Capabilities.includes('sessions.cancel') ? '当前实例未提供 Session 取消能力' : undefined} onClick={() => Input.OnRequestAction({ Title: `取消 ${Session.Id}？`, Description: '请求会进入 Prism 的实际关闭链路；受理不等于资源已经释放。', Confirm: '确认取消 Session', Run: () => Input.OnCancel(Session) })}><Ban aria-hidden="true" />取消 Session</Button> : <Alert><CircleAlert aria-hidden="true" /><AlertTitle>身份尚未核验</AlertTitle><AlertDescription>当前深链没有通过完整身份核验，不读取子资源也不显示可操作按钮。</AlertDescription></Alert>}</TabsContent>
        <TabsContent value="trace" className="mt-4"><RelationView State={Input.TraceState} Label="阶段记录">
            {Input.TracePages.some(Page => Page.Lost) && <Alert variant="destructive" className="mb-3"><CircleAlert aria-hidden="true" /><AlertTitle>阶段记录存在缺口</AlertTitle><AlertDescription>后端报告了缓冲覆盖或并发读取跳过；已载入记录不代表完整链路。</AlertDescription></Alert>}
            <TraceTable Rows={Input.Trace} />
        </RelationView></TabsContent>
        <TabsContent value="streams" className="mt-4"><RelationView State={Input.StreamState} Label="Stream">
            <ResourceList Title="Streams" Empty="当前已载入范围没有 Stream。">{Input.Streams.map(Value => <div key={Value.Id} className="flex flex-wrap items-center justify-between gap-3 px-3 py-2"><div><p className="font-mono text-sm">{Value.Id}</p><p className="text-xs text-muted-foreground">{Value.Protocol} · Task {Value.TaskId} · 父 Task {Value.ParentTaskId ?? '未提供'} · {Value.State}</p></div><div className="text-right text-xs text-muted-foreground">↑ {FormatBytes(Value.Traffic?.Up)}<br />↓ {FormatBytes(Value.Traffic?.Down)}</div>{Value.State === 'active' && <Button variant="outline" size="sm" disabled={!Input.Capabilities.includes('streams.reset') || !Value.ParentTaskId} title={!Input.Capabilities.includes('streams.reset') ? '当前实例未提供 Stream 重置能力' : !Value.ParentTaskId ? '缺少父任务身份' : undefined} onClick={() => Input.OnRequestAction({ Title: `重置 Stream ${Value.Id}？`, Description: '该 Stream 将进入关闭流程。', Confirm: '确认重置', Run: () => Input.OnReset(Value) })}><RotateCcw aria-hidden="true" />重置</Button>}</div>)}</ResourceList>
        </RelationView></TabsContent>
        <TabsContent value="tasks" className="mt-4"><RelationView State={Input.TaskState} Label="Task">
            <ResourceList Title="Tasks" Empty="当前已载入范围没有 Task。">{Input.Tasks.map(Value => <div key={Value.Id} className="flex flex-wrap items-center justify-between gap-3 px-3 py-2"><div><p className="font-mono text-sm">{Value.Id}</p><p className="text-xs text-muted-foreground">{Value.Status} · Stream {Value.StreamId} · 父 Task {Value.ParentTaskId ?? '未提供'}{Value.Failure ? ` · ${Value.Failure}` : ''}</p><p className="text-xs text-muted-foreground">取消请求 {Value.CancelRequested ? '是' : '否'} · 排空受阻 {Value.DrainBlocked ? '是' : '否'}{Value.DrainFailure ? ` · ${Value.DrainFailure}` : ''}</p></div>{Value.Cancellable && !Value.CancelRequested && <Button variant="outline" size="sm" disabled={!Input.Capabilities.includes('tasks.cancel')} title={!Input.Capabilities.includes('tasks.cancel') ? '当前实例未提供 Task 取消能力' : undefined} onClick={() => Input.OnRequestAction({ Title: `取消 Task ${Value.Id}？`, Description: '请求已受理不代表 Task 已退出，需要随后核验状态。', Confirm: '确认取消', Run: () => Input.OnCancelTask(Value) })}>取消 Task</Button>}</div>)}</ResourceList>
        </RelationView></TabsContent>
        <TabsContent value="events" className="mt-4"><RelationView State={Input.EventState} Label="关联事件">
            {Input.EventPages.some(Page => Page.Lost) && <Alert variant="destructive" className="mb-3"><CircleAlert aria-hidden="true" /><AlertTitle>事件窗口存在缺口</AlertTitle><AlertDescription>服务端报告记录已覆盖；当前已载入事件不能代表完整历史。</AlertDescription></Alert>}
            <ResourceList Title="关联事件" Empty="当前已载入范围没有关联事件。">{Input.Events.map(Value => <div key={`${Value.ProcessId}:${Value.Id}`} className="px-3 py-2"><div className="flex items-center justify-between gap-3"><StatusBadge Label={SeverityLabel(Value.Severity)} Tone={ToneForState(Value.Severity)} /><time className="text-xs text-muted-foreground">{FormatTime(Value.Time, true)}</time></div><p className="mt-1 text-sm font-medium">{Value.Message}</p><p className="text-xs text-muted-foreground">{Value.Detail || Value.Kind}</p></div>)}</ResourceList>
        </RelationView></TabsContent>
    </Tabs></CardContent></Card>;
}

function RelationCount(State: RelationState, Count: number): string { return State.HasData ? `${Count}${State.HasMore ? '+' : ''}` : '—'; }
function RelationView(Input: Readonly<{ State: RelationState; Label: string; children: ReactNode }>): ReactNode {
    return <><QueryState Pending={Input.State.Pending} Error={Input.State.Error} Label={Input.Label} HasData={Input.State.HasData} Retry={Input.State.Retry} Retrying={Input.State.Fetching} Children={Input.children} />
        {Input.State.HasData && <LoadMoreButton HasMore={Input.State.HasMore} Busy={Input.State.FetchingMore} OnLoad={Input.State.LoadMore} />}</>;
}
function TraceTable(Input: Readonly<{ Rows: readonly SessionTraceSpan[] }>): ReactNode { if (!Input.Rows.length) return <EmptyState Title="没有留存阶段" Detail="阶段记录可能尚未写入，或已经被有限缓冲覆盖。" />; return <Table><TableHeader><TableRow><TableHead>时间</TableHead><TableHead>阶段 / Span</TableHead><TableHead>状态 / 错误</TableHead><TableHead>耗时</TableHead><TableHead>关联资源</TableHead></TableRow></TableHeader><TableBody>{Input.Rows.map(Value => <TableRow key={Value.SpanId}><TableCell>{FormatTime(Value.StartTime, true)}</TableCell><TableCell className="font-mono">{Value.Name}<p className="mt-1 text-muted-foreground">{Value.SpanId}</p></TableCell><TableCell><StatusBadge Label={Value.Status} Tone={ToneForState(Value.Status)} />{Value.Attributes.failure_code && <p className="mt-1 text-xs text-muted-foreground">{String(Value.Attributes.failure_code)}</p>}</TableCell><TableCell>{Value.DurationMs === null ? '未提供' : `${FormatCount(Value.DurationMs)} ms`}</TableCell><TableCell className="text-muted-foreground">Task {Value.TaskId ?? '—'}<br />Stream {Value.StreamId ?? '—'}</TableCell></TableRow>)}</TableBody></Table>; }
function ResourceList(Input: Readonly<{ Title: string; Empty: string; children: ReactNode }>): ReactNode { return <section><h3 className="mb-2 text-sm font-medium">{Input.Title}</h3><div className="divide-y rounded-lg border">{Children.count(Input.children) > 0 ? Input.children : <p className="p-4 text-sm text-muted-foreground">{Input.Empty}</p>}</div></section>; }
function ActionResult(Input: Readonly<{ Value: AdminActionResult }>): ReactNode { return <Alert><ShieldCheck aria-hidden="true" /><AlertTitle>{Input.Value.Status === 'accepted' ? '操作请求已受理' : Input.Value.Ok ? '操作已完成' : '操作结果待核验'}</AlertTitle><AlertDescription>{Input.Value.Message}</AlertDescription></Alert>; }
function Fact(Input: Readonly<{ Label: string; Value: string }>): ReactNode { return <div className="min-w-0 border-b py-2"><dt className="text-xs text-muted-foreground">{Input.Label}</dt><dd className="mt-1 break-all font-medium">{Input.Value}</dd></div>; }
function Reading(Input: Readonly<{ Label: string; Value: string }>): ReactNode { return <div className="py-1.5"><dt className="text-xs text-muted-foreground">{Input.Label}</dt><dd className="mt-0.5 text-sm font-semibold tabular-nums">{Input.Value}</dd></div>; }
function Matches(Value: SessionRecord, Filter: Readonly<{ Search: string; Protocol: string; Account: string; Worker: string; WorkerProcess: string; WorkerGeneration: string; State: FilterState }>): boolean { const Text = `${Value.Id} ${Value.Identity} ${Value.SourceAddress} ${Value.Target} ${Value.Protocol} ${Value.AccountId} ${Value.WorkerId}`.toLocaleLowerCase(); return (!Filter.Search || Text.includes(Filter.Search.toLocaleLowerCase())) && (Filter.Protocol === 'all' || Value.Protocol.toLocaleLowerCase() === Filter.Protocol.toLocaleLowerCase()) && (!Filter.Account || Value.AccountId === Filter.Account) && (!Filter.Worker || Value.WorkerId === Filter.Worker) && (!Filter.WorkerProcess || Value.ProcessId === Filter.WorkerProcess) && (!Filter.WorkerGeneration || Value.GenerationId === Filter.WorkerGeneration) && (Filter.State === 'all' || Filter.State === 'active' && Value.Active || Filter.State === 'draining' && Value.Draining || Filter.State === 'closed' && !Value.Active && !Value.Draining); }
function ReadIdentity(Params: URLSearchParams): SessionIdentity | null { const Id = Params.get('session') ?? '', ProcessId = Params.get('process') ?? '', WorkerId = Params.get('identity_worker') ?? '', AccountId = Params.get('identity_account') ?? '', GenerationId = Params.get('generation') ?? ''; return Id && ProcessId && WorkerId && AccountId && GenerationId ? { Id, ProcessId, WorkerId, AccountId, GenerationId } : null; }
function IsSameIdentity(Value: SessionRecord | null, Identity: SessionIdentity | null): boolean { return !!Value && !!Identity && Value.Id === Identity.Id && Value.ProcessId === Identity.ProcessId && Value.WorkerId === Identity.WorkerId && Value.AccountId === Identity.AccountId && Value.GenerationId === Identity.GenerationId; }
function IdentityParameters(Value: SessionRecord, Current: URLSearchParams): URLSearchParams { const Next = new URLSearchParams(Current); Next.set('session', Value.Id); Next.set('process', Value.ProcessId); Next.set('identity_worker', Value.WorkerId); Next.set('identity_account', Value.AccountId); Next.set('generation', Value.GenerationId); return Next; }
function ClearSelection(Current: URLSearchParams): URLSearchParams { const Next = new URLSearchParams(Current); for (const Key of ['session', 'identity_worker', 'identity_account']) Next.delete(Key); if (!Next.get('worker')) { Next.delete('process'); Next.delete('generation'); } return Next; }
function ClearIdentity(Params: URLSearchParams): void { for (const Key of ['session', 'process', 'identity_worker', 'identity_account', 'generation']) Params.delete(Key); }
function IdentityKey(Value: SessionRecord): string { return [Value.ProcessId, Value.GenerationId, Value.WorkerId, Value.AccountId, Value.Id].join(':'); }
function EmptyCursorPage<Value>(): CursorPage<Value> { return { Items: [], NextCursor: '0', HasMore: false }; }
function EmptyEventPage(): EventPage { return { ...EmptyCursorPage<EventRecord>(), EarliestCursor: '0', Lost: false, LostRanges: [], Dropped: '0', TerminalDropped: '0', Overwritten: '0', SeverityFilterSupported: false }; }
function SeverityLabel(Value: EventRecord['Severity']): string { return Value === 'error' ? '错误' : Value === 'warning' ? '警告' : Value === 'debug' ? '调试' : '信息'; }
