import { TimeLink as Link } from '../TimeLink';
import { FilterScopeNotice } from '../FilterScopeNotice';
import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import * as Tabs from '@radix-ui/react-tabs';
import { useInfiniteQuery } from '@tanstack/react-query';
import { Activity, RefreshCw, Search } from 'lucide-react';
import { useSearchParams } from 'react-router';
import { ConfirmAction } from '../../Components/ConfirmAction';
import {
    EmptyState, FormatBytes, FormatCount, FormatTime, LoadMoreButton, PageHeader, Panel,
    QueryState, StatusBadge, ToneForState,
} from '../../Components/Ui';
import type {
    SessionIdentity, SessionRecord, SessionTraceSpan, StreamIdentity, StreamRecord, TaskIdentity, TaskRecord,
} from '../../Services/AdminDataSource';
import { useAdminInfiniteQuery, useAdminMutation, useAdminQuery, useAdminServices } from '../UseOperations';
import { ActionFeedback } from '../ActionFeedback';

export default function SessionsPage(): ReactNode {
    const Services = useAdminServices();
    const [Params, SetParams] = useSearchParams();
    const SearchText = Params.get('q') ?? '';
    const Protocol = Params.get('protocol') ?? 'all';
    const Account = Params.get('account') ?? '';
    const Worker = Params.get('worker') ?? '';
    const WorkerProcess = Worker ? Params.get('process') ?? '' : '';
    const WorkerGeneration = Worker ? Params.get('generation') ?? '' : '';
    const State = Params.get('state') ?? 'all';
    const Query = useAdminInfiniteQuery('sessions', (Source, Page) => Source.GetSessions(Page), [WorkerProcess, WorkerGeneration]);
    const SelectedIdentity = ReadIdentity(Params);
    const [Pinned, SetPinned] = useState<SessionRecord | null>(null);
    const [PinnedAt, SetPinnedAt] = useState(0);
    const Sessions = Query.data?.pages.flatMap(Page => Page.Items) ?? [];
    const Filtered = useMemo(() => Sessions.filter(Session => {
        const Searchable = `${Session.Id} ${Session.Identity} ${Session.SourceAddress} ${Session.Target} ${Session.Protocol} ${Session.AccountId} ${Session.WorkerId}`.toLowerCase();
        return (!SearchText || Searchable.includes(SearchText.toLowerCase())) &&
            (Protocol === 'all' || Session.Protocol.toLowerCase() === Protocol.toLowerCase()) && (!Account || Session.AccountId === Account) &&
            (!Worker || Session.WorkerId === Worker) && (!WorkerProcess || Session.ProcessId === WorkerProcess) &&
            (!WorkerGeneration || Session.GenerationId === WorkerGeneration) &&
            (State === 'all' || State === 'active' && Session.Active || State === 'draining' && Session.Draining || State === 'closed' && !Session.Active && !Session.Draining);
    }), [Sessions, SearchText, Protocol, Account, Worker, WorkerProcess, WorkerGeneration, State]);
    const MatchIdentity = (Session: SessionRecord, Identity: SessionIdentity): boolean => Session.Id === Identity.Id &&
        Session.ProcessId === Identity.ProcessId && Session.WorkerId === Identity.WorkerId &&
        Session.GenerationId === Identity.GenerationId;
    const RequestedSessionId = Params.get('session') ?? '';
    const Exact = useAdminQuery('session-target', Source => Source.GetSessions({ Cursor: '0', Limit: 1, Id: RequestedSessionId }),
        { Enabled: !!RequestedSessionId && !!SelectedIdentity,
            Scope: [RequestedSessionId, Params.get('process'), Params.get('identity_worker'), Params.get('generation')] });
    const FromList = SelectedIdentity ? Sessions.find(Session => MatchIdentity(Session, SelectedIdentity)) : null;
    const ExactItems = Exact.data?.Items ?? [];
    const ExactMatch = Exact.isSuccess && !Exact.isFetching && SelectedIdentity
        ? ExactItems.find(Session => Session.Id === RequestedSessionId && (!SelectedIdentity || MatchIdentity(Session, SelectedIdentity)))
        : undefined;
    const ExactHasSameIdDifferentIdentity = !!SelectedIdentity && Exact.isSuccess && !Exact.isFetching && !ExactMatch && ExactItems.some(Session => Session.Id === RequestedSessionId);
    const ExactRetired = !!SelectedIdentity && Exact.isSuccess && !Exact.isFetching && ExactItems.length === 0;
    const LastExactMatch = SelectedIdentity ? ExactItems.find(Session => MatchIdentity(Session, SelectedIdentity)) : undefined;
    const PinnedMatch = Pinned && SelectedIdentity && MatchIdentity(Pinned, SelectedIdentity) ? Pinned : null;
    const LastObservedAt = LastExactMatch ? Exact.dataUpdatedAt : FromList ? Query.dataUpdatedAt : PinnedAt;
    const ExactRefreshing = !!SelectedIdentity && Exact.isFetching && !!LastExactMatch;
    const ExactEvidence: 'verified' | 'refreshing' | 'retired' | 'identity-mismatch' | 'pending' | 'error' | 'incomplete' | 'snapshot' = RequestedSessionId && !SelectedIdentity ? 'incomplete'
        : ExactRefreshing ? 'refreshing' : ExactMatch ? 'verified'
        : ExactRetired ? 'retired' : ExactHasSameIdDifferentIdentity ? 'identity-mismatch'
            : Exact.error ? 'error' : (Exact.isPending || Exact.isFetching) && SelectedIdentity ? 'pending' : 'snapshot';
    const Selected = ExactMatch ?? (ExactRetired && PinnedMatch ? { ...PinnedMatch, Active: false, Draining: false } : null)
        ?? ((ExactEvidence === 'refreshing' || ExactEvidence === 'pending' || ExactEvidence === 'error' || ExactEvidence === 'identity-mismatch')
            ? LastExactMatch ?? FromList ?? PinnedMatch : null)
        ?? (!RequestedSessionId ? Filtered[0] ?? null : null);
    const RelationsUnverified = !Selected || (ExactEvidence !== 'verified' && ExactEvidence !== 'refreshing');
    const RelationTarget = RelationsUnverified ? null : Selected;
    const TraceTarget = Selected ?? SelectedIdentity;
    const IdentityScope = TraceTarget ? [TraceTarget.ProcessId, TraceTarget.Id, TraceTarget.WorkerId, TraceTarget.GenerationId] : [];
    const TraceQuery = useAdminInfiniteQuery('session-trace', (Source, Page) => TraceTarget
        ? Source.GetSessionTrace(TraceTarget, Page) : Promise.resolve(EmptyPage<SessionTraceSpan>()), IdentityScope);
    const RelationScope = RelationTarget
        ? [RelationTarget.ProcessId, RelationTarget.Id, RelationTarget.WorkerId, RelationTarget.GenerationId]
        : ['unverified', RequestedSessionId, Params.get('process') ?? '', Params.get('identity_worker') ?? '', Params.get('generation') ?? ''];
    const StreamsQuery = useInfiniteQuery({ queryKey: ['operations', 'session-streams', ...RelationScope],
        enabled: RelationTarget !== null, initialPageParam: '0',
        queryFn: ({ pageParam }) => { const Target = RelationTarget;
            if (!Target) throw new Error('Session identity must be verified before reading Streams.');
            return Services.Data.GetStreams(Target, { Cursor: pageParam, Limit: 50 }); },
        getNextPageParam: Page => Page.HasMore ? Page.NextCursor : undefined, retry: false, staleTime: 2_000,
        refetchInterval: RelationTarget && Services.Mode === 'live' ? 5_000 : false,
        refetchIntervalInBackground: false, refetchOnWindowFocus: RelationTarget !== null });
    const TasksQuery = useInfiniteQuery({ queryKey: ['operations', 'session-tasks', ...RelationScope],
        enabled: RelationTarget !== null, initialPageParam: '0',
        queryFn: ({ pageParam }) => { const Target = RelationTarget;
            if (!Target) throw new Error('Session identity must be verified before reading Tasks.');
            return Services.Data.GetTasks(Target, { Cursor: pageParam, Limit: 50 }); },
        getNextPageParam: Page => Page.HasMore ? Page.NextCursor : undefined, retry: false, staleTime: 2_000,
        refetchInterval: RelationTarget && Services.Mode === 'live' ? 5_000 : false,
        refetchIntervalInBackground: false, refetchOnWindowFocus: RelationTarget !== null });
    const EventsQuery = useAdminInfiniteQuery('events', (Source, Page) => Source.GetEvents(Page,
        TraceTarget ? { SessionId: TraceTarget.Id, ProcessId: TraceTarget.ProcessId, GenerationId: TraceTarget.GenerationId } : {}), IdentityScope);
    const Cancel = useAdminMutation((Source, Identity: SessionIdentity) => Source.CancelSession(Identity));
    const ResetStream = useAdminMutation((Source, Identity: StreamIdentity) => Source.ResetStream(Identity));
    const CancelTask = useAdminMutation((Source, Identity: TaskIdentity) => Source.CancelTask(Identity));
    const Trace = (TraceQuery.data?.pages.flatMap(Page => Page.Items) ?? []).sort((A, B) => Date.parse(A.StartTime) - Date.parse(B.StartTime) || (BigInt(A.Sequence) < BigInt(B.Sequence) ? -1 : 1));
    const TraceLost = TraceQuery.data?.pages.some(Page => 'Lost' in Page && Page.Lost === true) ?? false;
    const TraceLoss = (TraceQuery.data?.pages.flatMap(Page => (Page as { Loss?: readonly SessionTraceLoss[] }).Loss ?? []) ?? [])
        .filter((Loss, Index, Items) => Items.findIndex(Value => Value.WorkerId === Loss.WorkerId && Value.Overwritten === Loss.Overwritten &&
            Value.LostSinceCursor === Loss.LostSinceCursor && Value.ConcurrentReadSkips === Loss.ConcurrentReadSkips) === Index);
    const Streams = StreamsQuery.data?.pages.flatMap(Page => Page.Items) ?? [];
    const Tasks = TasksQuery.data?.pages.flatMap(Page => Page.Items) ?? [];
    const Events = (EventsQuery.data?.pages.flatMap(Page => Page.Items) ?? []).filter(Event => !TraceTarget ||
        Event.SessionId === TraceTarget.Id && Event.ProcessId === TraceTarget.ProcessId && Event.GenerationId === TraceTarget.GenerationId &&
        (!Event.WorkerId || Event.WorkerId === TraceTarget.WorkerId));
    const Protocols = [...new Set(Sessions.map(Session => Session.Protocol))];
    const Active = Sessions.filter(Session => Session.Active).length;
    const Draining = Sessions.filter(Session => Session.Draining).length;

    useEffect(() => {
        if (SelectedIdentity || RequestedSessionId || Filtered.length === 0) return;
        const First = Filtered[0];
        if (!First) return;
        SetPinned(First);
        SetPinnedAt(Query.dataUpdatedAt || Date.now());
        SetParams(IdentityParams(First, Params), { replace: true });
    }, [SelectedIdentity, Filtered, Params, RequestedSessionId, SetParams]);

    const Select = (Session: SessionRecord): void => {
        SetPinned(Session);
        SetPinnedAt(Query.dataUpdatedAt || Date.now());
        SetParams(IdentityParams(Session, Params));
    };
    const UpdateFilter = (Key: string, Value: string): void => {
        const Next = new URLSearchParams(Params);
        if (Value && Value !== 'all') Next.set(Key, Value); else Next.delete(Key);
        ClearIdentity(Next);
        SetPinned(null);
        SetPinnedAt(0);
        SetParams(Next, { replace: true });
    };
    const Refresh = (): void => { void Query.refetch(); };

    return <div className="resource-workspace sessions-workspace">
        <PageHeader Title="Session 追踪"
            Description="当前活动连接快照；选择 Session 查看实际记录阶段、子资源与关联事件。"
            Actions={<button className="button button-secondary" type="button" onClick={Refresh} disabled={Query.isFetching}>
                <RefreshCw size={14} />{Query.isFetching ? '刷新中' : '刷新列表'}</button>} />
        <p className="table-footnote">列表、Trace 和关联事件按数据源快照与游标查询，不受全局时间范围设置筛选。</p>
        <div className="page-metric-strip" aria-label="Session 列表状态">
            <SessionMetric Label="已载入 Session" Value={FormatCount(Sessions.length)} Hint={Query.hasNextPage ? '还有更多游标记录' : '当前列表快照'} />
            <SessionMetric Label="活动中" Value={FormatCount(Active)} Hint="TCP Session 状态" />
            <SessionMetric Label="排空中" Value={FormatCount(Draining)} Hint="正在收尾的连接" />
            <SessionMetric Label="关联事件" Value={ResourceCount(StateOf(EventsQuery), Events.length)} Hint="选中 Session 的已载入事件样本" />
        </div>
        <Panel Title="连接清单" Action={<span className="list-scope">TCP Session · 已载入快照</span>}>
            <div className="toolbar">
                <label className="search-field"><Search size={15} aria-hidden="true" /><input aria-label="搜索 Session" placeholder="搜索 Session、来源、目标、账户或 Worker"
                    value={SearchText} onChange={Event => UpdateFilter('q', Event.target.value)} /></label>
                <select className="filter-select" aria-label="按协议筛选" value={Protocol} onChange={Event => UpdateFilter('protocol', Event.target.value)}>
                    <option value="all">全部协议</option>{Protocols.map(Value => <option value={Value} key={Value}>{Value}</option>)}
                </select>
                <select className="filter-select" aria-label="按 Session 状态筛选" value={State} onChange={Event => UpdateFilter('state', Event.target.value)}>
                    <option value="all">全部状态</option><option value="active">活动中</option><option value="draining">排空中</option><option value="closed">已结束</option>
                </select>
            </div>
            {(Account || Worker) && <div className="active-filter-strip"><span>资源过滤</span>{Account && <code>Account {Account}</code>}
                {Worker && <code>Worker {Worker}</code>}{WorkerProcess && <code>Process {WorkerProcess}</code>}{WorkerGeneration && <code>Generation {WorkerGeneration}</code>}
                <button className="button button-quiet" type="button"
                    onClick={() => { const Next = new URLSearchParams(Params); Next.delete('account'); Next.delete('worker'); ClearIdentity(Next); SetParams(Next); SetPinned(null); SetPinnedAt(0); }}>清除过滤</button></div>}
            <FilterScopeNotice Collection="sessions" />
            <QueryState Pending={Query.isPending} Error={Query.error} Label="Session 列表" HasData={Query.data !== undefined}
                Children={Filtered.length === 0 ? <><EmptyState Title={Worker && (WorkerProcess || WorkerGeneration) ? '当前已载入样本没有该 Worker 代际的活动 Session' : '没有匹配的 Session'}
                    Detail={Worker && (WorkerProcess || WorkerGeneration) ? Query.hasNextPage
                        ? '此列表只包含活动 Session；继续载入其他页查找该范围，空结果不验证 Worker slot 状态。'
                        : '此列表只包含活动 Session；没有匹配记录不验证 Worker slot 状态。'
                        : '更改筛选条件，或载入下一页连接记录。'} />
                    <LoadMoreButton HasMore={Query.hasNextPage ?? false} Busy={Query.isFetchingNextPage} OnLoad={() => void Query.fetchNextPage()} />
                </> : <>
                    <div className="session-page-grid">
                        <div className="session-list" role="listbox" aria-label="Session 连接列表">
                            {Filtered.map(Session => <SessionItem key={[Session.ProcessId, Session.GenerationId, Session.WorkerId, Session.AccountId, Session.Id].join(':')}
                                Value={Session} Selected={Selected !== null && MatchIdentity(Session, Selected)} OnSelect={() => Select(Session)} />)}
                            <LoadMoreButton HasMore={Query.hasNextPage ?? false} Busy={Query.isFetchingNextPage}
                                OnLoad={() => void Query.fetchNextPage()} />
                        </div>
                        {Selected ? <SessionInspector Value={Selected} StatusEvidence={ExactEvidence} RelationsUnverified={RelationsUnverified} StatusError={Exact.error}
                            StatusReadAt={Exact.dataUpdatedAt} LastObservedAt={LastObservedAt} StatusFetching={Exact.isFetching} OnRefreshStatus={() => { void Exact.refetch(); }}
                            Trace={Trace} Streams={Streams} Tasks={Tasks} Events={Events}
                            TraceState={StateOf(TraceQuery)} StreamsState={StateOf(StreamsQuery)} TasksState={StateOf(TasksQuery)} EventsState={StateOf(EventsQuery)}
                            Busy={Cancel.isPending || ResetStream.isPending || CancelTask.isPending}
                            OnCancel={() => Cancel.mutateAsync(Selected)}
                            OnResetStream={Identity => ResetStream.mutateAsync(Identity)}
                            OnCancelTask={Identity => CancelTask.mutateAsync(Identity)} /> : null}
                    </div>
                </>} />
        </Panel>
        {TraceLost && <div className="notice notice-warning" role="status"><strong>Trace 记录存在覆盖或并发读取缺口；不会补造缺失阶段或耗时。</strong>
            {TraceLoss.length > 0 ? <ul>{TraceLoss.map((Loss, Index) => <li key={Loss.WorkerId + ':' + Index}>Worker {Loss.WorkerId} · 覆盖 {FormatCount(Loss.Overwritten)} · 游标后丢失 {FormatCount(Loss.LostSinceCursor)} · 并发读取跳过 {FormatCount(Loss.ConcurrentReadSkips)}</li>)}</ul>
                : <p>数据源报告缺口，但没有提供可分解的 Worker 丢失计数。</p>}</div>}
        {RequestedSessionId && !Selected && <QueryState Pending={!!SelectedIdentity && (Exact.isPending || Exact.isFetching)} Error={SelectedIdentity ? Exact.error : null} HasData={Exact.data !== undefined} Label="指定 Session" Children={<>
            {!SelectedIdentity ? <EmptyState Title="Session 身份字段不足" Detail="需要 Process、Generation 和 Worker 才能精确定位；不会仅凭 Session ID 选择当前清单中的其他记录。" />
                : ExactRetired ? <EmptyState Title="Session 已退出当前活动清单" Detail="本次精确查询成功但未返回该 Session；保留原始身份，仍可查询留存 Trace。" />
                : ExactHasSameIdDifferentIdentity ? <EmptyState Title="当前清单中的同 ID 记录身份不同" Detail="不会将它替换成 URL 指定的连接；原目标的当前状态无法确认。" />
                    : Exact.error ? <EmptyState Title="无法核实指定 Session 状态" Detail="查询失败不能证明连接已结束；保留原始身份，可重试精确查询或查看留存 Trace。" />
                        : <EmptyState Title="正在核实指定 Session" Detail="精确查询完成前不推断连接已结束，也不会选择其他连接。" />}
            {SelectedIdentity && <button className="button button-secondary" type="button" disabled={Exact.isFetching} onClick={() => { void Exact.refetch(); }}>
                <RefreshCw size={14} />{Exact.isFetching ? '核对中…' : '重新核对此 Session'}</button>}
            {TraceTarget && <ResourceContent State={StateOf(TraceQuery)} Label="Session Trace"><TraceWaterfall Spans={Trace} /></ResourceContent>}
        </>} />}
        <ActionFeedback Result={Cancel.data} /><ActionFeedback Result={ResetStream.data} /><ActionFeedback Result={CancelTask.data} />
    </div>;
}

type ResourceState = Readonly<{ Pending: boolean; Error: Error | null; HasData: boolean; HasMore: boolean; Busy: boolean; LoadMore: () => void }>;
type SessionTraceLoss = Readonly<{ WorkerId: string; Overwritten: string; LostSinceCursor: string; ConcurrentReadSkips: string }>;
/** @brief 子资源各自保留加载、失败与分页状态，失败或未载入不显示成零条。 */
function StateOf(Query: Readonly<{
    isPending: boolean; error: Error | null; data: unknown; hasNextPage: boolean; isFetchingNextPage: boolean; fetchNextPage: () => Promise<unknown>;
}>): ResourceState {
    return { Pending: Query.isPending, Error: Query.error, HasData: Query.data !== undefined, HasMore: Query.hasNextPage,
        Busy: Query.isFetchingNextPage, LoadMore: () => { void Query.fetchNextPage(); } };
}

function ResourceContent(Input: Readonly<{ State: ResourceState; Label: string; children: ReactNode }>): ReactNode {
    return <QueryState Pending={Input.State.Pending} Error={Input.State.Error} HasData={Input.State.HasData} Label={Input.Label}
        Children={<>{Input.children}<LoadMoreButton HasMore={Input.State.HasMore} Busy={Input.State.Busy} OnLoad={Input.State.LoadMore} /></>} />;
}

function ResourceCount(State: ResourceState, Count: number): string {
    return !State.HasData ? State.Pending ? '…' : '不可用' : `${Count}${State.HasMore ? '+' : ''}`;
}

function EmptyPage<Value>(): Readonly<{ Items: readonly Value[]; NextCursor: string; HasMore: boolean }> {
    return { Items: [], NextCursor: '0', HasMore: false };
}

function ReadIdentity(Params: URLSearchParams): SessionIdentity | null {
    const Id = Params.get('session');
    const ProcessId = Params.get('process');
    const WorkerId = Params.get('identity_worker');
    const AccountId = Params.get('identity_account');
    const GenerationId = Params.get('generation');
    return Id && ProcessId && WorkerId && GenerationId
        ? { Id, ProcessId, WorkerId, AccountId: AccountId ?? '0', GenerationId } : null;
}

function IdentityParams(Session: SessionRecord, Current: URLSearchParams): URLSearchParams {
    const Next = new URLSearchParams(Current);
    Next.set('session', Session.Id); Next.set('process', Session.ProcessId); Next.set('identity_worker', Session.WorkerId);
    Next.set('identity_account', Session.AccountId); Next.set('generation', Session.GenerationId);
    return Next;
}

function ClearIdentity(Params: URLSearchParams): void {
    for (const Key of ['session', 'process', 'identity_worker', 'identity_account', 'generation']) Params.delete(Key);
}

function SessionMetric(Input: Readonly<{ Label: string; Value: string; Hint: string }>): ReactNode {
    return <div className="page-metric" title={Input.Hint}><span>{Input.Label}</span><strong>{Input.Value}</strong></div>;
}

function SessionItem(Input: Readonly<{ Value: SessionRecord; Selected: boolean; OnSelect: () => void }>): ReactNode {
    const Session = Input.Value;
    const State = Session.Draining ? '排空中' : Session.Active ? '活动中' : '已结束';
    return <button className={`session-item ${Input.Selected ? 'is-selected' : ''}`} type="button"
        role="option" aria-selected={Input.Selected} onClick={Input.OnSelect}>
        <span className="session-item-head"><strong>{Session.Id}</strong><StatusBadge Label={State} Tone={ToneForState(State)} /></span>
        <span className="session-item-grid"><span>{Session.Protocol} · {Session.Identity || Session.AccountId}</span><span>{Session.WorkerId}</span></span>
        <span className="session-item-target" title={`${Session.SourceAddress || '来源未提供'} → ${Session.Target}`}>→ {Session.Target || '目标未提供'}</span>
    </button>;
}

function SessionInspector(Input: Readonly<{
    Value: SessionRecord; StatusEvidence: 'verified' | 'refreshing' | 'retired' | 'identity-mismatch' | 'pending' | 'error' | 'incomplete' | 'snapshot';
    RelationsUnverified: boolean;
    StatusError: Error | null; StatusReadAt: number; LastObservedAt: number; StatusFetching: boolean; OnRefreshStatus: () => void;
    Trace: readonly SessionTraceSpan[]; Streams: readonly StreamRecord[];
    Tasks: readonly TaskRecord[]; Events: readonly import('../../Services/AdminDataSource').EventRecord[];
    TraceState: ResourceState; StreamsState: ResourceState; TasksState: ResourceState; EventsState: ResourceState; Busy: boolean;
    OnCancel: () => Promise<unknown>; OnResetStream: (Value: StreamIdentity) => Promise<unknown>;
    OnCancelTask: (Value: TaskIdentity) => Promise<unknown>;
}>): ReactNode {
    const Session = Input.Value;
    const State = Session.Draining ? '排空中' : Session.Active ? '活动中' : '已结束';
    const StateLabel = Input.StatusEvidence === 'verified' ? State
        : Input.StatusEvidence === 'refreshing' ? '正在复核'
        : Input.StatusEvidence === 'retired' ? '已退出当前活动清单' : '当前状态未知';
    const MutationsAllowed = Input.StatusEvidence === 'verified' && (Session.Active || Session.Draining);
    const [Tab, SetTab] = useState('trace');
    const Blocked = Input.Tasks.filter(Task => Task.DrainBlocked || Task.Failure || Task.Status === 'failed' || Task.Status === 'quarantined');
    return <section className="session-inspector" aria-label={`Session ${Session.Id} 详情`}>
        <div className="session-inspector-head"><div><h2>{Session.Id}</h2><p>{Session.SourceAddress || '来源地址未提供'} → {Session.Target}</p></div>
            <div><StatusBadge Label={StateLabel} Tone={Input.StatusEvidence === 'verified' ? ToneForState(State)
                : Input.StatusEvidence === 'refreshing' ? 'neutral' : ToneForState('unknown')} />
                {Input.StatusEvidence === 'verified' && Session.Active && !Session.Draining && <ConfirmAction Label="取消 Session" Title="取消此 Session？"
                    Description={`${Session.Id} 将请求取消并等待所属任务和传输实际关闭；已受理不等于资源已释放。`} ConfirmLabel="确认取消"
                    Tone="danger" Busy={Input.Busy} OnConfirm={Input.OnCancel} />}</div>
        </div>
        {Input.StatusEvidence === 'refreshing' && <div className="notice notice-info" role="status">
            <strong>正在复核 Session</strong>
            <p>最近成功核验：{State} · 读取时间 {Input.StatusReadAt > 0 ? FormatTime(new Date(Input.StatusReadAt).toISOString(), true) : '未提供'}。核对完成前，取消和子资源操作暂不可用。</p>
        </div>}
        {Input.StatusEvidence !== 'verified' && Input.StatusEvidence !== 'refreshing' && Input.StatusEvidence !== 'retired' && <div className="notice notice-warning" role="status">
            <strong>当前 Session 状态无法确认</strong>
            <p>最后观察到的状态：{State} · 读取时间 {Input.LastObservedAt > 0 ? FormatTime(new Date(Input.LastObservedAt).toISOString(), true) : '未提供'}。{Input.StatusEvidence === 'identity-mismatch' ? '当前查询返回了同 ID 但完整身份不同的记录，不会替换所选目标。'
                : Input.StatusError ? '精确查询失败：' + Input.StatusError.message : '精确查询尚未成功；这不表示连接已结束。'} 取消和子资源操作暂不可用。</p>
            <button className="button button-secondary" type="button" disabled={Input.StatusFetching} onClick={Input.OnRefreshStatus}>
                <RefreshCw size={14} />{Input.StatusFetching ? '核对中…' : '重新核对此 Session'}</button>
        </div>}
        {Input.StatusEvidence === 'retired' && <p className="field-hint">精确查询于 {Input.StatusReadAt > 0 ? FormatTime(new Date(Input.StatusReadAt).toISOString(), true) : '未知时间'} 成功且活动清单未返回该 Session；下面的 Trace 查询仍受有界留存和覆盖范围限制。</p>}
        <div className="session-primary-facts">
            <span>{Session.Transport.toUpperCase()} / <strong>{Session.Protocol}</strong></span>
            <span>账户 <Link to={`/accounts?account=${encodeURIComponent(Session.AccountId)}`}>查看当前账户 {Session.Identity || Session.AccountId}</Link></span>
            <span>Worker <Link to={WorkerPath(Session)}>{Session.WorkerId}</Link></span>
            <span>活动任务 <strong>{Session.ActiveTasks === null ? '未提供' : FormatCount(Session.ActiveTasks)}</strong></span>
        </div>
        <div className="session-stat-row"><span>累计上行 <strong>{Session.Traffic ? FormatBytes(Session.Traffic.Up) : '未采集'}</strong></span>
            <span>累计下行 <strong>{Session.Traffic ? FormatBytes(Session.Traffic.Down) : '未采集'}</strong></span></div>
        <div className="session-context-line"><span>Process {Session.ProcessId} · G{Session.GenerationId}</span><span>开始 {FormatTime(Session.StartedAt, true)}</span>
            <Link to={SessionEventsPath(Session)}>关联事件</Link>
            <details className="session-full-identity"><summary>完整身份</summary><div><span>Account {Session.AccountId}</span><span>Worker {Session.WorkerId}</span>
                <span>Process {Session.ProcessId}</span><span>Generation {Session.GenerationId}</span><span>Session {Session.Id}</span></div></details>
        </div>
        {Blocked.length > 0 && <div className="session-task-alert" role="status"><strong>{Blocked.length} 个已载入 Task 存在失败或排空受阻</strong>
            <button className="button button-quiet" type="button" onClick={() => SetTab('tasks')}>查看 Tasks</button></div>}

        <Tabs.Root value={Tab} onValueChange={SetTab} className="session-detail-tabs">
        <Tabs.List className="detail-tabs" aria-label="连接详情视图">
            <Tabs.Trigger value="trace">连接阶段</Tabs.Trigger>
            <Tabs.Trigger value="streams">Streams {Input.RelationsUnverified ? '待核实' : ResourceCount(Input.StreamsState, Input.Streams.length)}</Tabs.Trigger>
            <Tabs.Trigger value="tasks">Tasks {Input.RelationsUnverified ? '待核实' : ResourceCount(Input.TasksState, Input.Tasks.length)}</Tabs.Trigger>
            <Tabs.Trigger value="events">关联事件 {ResourceCount(Input.EventsState, Input.Events.length)}</Tabs.Trigger>
        </Tabs.List>
        <Tabs.Content value="trace"><div className="trace-block">
            <div className="trace-block-heading"><h3>Session Trace</h3><span>{Input.Trace.length} 个实际记录阶段</span></div>
            <p className="field-hint">时间线按事件时间排列；相对时间是自接入偏移，不代表阶段耗时。服务端未提供 DurationMs 时不推算耗时。</p>
            <ResourceContent State={Input.TraceState} Label="Session Trace">
                {Input.Trace.length === 0 ? <EmptyState Title="该 Session 暂无阶段事件" Detail="记录可能尚未产生或已被覆盖；可查询事件、Task 和 Stream。" />
                    : <TraceWaterfall Spans={Input.Trace} />}</ResourceContent>
            {Input.Trace.length > 0 && <details className="trace-raw-events"><summary>阶段明细 · {Input.Trace.length} 条</summary>
                <div className="trace-event-list">
                {Input.Trace.map(Span => <TraceEvent key={Span.SpanId} Value={Span} />)}
                </div></details>}
        </div></Tabs.Content>

        <Tabs.Content value="streams"><div className="trace-block"><div className="trace-block-heading"><h3>Streams</h3><span>{Input.RelationsUnverified ? '待核实' : `${ResourceCount(Input.StreamsState, Input.Streams.length)} 条`}</span></div>
            {Input.RelationsUnverified ? <p className="field-hint">精确核实 Session 身份后才会请求 Streams；当前没有把未核实状态表示成空结果。</p>
                : <ResourceContent State={Input.StreamsState} Label="Streams">
            {Input.Streams.length === 0 ? <p className="field-hint">当前数据源没有返回 Stream 记录。</p> : <div className="resource-sublist">
                {Input.Streams.map(Stream => <StreamResource key={`${Stream.Id}-${Stream.TaskId}`} Session={Session} Value={Stream} CanMutate={MutationsAllowed}
                    Busy={Input.Busy} OnReset={() => Input.OnResetStream(Stream)} />)}</div>}
            </ResourceContent>}</div></Tabs.Content>
        <Tabs.Content value="tasks"><div className="trace-block"><div className="trace-block-heading"><h3>Tasks</h3><span>{Input.RelationsUnverified ? '待核实' : `${ResourceCount(Input.TasksState, Input.Tasks.length)} 条`}</span></div>
            {Input.RelationsUnverified ? <p className="field-hint">精确核实 Session 身份后才会请求 Tasks；当前没有把未核实状态表示成空结果。</p>
                : <ResourceContent State={Input.TasksState} Label="Tasks">
            {Input.Tasks.length === 0 ? <p className="field-hint">当前数据源没有返回 Task 记录。</p> : <div className="resource-sublist">
                {Input.Tasks.map(Task => <TaskResource key={Task.Id} Value={Task} CanMutate={MutationsAllowed} Busy={Input.Busy}
                    OnCancel={() => Input.OnCancelTask(Task)} />)}</div>}
            </ResourceContent>}</div></Tabs.Content>
        <Tabs.Content value="events"><div className="trace-block"><div className="trace-block-heading"><h3>关联事件</h3><span>{ResourceCount(Input.EventsState, Input.Events.length)} 条已载入</span></div>
            <ResourceContent State={Input.EventsState} Label="关联事件">
            {Input.Events.length === 0 ? <p className="field-hint">当前事件样本没有 Session ID 关联。</p> : <div className="resource-sublist">
                {Input.Events.map(Event => <Link className="related-row" key={Event.ProcessId + ':' + Event.Id} to={`/events?session=${encodeURIComponent(Session.Id)}`}>
                    <strong>{Event.Message}</strong><small>{FormatTime(Event.Time)} · {Event.CorrelationId}</small>
                </Link>)}</div>}
            </ResourceContent></div></Tabs.Content>
        </Tabs.Root>
        <p className="session-snapshot-note"><Activity size={13} />此连接身份已固定；刷新列表和新连接不会替换所选记录。</p>
    </section>;
}

function TraceWaterfall(Input: Readonly<{ Spans: readonly SessionTraceSpan[] }>): ReactNode {
    if (!Input.Spans.length) return <EmptyState Title="没有留存阶段事件" Detail="历史连接的 Trace 可能已被环形缓冲覆盖。" />;
    return <div className="trace-timeline" role="list" aria-label="Session 实际阶段时间线">
        {Input.Spans.map(Span => <div className="trace-timeline-item" role="listitem" key={Span.SpanId}>
            <div className="trace-timeline-time"><time dateTime={Span.StartTime}>{FormatTime(Span.StartTime)}</time>
                <small>{Elapsed(Span.Attributes.elapsed_ns)}</small></div>
            <div className="trace-timeline-content"><strong>{Span.Name}</strong><StatusBadge Label={Span.Status} Tone={ToneForState(Span.Status)} />
                <p>{Span.DurationMs === null ? '阶段事件 · 未提供独立 span 耗时' : FormatDuration(Span.DurationMs)}</p>
                {Span.Attributes.failure_code && <p>失败代码 {String(Span.Attributes.failure_code)}</p>}
            </div>
        </div>)}
    </div>;
}
function Elapsed(Value: string | boolean | null | undefined): string {
    if (typeof Value !== 'string' || !/^\d+$/.test(Value)) return '相对时间未提供';
    return '+' + (Number(BigInt(Value)) / 1_000_000).toFixed(2) + ' ms 自接入';
}

function TraceEvent(Input: Readonly<{ Value: SessionTraceSpan }>): ReactNode {
    const Span = Input.Value;
    return <details className="trace-event">
        <summary><time dateTime={Span.StartTime}>{FormatTime(Span.StartTime)}</time><strong>{Span.Name}</strong>
            <StatusBadge Label={Span.Status} Tone={ToneForState(Span.Status)} />
            <span>{Span.DurationMs === null ? '阶段事件' : FormatDuration(Span.DurationMs)}</span></summary>
        <div className="trace-attributes">
            <span>Span <code>{Span.SpanId}</code></span><span>Parent <code>{Span.ParentSpanId ?? '—'}</code></span>
            {Span.WorkerId && <span>Worker <code>{Span.WorkerId}</code></span>}
            {Span.AccountId && <span>Account <code>{Span.AccountId}</code></span>}
            {Span.StreamId && <span>Stream <code>{Span.StreamId}</code></span>}
            {Span.TaskId && <span>Task <code>{Span.TaskId}</code></span>}
            {Object.entries(Span.Attributes).map(([Key, Value]) => <span key={Key}>{Key} <code>{String(Value)}</code></span>)}
        </div>
    </details>;
}

function WorkerPath(Identity: Pick<SessionIdentity, 'WorkerId' | 'ProcessId' | 'GenerationId'>): string {
    const Params = new URLSearchParams({ worker: Identity.WorkerId, process: Identity.ProcessId, generation: Identity.GenerationId });
    return '/workers?' + Params.toString();
}

function SessionEventsPath(Session: SessionRecord): string {
    const Params = new URLSearchParams({ session: Session.Id, process: Session.ProcessId, generation: Session.GenerationId,
        worker: Session.WorkerId });
    return '/events?' + Params.toString();
}

function FormatDuration(Value: string | number | null): string {
    if (Value === null) return '未提供';
    const Duration = Number(Value);
    return Number.isFinite(Duration)
        ? `${new Intl.NumberFormat('zh-CN', { maximumFractionDigits: 2 }).format(Duration)} ms`
        : '耗时不可用';
}

function StreamResource(Input: Readonly<{ Session: SessionRecord; Value: StreamRecord; CanMutate: boolean; Busy: boolean; OnReset: () => Promise<unknown> }>): ReactNode {
    const Value = Input.Value;
    return <div className="resource-item"><span><strong>{Value.Id}</strong><small> · {Value.Protocol} · {Value.State}</small>
        <small> · Task {Value.TaskId} · Parent {Value.ParentTaskId ?? '—'}</small></span>
        <span>{Value.Traffic ? `${FormatBytes(Value.Traffic.Up)} ↑ / ${FormatBytes(Value.Traffic.Down)} ↓` : '流量未提供'}</span>
        {Input.CanMutate && Value.State === 'active' && Value.ParentTaskId !== null && <ConfirmAction Label="重置" Title="重置此 Stream？"
            Description={`Stream ${Value.Id} 将进入关闭流程。`} ConfirmLabel="确认重置" Tone="danger" Busy={Input.Busy} OnConfirm={Input.OnReset} />}
    </div>;
}

function TaskResource(Input: Readonly<{ Value: TaskRecord; CanMutate: boolean; Busy: boolean; OnCancel: () => Promise<unknown> }>): ReactNode {
    const Task = Input.Value;
    const CanCancel = Input.CanMutate && Task.Cancellable && !Task.CancelRequested && (Task.Status === 'running' || Task.Status === 'pending');
    const HasOutcome = Task.Status === 'succeeded' || Task.Status === 'failed' || Task.Status === 'canceled' || Task.Status === 'quarantined';
    return <div className="resource-item"><span><strong>{Task.Id}</strong><small> · {Task.Status} · Stream {Task.StreamId} · Parent {Task.ParentTaskId ?? '—'}</small>
        {Task.CancelRequested && <small> · 已请求取消；仍在 Task 清单中，资源退休尚未确认</small>}
        {HasOutcome && <small> · 已记录任务结果；当前仍在资源清单中，退休状态未确认</small>}
        {Task.Failure && <small> · 失败：{Task.Failure}</small>}</span>
        <span>{Task.DrainBlocked ? `排空受阻：${Task.DrainFailure ?? '等待资源关闭'}` : Task.StartedAt ? FormatTime(Task.StartedAt) : '开始时间未提供'}</span>
        {CanCancel && <ConfirmAction Label="取消 Task" Title="取消此 Task？" Description={`Task ${Task.Id} 将请求取消；受理请求不等于资源已退出，需以任务结果与排空状态复核。`}
            ConfirmLabel="确认取消" Tone="danger" Busy={Input.Busy} OnConfirm={Input.OnCancel} />}
    </div>;
}
