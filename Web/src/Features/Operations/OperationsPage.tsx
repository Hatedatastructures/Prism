import { TimeLink as Link } from '../TimeLink';
import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { Activity, ArrowRight, CheckCheck, Clock3, ListTodo, RefreshCw } from 'lucide-react';
import { useSearchParams } from 'react-router';
import { Badge, EmptyState, FormatTime, LoadMoreButton, PageHeader, Panel, QueryState, SectionHeading, StatusBadge, ToneForState } from '../../Components/Ui';
import { OperationScopeChangedError } from '../../Services/AdminDataSource';
import type { OperationRecord, OperationScope } from '../../Services/AdminDataSource';
import { useAdminInfiniteQuery, useAdminServices, useBootstrapIdentity } from '../UseOperations';

export default function OperationsPage(): ReactNode {
    const [Params, SetParams] = useSearchParams();
    const Services = useAdminServices();
    const Bootstrap = useBootstrapIdentity();
    const CurrentScope: OperationScope | null = Bootstrap.isSuccess && Bootstrap.data
        ? { ProcessId: Bootstrap.data.ProcessId, Incarnation: Bootstrap.data.Incarnation } : null;
    const RouteId = Params.get('operation') ?? '';
    const RouteProcessId = Params.get('process');
    const RouteIncarnation = Params.get('incarnation');
    const RouteScope: OperationScope | null = RouteProcessId && RouteIncarnation
        ? { ProcessId: RouteProcessId, Incarnation: RouteIncarnation } : null;
    const HasScopeChanged = !!RouteId && !!CurrentScope && !!RouteScope &&
        (CurrentScope.ProcessId !== RouteScope.ProcessId || CurrentScope.Incarnation !== RouteScope.Incarnation);
    const ScopeState = !CurrentScope ? Bootstrap.isError ? 'bootstrap-error' : 'bootstrap-pending'
        : RouteId && !RouteScope ? 'unscoped' : HasScopeChanged ? 'mismatch' : 'match';
    const Query = useAdminInfiniteQuery('operations', (Source, Page) => CurrentScope
        ? Source.GetOperations(Page, CurrentScope) : Promise.resolve({ Items: [], NextCursor: '0', HasMore: false }),
        CurrentScope ? [CurrentScope.ProcessId, CurrentScope.Incarnation] : ['scope-unavailable'], { Refresh: !!CurrentScope });
    const Operations = Query.data?.pages.flatMap(Page => Page.Items) ?? [];
    const [SelectionCleared, SetSelectionCleared] = useState(false);
    const Selected = RouteId ? ScopeState === 'match' ? Operations.find(Operation => Operation.Id === RouteId) : undefined
        : SelectionCleared ? undefined : Operations[0];
    const TargetId = RouteId || Selected?.Id || '';
    const TargetScope = RouteId ? RouteScope : CurrentScope;
    const [OpenedAt, SetOpenedAt] = useState(() => Date.now());
    useEffect(() => SetOpenedAt(Date.now()), [TargetId, TargetScope?.ProcessId, TargetScope?.Incarnation]);
    const StatusQuery = useQuery({ queryKey: ['operations', 'operation-status', TargetId, TargetScope?.ProcessId, TargetScope?.Incarnation],
        enabled: !!TargetId && ScopeState === 'match' && !!TargetScope,
        queryFn: () => Services.Data.GetOperationStatus(TargetId, TargetScope!), retry: false, refetchIntervalInBackground: false,
        refetchInterval: Value => Value.state.error instanceof OperationScopeChangedError ? false
            : Value.state.data && !['accepted', 'running'].includes(Value.state.data.State) ? false
                : Date.now() - OpenedAt < 30_000 ? 1000 : 5000 });
    const ScopeChanged = StatusQuery.error instanceof OperationScopeChangedError;
    const ListScopeChanged = Query.error instanceof OperationScopeChangedError;
    useEffect(() => { if (ScopeChanged || ListScopeChanged) void Bootstrap.refetch(); }, [ScopeChanged, ListScopeChanged, Bootstrap.refetch]);
    const ViewScopeState = ScopeChanged ? 'mismatch' : ScopeState;
    const StatusRecord = StatusQuery.data?.Id === TargetId ? StatusQuery.data : undefined;
    const Unverifiable = StatusQuery.data !== undefined && StatusRecord === undefined;
    const Completed = Operations.filter(Operation => Operation.State === 'completed').length;
    const InProgress = Operations.filter(Operation => Operation.State === 'accepted' || Operation.State === 'running').length;
    const Failed = Operations.filter(Operation => ['failed', 'rejected', 'timed_out', 'blocked', 'conflict', 'invalid'].includes(Operation.State)).length;

    const Select = (Id: string): void => {
        if (!CurrentScope) return;
        const Next = new URLSearchParams(Params);
        Next.set('operation', Id); Next.set('process', CurrentScope.ProcessId); Next.set('incarnation', CurrentScope.Incarnation);
        SetSelectionCleared(false); SetParams(Next, { replace: true });
    };
    const ClearSelection = (): void => {
        const Next = new URLSearchParams(Params);
        for (const Key of ['operation', 'process', 'incarnation']) Next.delete(Key);
        SetSelectionCleared(true); SetParams(Next, { replace: true });
    };
    const DefaultId = Operations[0]?.Id ?? '';
    useEffect(() => {
        if (RouteId || SelectionCleared || !DefaultId || !CurrentScope) return;
        const Next = new URLSearchParams(Params);
        Next.set('operation', DefaultId); Next.set('process', CurrentScope.ProcessId); Next.set('incarnation', CurrentScope.Incarnation);
        SetParams(Next, { replace: true });
    }, [RouteId, SelectionCleared, DefaultId, CurrentScope?.ProcessId, CurrentScope?.Incarnation, Params, SetParams]);
    const Detail = Selected ? EnrichOperationTarget(Selected, StatusRecord) : StatusRecord;

    return <>
        <PageHeader Title="操作中心"
            Description="区分已受理、真实完成和结果未知；按完整目标与操作 ID 核对。"
            Actions={<Badge Tone="accent" Dot>{Services.Mode === 'demo' ? '演示记录' : '当前管理端保留范围'}</Badge>} />
        <div className="operation-summary-strip" aria-label="操作统计">
            <OperationMetric Label="近期操作" Value={String(Operations.length)} Icon={<ListTodo size={15} />} />
            <OperationMetric Label="已完成" Value={String(Completed)} Icon={<CheckCheck size={15} />} />
            <OperationMetric Label="尚未观测到终态" Value={String(InProgress)} Icon={<Activity size={15} />} />
            <OperationMetric Label="失败 / 拒绝" Value={String(Failed)} Icon={<Clock3 size={15} />} />
        </div>
        <Panel Title="近期操作记录" Subtitle="选择一项核对状态、失败原因和关联身份"
            Action={<button className="button button-quiet" type="button" disabled={!TargetId} onClick={ClearSelection}>清除选择</button>}>
            <QueryState Pending={(!CurrentScope && !Bootstrap.isError) || Query.isPending} Error={Bootstrap.error ?? Query.error}
                Label="操作记录" HasData={!!CurrentScope && Query.data !== undefined}
                Children={Operations.length === 0 && !TargetId ? <EmptyState Title="暂无操作记录" Detail="提交管理命令后可在这里核对结果。" /> :
                    <div className="operation-layout">
                        <div className="operation-list" role="group" aria-label="近期操作">
                            {Operations.map(Operation => <OperationRow Value={Operation} key={Operation.Id}
                                Selected={Operation.Id === Selected?.Id} Disabled={!CurrentScope} OnSelect={() => Select(Operation.Id)} />)}
                            <LoadMoreButton HasMore={Query.hasNextPage ?? false} Busy={Query.isFetchingNextPage}
                                OnLoad={() => void Query.fetchNextPage()} />
                        </div>
                        {ViewScopeState === 'mismatch' ? <div className="notice notice-warning operation-lookup-error" role="status">
                                <strong>来源实例已变，未查询同号操作</strong>
                                <p>链接或本次查询来源为 Process {(RouteScope ?? TargetScope)?.ProcessId ?? '未提供'} / Incarnation {(RouteScope ?? TargetScope)?.Incarnation ?? '未提供'}；服务端身份复核检测到变化，此 ID 不会按新实例重新解释。</p>
                                {CurrentScope && <small>当前页面最近确认的实例：Process {CurrentScope.ProcessId} / Incarnation {CurrentScope.Incarnation}。</small>}
                                <Link className="button button-secondary" to={CurrentOperationsPath(Params)}>查看当前实例操作列表 <ArrowRight size={12} /></Link>
                            </div>
                            : ViewScopeState === 'unscoped' ? <div className="notice notice-warning operation-lookup-error" role="status">
                                <strong>操作链接未包含来源实例</strong>
                                <p>该 ID 可能在进程重启后复用。本页不会把它当作原操作查询；列表只展示当前实例保留的记录，来源无法确认。选择一行后会将 URL 绑定到当前实例。</p>
                            </div>
                            : ViewScopeState === 'bootstrap-pending' ? <EmptyState Title="正在读取当前实例身份" Detail="确认 Process 与 Incarnation 后才查询操作 ID。" />
                            : ViewScopeState === 'bootstrap-error' ? <div className="notice notice-warning" role="status"><strong>当前无法核实操作来源</strong><p>{Bootstrap.error?.message ?? '当前实例身份读取失败。'}</p></div>
                            : Detail ? <OperationDetail Value={Detail} Current={StatusRecord} Scope={TargetScope} Unverifiable={Unverifiable}
                                LastReadAt={StatusQuery.dataUpdatedAt} Pending={StatusQuery.isPending} Fetching={StatusQuery.isFetching}
                                Error={StatusQuery.error} OnRefresh={() => { void StatusQuery.refetch(); }} />
                                : TargetId && Unverifiable ? <div className="notice notice-warning operation-lookup-error" role="status">
                                    <strong>当前实例没有可验证的此操作记录</strong><p>状态响应未回显请求的操作 ID。记录可能已淘汰或实例已重启；不能推断原操作是否执行。请按目标与时间核对当前列表。</p>
                                </div>
                                : TargetId && StatusQuery.error ? <div className="notice notice-warning operation-lookup-error" role="status">
                                    <strong>当前状态未知</strong><p>{StatusQuery.error.message}。当前实例无法确认原操作是否执行；先核对目标状态，不要重复提交命令。</p>
                                    <button className="button button-secondary" type="button" disabled={StatusQuery.isFetching} onClick={() => { void StatusQuery.refetch(); }}>
                                        <RefreshCw size={14} />{StatusQuery.isFetching ? '查询中…' : '重新查询'}
                                    </button>
                                </div>
                                : TargetId ? <div className="operation-lookup-pending">
                                    <QueryState Pending={StatusQuery.isPending} Error={null} HasData={false} Label="指定操作"
                                        Children={<EmptyState Title="正在核对指定操作" Detail="先确认当前实例，然后通过原操作 ID 查询；查询失败不会自动重新提交命令。" />} />
                                    <button className="button button-quiet" type="button" disabled={StatusQuery.isFetching} onClick={() => { void StatusQuery.refetch(); }}>
                                        <RefreshCw size={14} />{StatusQuery.isFetching ? '查询中…' : '重新查询此操作'}
                                    </button>
                                </div> : <EmptyState Title="未选择操作" Detail="从当前操作列表中选择一条记录。" />}
                    </div>} />
        </Panel>
        <div className="notice notice-info operation-retention-note"><Clock3 size={14} />HTTP 超时或记录未命中不能证明命令没有执行。优先查询原操作；结果未知时先核对目标状态。</div>
    </>;
}

function OperationMetric(Input: Readonly<{ Label: string; Value: string; Icon: ReactNode }>): ReactNode {
    return <div className="operation-summary-cell"><span>{Input.Icon}{Input.Label}</span><strong>{Input.Value}</strong></div>;
}

function OperationRow(Input: Readonly<{ Value: OperationRecord; Selected: boolean; Disabled: boolean; OnSelect: () => void }>): ReactNode {
    const Value = Input.Value;
    return <button className={`operation-record ${Input.Selected ? 'selected' : ''}`} type="button" disabled={Input.Disabled}
        aria-pressed={Input.Selected} onClick={Input.OnSelect}>
        <span className="operation-record-head"><strong>{Value.Name}</strong><StatusBadge Label={OperationLabel(Value.State)} Tone={ToneForState(Value.State)} /></span>
        <p>{Value.Message}</p>
        <span className="operation-record-meta"><span>{Value.Id}</span><span>目标 {Value.Target}</span><span>{FormatTime(Value.StartedAt, true)}</span></span>
    </button>;
}

function EnrichOperationTarget(ListRecord: OperationRecord, DetailRecord: OperationRecord | undefined): OperationRecord {
    if (!DetailRecord) return ListRecord;
    const UpdatedAt = DetailRecord.UpdatedAt ?? ListRecord.UpdatedAt;
    const ProcessId = DetailRecord.ProcessId ?? ListRecord.ProcessId;
    const WorkerId = DetailRecord.WorkerId ?? ListRecord.WorkerId;
    const AccountId = DetailRecord.AccountId ?? ListRecord.AccountId;
    const SessionId = DetailRecord.SessionId ?? ListRecord.SessionId;
    const StreamId = DetailRecord.StreamId ?? ListRecord.StreamId;
    const TaskId = DetailRecord.TaskId ?? ListRecord.TaskId;
    const ParentTaskId = DetailRecord.ParentTaskId ?? ListRecord.ParentTaskId;
    return {
        ...ListRecord,
        ...(ProcessId !== undefined ? { ProcessId } : {}),
        GenerationId: DetailRecord.GenerationId ?? ListRecord.GenerationId,
        ...(WorkerId !== undefined ? { WorkerId } : {}),
        ...(AccountId !== undefined ? { AccountId } : {}),
        ...(SessionId !== undefined ? { SessionId } : {}),
        ...(StreamId !== undefined ? { StreamId } : {}),
        ...(TaskId !== undefined ? { TaskId } : {}),
        ...(ParentTaskId !== undefined ? { ParentTaskId } : {}),
        StartedAt: DetailRecord.StartedAt ?? ListRecord.StartedAt,
        ...(UpdatedAt !== undefined ? { UpdatedAt } : {}),
    };
}

function OperationDetail(Input: Readonly<{
    Value: OperationRecord; Current: OperationRecord | undefined; Scope: OperationScope | null; Unverifiable: boolean; LastReadAt: number;
    Pending: boolean; Fetching: boolean; Error: Error | null; OnRefresh: () => void;
}>): ReactNode {
    const Value = Input.Value;
    const Verified = Input.Current !== undefined && Input.Error === null;
    const LastKnown = Input.Current ?? Value;
    const StatusLabel = Verified && Input.Current ? OperationLabel(Input.Current.State)
        : Input.Error || Input.Unverifiable ? '当前状态未知' : Input.Pending ? '正在核对' : '尚未核实';
    const StatusTone = Verified && Input.Current ? ToneForState(Input.Current.State) : ToneForState('unknown');
    const LastKnownSource = Input.Current ? '最近成功查询' : '操作列表最后记录';
    const LastKnownTime = Input.Current ? ReadTime(Input.LastReadAt)
        : Value.UpdatedAt ? '列表所见末次状态事件 ' + FormatTime(Value.UpdatedAt, true) : '列表状态事件时间未提供';
    const Message = Verified && Input.Current ? Input.Current.Message : LastKnown.Message;
    const Failure = Verified && Input.Current ? Input.Current.Failure : LastKnown.Failure;
    const SessionTarget = SessionPath(Value);
    return <section className="operation-inspector" aria-label="操作详情">
        <SectionHeading Title={`${Value.Name} · ${Value.Target}`} Detail={`操作 ID ${Value.Id}`} />
        <QueryState Pending={Input.Pending} Error={null} Label="操作状态" HasData={true}
            Children={<>
                <div className="operation-detail-state">
                    <StatusBadge Label={StatusLabel} Tone={StatusTone} />
                    <span>{Verified ? '当前状态 · 最近成功读取 ' + ReadTime(Input.LastReadAt)
                        : LastKnownSource + '：' + OperationLabel(LastKnown.State) + ' · ' + LastKnownTime}</span>
                    <button className="button button-quiet" type="button" disabled={Input.Fetching}
                        onClick={Input.OnRefresh}><RefreshCw size={14} />{Input.Fetching ? '查询中…' : '重新查询'}</button>
                </div>
                {Input.Error && <div className="notice notice-warning" role="status">
                    <strong>当前状态查询失败，无法确认操作是否仍在执行。</strong>
                    <p>{Input.Error.message}。你可以重新查询同一操作；不要重复提交命令。</p>
                </div>}
                {Input.Unverifiable && <div className="notice notice-warning" role="status">
                    <strong>当前实例没有可验证的此操作记录</strong>
                    <p>状态响应没有回显请求的操作 ID。记录可能已淘汰或实例已重启；这不能证明原操作失败、取消或未执行。</p>
                </div>}
                <strong className="operation-message">{Verified ? Message : '最后记录：' + Message}</strong>
                {Failure && <Badge Tone="danger">{Verified ? '失败原因：' : '最后记录的失败原因：'}{Failure}</Badge>}
                <dl className="detail-kv">
                    <div><dt>命令</dt><dd>{Value.Name}</dd></div><div><dt>目标</dt><dd>{Value.Target}</dd></div>
                    <div><dt>操作 ID</dt><dd>{Value.Id}</dd></div><div><dt>关联 ID</dt><dd>{Value.CorrelationId || '未提供'}</dd></div>
                    <div><dt>Process</dt><dd>{Value.ProcessId ?? '未提供'}</dd></div>
                    <div><dt>Process Incarnation</dt><dd>{Input.Scope?.Incarnation ?? '未提供'}</dd></div>
                    <div><dt>Generation</dt><dd>{Value.GenerationId ?? '未提供'}</dd></div>
                    <div><dt>Worker</dt><dd>{Value.WorkerId ?? '未提供'}</dd></div>
                    <div><dt>账户</dt><dd>{Value.AccountId ?? '未提供'}</dd></div>
                    <div><dt>Session</dt><dd>{Value.SessionId ?? '未提供'}</dd></div>
                    <div><dt>Stream</dt><dd>{Value.StreamId ?? '未提供'}</dd></div>
                    <div><dt>Task</dt><dd>{Value.TaskId ?? '未提供'}</dd></div>
                    <div><dt>Parent Task</dt><dd>{Value.ParentTaskId ?? '未提供'}</dd></div>
                    <div><dt>受理事件时间</dt><dd>{Value.StartedAt ? FormatTime(Value.StartedAt, true) : '未提供'}</dd></div>
                    <div><dt>列表所见末次状态事件</dt><dd>{Value.UpdatedAt ? FormatTime(Value.UpdatedAt, true) : '未提供'}</dd></div>
                </dl>
                <div className="detail-links">
                    {Value.WorkerId && Value.ProcessId && Value.GenerationId && <Link to={WorkerPath(Value)}>查看 Worker {Value.WorkerId} 的目标范围 <ArrowRight size={11} /></Link>}
                    {Value.WorkerId && (!Value.ProcessId || !Value.GenerationId) && <span>Worker {Value.WorkerId} · 缺少 Process/Generation，不能精确跳转</span>}
                    {Value.AccountId && <Link to={`/accounts?account=${encodeURIComponent(Value.AccountId)}`}>查看当前账户 {Value.AccountId} <ArrowRight size={11} /></Link>}
                    {Value.SessionId && SessionTarget && <Link to={SessionTarget}>Session {Value.SessionId} <ArrowRight size={11} /></Link>}
                    {Value.SessionId && !SessionTarget && <span>Session {Value.SessionId} · 完整身份字段不足，无法精确跳转</span>}
                </div>
            </>} />
    </section>;
}

function ReadTime(Value: number): string {
    return Number.isFinite(Value) && Value > 0
        ? FormatTime(new Date(Value).toISOString(), true) : '读取时间未提供';
}

function SessionPath(Value: OperationRecord): string | null {
    if (!Value.SessionId || !Value.ProcessId || !Value.WorkerId || !Value.GenerationId) return null;
    const Params = new URLSearchParams({
        session: Value.SessionId, process: Value.ProcessId,
        identity_worker: Value.WorkerId, generation: Value.GenerationId,
    });
    if (Value.AccountId) Params.set('identity_account', Value.AccountId);
    return '/sessions?' + Params.toString();
}

function WorkerPath(Value: OperationRecord): string {
    const Params = new URLSearchParams({ worker: Value.WorkerId ?? '', process: Value.ProcessId ?? '', generation: Value.GenerationId ?? '' });
    return '/workers?' + Params.toString();
}

function CurrentOperationsPath(Current: URLSearchParams): string {
    const Params = new URLSearchParams(Current);
    for (const Key of ['operation', 'process', 'incarnation']) Params.delete(Key);
    const Query = Params.toString();
    return '/operations' + (Query ? '?' + Query : '');
}

function OperationLabel(State: OperationRecord['State']): string {
    const Labels: Readonly<Record<OperationRecord['State'], string>> = {
        accepted: '已接收', running: '等待终态', completed: '已完成', rejected: '已拒绝', unavailable: '不可用',
        failed: '失败', timed_out: '超时', blocked: '受阻', restart_required: '需重启', conflict: '版本冲突', invalid: '无效请求',
        unknown: '结果未知', interrupted: '中断待核对',
    };
    return Labels[State];
}
