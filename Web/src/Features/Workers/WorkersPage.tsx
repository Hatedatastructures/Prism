import { TimeLink as Link } from '../TimeLink';
import { FilterScopeNotice } from '../FilterScopeNotice';
import { useMemo } from 'react';
import type { ReactNode } from 'react';
import * as Tabs from '@radix-ui/react-tabs';
import { ArrowRight, RefreshCw, Search } from 'lucide-react';
import { useSearchParams } from 'react-router';
import { ConfirmAction } from '../../Components/ConfirmAction';
import { SessionPath } from '../../Components/ResourcePaths';
import { Badge, EmptyState, FormatBytes, FormatCount, LoadMoreButton, PageHeader, Panel, ProgressBar,
    QueryState, StatusBadge, ToneForState } from '../../Components/Ui';
import type { SessionRecord, UInt64Value, WorkerRecord } from '../../Services/AdminDataSource';
import { useAdminInfiniteQuery, useAdminMutation, useAdminQuery } from '../UseOperations';
import { TimeRangeControl } from '../TimeRange';
import { HistoryPanel } from '../HistoryPanel';
import { ActionFeedback } from '../ActionFeedback';
import { CheckWorkerIdentity, WorkerTargetPath } from './WorkerIdentity';
import type { ExpectedWorkerIdentity, WorkerIdentityStatus } from './WorkerIdentity';

type WorkerFilter = 'all' | 'accepting' | 'draining' | 'stopped';

export default function WorkersPage(): ReactNode {
    const [Params, SetParams] = useSearchParams();
    const Query = useAdminInfiniteQuery('workers', (Source, Page) => Source.GetWorkers(Page));
    const SessionsQuery = useAdminInfiniteQuery('sessions', (Source, Page) => Source.GetSessions(Page));
    const Drain = useAdminMutation((Source, Worker: Pick<WorkerRecord, 'Id' | 'ProcessId' | 'GenerationId'>) => Source.DrainWorker(Worker));
    const Workers = Query.data?.pages.flatMap(Page => Page.Items) ?? [];
    const Sessions = SessionsQuery.data?.pages.flatMap(Page => Page.Items) ?? [];
    const Requested = Params.get('state') ?? 'all';
    const Filter: WorkerFilter = Requested === 'accepting' || Requested === 'draining' || Requested === 'stopped' ? Requested : 'all';
    const SearchText = Params.get('q') ?? '';
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
    };
    const Filtered = useMemo(() => Workers.filter(Worker => {
        const MatchText = !SearchText || `${Worker.Id} ${Worker.Name}`.toLowerCase().includes(SearchText.toLowerCase());
        return MatchText && (Filter === 'all' || Filter === 'accepting' && Worker.Accepting ||
            Filter === 'draining' && Worker.State === 'draining' || Filter === 'stopped' && !Worker.Running);
    }), [Workers, SearchText, Filter]);
    const SelectedId = Params.get('worker') ?? '';
    const Expected: ExpectedWorkerIdentity = {
        Id: SelectedId,
        ProcessId: Params.get('process'),
        GenerationId: Params.get('generation'),
    };
    const Exact = useAdminQuery('worker-target', Source => Source.GetWorkers({ Cursor: '0', Limit: 1, Id: SelectedId }), {
        Enabled: !!SelectedId,
        Scope: [SelectedId, Expected.ProcessId ?? '', Expected.GenerationId ?? ''],
    });
    const ExactTarget = Exact.isSuccess ? Exact.data?.Items.find(Worker => Worker.Id === SelectedId) ?? null : null;
    const IdentityStatus: WorkerIdentityStatus | null = SelectedId ? CheckWorkerIdentity(Expected, ExactTarget) : null;
    const Selected = SelectedId ? IdentityStatus === 'verified' ? ExactTarget : null : Query.isSuccess ? Filtered[0] ?? null : null;
    const Related = Sessions.filter(Session => Session.WorkerId === Selected?.Id &&
        Session.ProcessId === Selected.ProcessId && Session.GenerationId === Selected.GenerationId);
    const Available = (Value: string): string => Query.data === undefined ? '—' : Value;
    return <div className="resource-workspace workers-workspace">
        <PageHeader Title="Worker" Description="先比较队列与失败，再定位连接或执行排空。"
            Actions={<><TimeRangeControl /><button className="button button-secondary" type="button" disabled={Query.isFetching || SessionsQuery.isFetching}
                onClick={() => { void Promise.all([Query.refetch(), SessionsQuery.refetch()]); }}><RefreshCw size={14} />刷新快照</button></>} />
        <div className="page-metric-strip six-metrics" aria-label="Worker 运行摘要">
            <WorkerMetric Label="接收中 / 已载入" Value={Available(`${Workers.filter(Worker => Worker.Accepting).length} / ${Workers.length}${Query.hasNextPage ? '+' : ''}`)} />
            <WorkerMetric Label="排空中" Value={Available(String(Workers.filter(Worker => Worker.State === 'draining').length))} />
            <WorkerMetric Label="命令邮箱待处理" Value={Available(FormatCount(Sum(Workers.map(Worker => Worker.QueueDepth))))} />
            <WorkerMetric Label="累计派发拒绝" Value={Available(FormatCount(Sum(Workers.map(Rejections))))} Warning />
            <WorkerMetric Label="累计命令失败" Value={Available(FormatCount(Sum(Workers.map(Worker => Worker.CommandsFailed))))} Warning />
            <WorkerMetric Label="累计事件丢弃" Value={Available(FormatCount(Sum(Workers.map(Worker => Worker.DroppedEvents))))} Warning />
        </div>
        <Panel Title="Worker 清单" ClassName="worker-list-panel" Action={<span className="list-scope">已载入范围 · 点击 ID 查看明细</span>}>
            <div className="toolbar">
                <label className="search-field"><Search size={16} aria-hidden="true" /><input aria-label="搜索 Worker" placeholder="搜索 Worker ID 或名称"
                    value={SearchText} onChange={Event => Update('q', Event.target.value)} /></label>
                <div className="state-filters" role="group" aria-label="Worker 状态筛选">
                    {(['all', 'accepting', 'draining', 'stopped'] as const).map(Value => <button key={Value}
                        type="button" aria-pressed={Filter === Value} onClick={() => Update('state', Value)}>{FilterLabel(Value)}</button>)}
                </div>
            </div>
            <FilterScopeNotice Collection="workers" />
            <QueryState Pending={Query.isPending} Error={Query.error} Label="Worker 列表" HasData={Query.data !== undefined}
                Children={Filtered.length === 0 ? <EmptyState Title="没有匹配的 Worker" Detail="更改筛选或载入更多记录。" /> : <>
                    <div className="table-scroll resource-table-scroll" tabIndex={0} role="region" aria-label="Worker 对比表，可横向滚动">
                        <table className="data-table worker-comparison-table"><thead><tr><th>Worker</th><th>接收状态</th><th>活动任务</th><th>命令邮箱 / 容量</th>
                            <th>派发拒绝</th><th>命令失败</th><th>事件丢弃</th><th>快速定位</th></tr></thead>
                            <tbody>{Filtered.map(Worker => <WorkerRow key={`${Worker.ProcessId}-${Worker.GenerationId}-${Worker.Id}`} Value={Worker}
                                Selected={Selected?.Id === Worker.Id} OnSelect={() => SelectWorker(Worker)} />)}</tbody>
                        </table>
                    </div>
                    <p className="table-footnote">显示 {Filtered.length} / {Workers.length}{Query.hasNextPage ? '+' : ''} 个已载入 Worker；拒绝、失败、丢弃均为累计值。<span className="mobile-table-hint">表格可横向滚动。</span></p>
                    <LoadMoreButton HasMore={Query.hasNextPage} Busy={Query.isFetchingNextPage} OnLoad={() => void Query.fetchNextPage()} />
                </>} />
        </Panel>
        {SelectedId && IdentityStatus !== 'verified' && <WorkerTargetNotice Status={IdentityStatus ?? 'unavailable'}
            Expected={Expected} Current={ExactTarget} Pending={Exact.isPending} Error={Exact.error} />}
        {Selected && <WorkerInspector Value={Selected} Sessions={Related} SessionsPending={SessionsQuery.isPending}
            SessionsError={SessionsQuery.error} SessionsHasData={SessionsQuery.data !== undefined} SessionsHasMore={SessionsQuery.hasNextPage}
            Busy={Drain.isPending} CanDrain={SelectedId ? IdentityStatus === 'verified' && Exact.isSuccess && !Exact.isFetching : Query.isSuccess && !Query.isFetching}
            IdentityVerifying={SelectedId ? Exact.isFetching : Query.isFetching}
            OnDrain={() => Drain.mutateAsync(Selected)} />}
        {Drain.error && <div className="notice notice-warning" role="alert"><strong>排空结果尚未确认。</strong>
            <p>{Drain.error.message} 请刷新 Worker 快照后再判断当前状态。</p></div>}
        <ActionFeedback Result={Drain.data} />
        {Selected && <div className="analysis-split"><HistoryPanel Scope="worker" ResourceKey={Selected.Id} Title={`Worker ${Selected.Id} 流量`} /><HistoryPanel Scope="worker" ResourceKey={Selected.Id} Kind="active" Title="活动任务趋势" /></div>}
    </div>;
}

function Sum(Values: readonly UInt64Value[]): string { return Values.reduce<bigint>((Total, Value) => Total + BigInt(Value), 0n).toString(); }
function Rejections(Value: WorkerRecord): string {
    return Sum([Value.DispatchFull, Value.DispatchClosed, Value.DispatchUnavailable, Value.DispatchGenerationRejected]);
}
function Ratio(Value: WorkerRecord): number | null {
    return BigInt(Value.QueueCapacity) > 0n ? Number(BigInt(Value.QueueDepth) * 10_000n / BigInt(Value.QueueCapacity)) / 100 : null;
}
function FilterLabel(Value: WorkerFilter): string {
    return Value === 'accepting' ? '接收中' : Value === 'draining' ? '排空中' : Value === 'stopped' ? '已停止' : '全部';
}
function WorkerMetric(Input: Readonly<{ Label: string; Value: string; Warning?: boolean }>): ReactNode {
    return <div className="page-metric"><span>{Input.Label}</span><strong>{Input.Value}</strong></div>;
}
function WorkerRow(Input: Readonly<{ Value: WorkerRecord; Selected: boolean; OnSelect: () => void }>): ReactNode {
    const Worker = Input.Value;
    const QueueRatio = Ratio(Worker);
    return <tr className={Input.Selected ? 'row-selected' : ''}>
        <td><button className="table-link" type="button" aria-pressed={Input.Selected} onClick={Input.OnSelect}>
            <i className={`health-dot health-${Worker.Health}`} /><strong>{Worker.Id}</strong></button></td>
        <td><StatusBadge Label={Worker.Accepting ? '接收中' : Worker.State === 'draining' ? '排空中' : '已停止'} Tone={Worker.Accepting ? 'good' : ToneForState(Worker.State)} /></td>
        <td>{FormatCount(Worker.ActiveTasks)}</td><td><span className="queue-cell">{FormatCount(Worker.QueueDepth)} / {FormatCount(Worker.QueueCapacity)}</span>
            {QueueRatio === null ? <small className="field-hint">容量为 0，使用率不可计算。</small>
                : <ProgressBar Value={QueueRatio} Tone="mint" Label={`${Worker.Id} 命令邮箱使用率`} />}</td>
        <td>{FormatCount(Rejections(Worker))}</td>
        <td>{FormatCount(Worker.CommandsFailed)}</td>
        <td>{FormatCount(Worker.DroppedEvents)}</td>
        <td><div className="row-links"><Link to={WorkerTargetPath('sessions', Worker)}>连接</Link><Link to={WorkerTargetPath('events', Worker)}>事件</Link></div></td>
    </tr>;
}

function WorkerTargetNotice(Input: Readonly<{
    Status: Exclude<WorkerIdentityStatus, 'verified'>; Expected: ExpectedWorkerIdentity; Current: WorkerRecord | null;
    Pending: boolean; Error: Error | null;
}>): ReactNode {
    const ExpectedScope = `Process ${Input.Expected.ProcessId ?? '缺失'} · Generation ${Input.Expected.GenerationId ?? '缺失'}`;
    return <Panel ClassName="worker-target-notice" Title="指定 Worker 目标核验">
        {Input.Pending ? <EmptyState Title="正在核对当前 Worker" Detail={`${Input.Expected.Id} · ${ExpectedScope}`} />
            : Input.Error ? <EmptyState Title="无法核对指定 Worker" Detail={`${Input.Expected.Id} · ${ExpectedScope}。查询失败时不会用同号 slot 替代目标。`} />
            : Input.Status === 'scope-missing' ? <EmptyState Title="深链缺少完整身份范围" Detail={`${Input.Expected.Id} · ${ExpectedScope}。需要 process 与 generation 才能确认是否仍是原目标。`} />
            : Input.Status === 'changed' && Input.Current ? <EmptyState Title="Worker 目标已变更" Detail={`原目标 ${Input.Expected.Id} · ${ExpectedScope}；当前同号 slot 为 Process ${Input.Current.ProcessId} · Generation ${Input.Current.GenerationId}。当前记录不能代替旧目标。`} />
            : <EmptyState Title="当前快照没有该 Worker 记录" Detail={`${Input.Expected.Id} · ${ExpectedScope}。当前接口只返回当前进程与代次，不能查询旧代 Worker 历史。`} />}
        {Input.Current && <Link className="text-link" to={WorkerTargetPath('workers', Input.Current)}>打开当前代次的 Worker <ArrowRight size={13} /></Link>}
        <p className="field-hint">Worker 记录不含实例 incarnation；process/generation 相同也不能证明跨实例重启后仍是同一对象。</p>
    </Panel>;
}

function WorkerInspector(Input: Readonly<{
    Value: WorkerRecord; Sessions: readonly SessionRecord[]; SessionsPending: boolean; SessionsError: Error | null;
    SessionsHasData: boolean; SessionsHasMore: boolean; Busy: boolean; CanDrain: boolean; IdentityVerifying: boolean;
    OnDrain: () => Promise<unknown>;
}>): ReactNode {
    const Worker = Input.Value;
    const Accounts = [...new Set(Input.Sessions.map(Session => Session.AccountId))];
    const SessionCount = Input.SessionsHasData ? `${Input.Sessions.length}${Input.SessionsHasMore ? '+' : ''}` : Input.SessionsPending ? '…' : '不可用';
    const AccountCount = Input.SessionsHasData ? `${Accounts.length}${Input.SessionsHasMore ? '+' : ''}` : Input.SessionsPending ? '…' : '不可用';
    return <Panel ClassName="worker-inspector" Title={Worker.Id}
        Subtitle={`Process ${Worker.ProcessId} · Generation ${Worker.GenerationId}`}
        Action={<div className="button-row"><Link className="button button-secondary" to={WorkerTargetPath('events', Worker)}>关联事件</Link>
            {Worker.Running && Worker.Accepting && Input.CanDrain ? <ConfirmAction Label="排空 Worker" Title={`排空 ${Worker.Id}？`}
                Description={`停止新增派发并请求所属任务取消，等待传输与任务实际退休。目标为 Process ${Worker.ProcessId} · Generation ${Worker.GenerationId} · Worker ${Worker.Id}。接口仅按 Worker ID 执行，不能原子校验代次；确认前请刷新快照。`}
                ConfirmLabel="确认排空" Tone="danger" Busy={Input.Busy} OnConfirm={Input.OnDrain} />
                : <Badge Tone={Worker.State === 'draining' ? 'warning' : 'neutral'}>{Worker.Running && Worker.Accepting
                    ? Input.IdentityVerifying ? '正在核验目标' : '目标身份未核实'
                    : Worker.State === 'draining' ? '正在排空' : '当前不接收'}</Badge>}</div>}>
        <p className="field-hint">当前 Worker DTO 未提供实例 incarnation；本页按 process、generation 与 slot ID 核对，无法证明跨实例重启后仍是同一历史对象。</p>
        <Tabs.Root defaultValue="summary"><Tabs.List className="detail-tabs" aria-label="Worker 详情类别">
            <Tabs.Trigger value="summary">派发与任务</Tabs.Trigger><Tabs.Trigger value="sessions">关联 Session {SessionCount}</Tabs.Trigger>
            <Tabs.Trigger value="accounts">关联账户 {AccountCount}</Tabs.Trigger>
        </Tabs.List>
        <Tabs.Content value="summary"><div className="worker-facts-grid">
            <section><h3>派发结果 · 累计</h3><dl className="inline-facts">
                <Fact Label="已接收" Value={FormatCount(Worker.DispatchAccepted)} /><Fact Label="命令邮箱已满" Value={FormatCount(Worker.DispatchFull)} />
                <Fact Label="命令邮箱已关闭" Value={FormatCount(Worker.DispatchClosed)} /><Fact Label="Worker 不可用" Value={FormatCount(Worker.DispatchUnavailable)} />
                <Fact Label="代次拒绝" Value={FormatCount(Worker.DispatchGenerationRejected)} /><Fact Label="命令执行 / 失败" Value={`${FormatCount(Worker.CommandsExecuted)} / ${FormatCount(Worker.CommandsFailed)}`} />
            </dl></section>
            <section><h3>任务与流量</h3><dl className="inline-facts">
                <Fact Label="启动 / 完成" Value={`${FormatCount(Worker.StartedTasks)} / ${FormatCount(Worker.CompletedTasks)}`} />
                <Fact Label="已取消任务" Value={FormatCount(Worker.CancelledTasks)} /><Fact Label="活动任务" Value={FormatCount(Worker.ActiveTasks)} />
                <Fact Label="累计上行" Value={Worker.Traffic ? FormatBytes(Worker.Traffic.Up) : '未提供'} />
                <Fact Label="累计下行" Value={Worker.Traffic ? FormatBytes(Worker.Traffic.Down) : '未提供'} />
            </dl></section>
        </div></Tabs.Content>
        <Tabs.Content value="sessions"><QueryState Pending={Input.SessionsPending} Error={Input.SessionsError} Label="关联连接" HasData={Input.SessionsHasData}
            Children={<div className="related-list">{Input.Sessions.length === 0 ? <p className="field-hint">已载入连接快照中没有关联记录。</p> : Input.Sessions.slice(0, 8).map(Session =>
                <Link className="related-row" key={[Session.ProcessId, Session.GenerationId, Session.WorkerId, Session.AccountId, Session.Id].join(':')} to={SessionPath(Session)}>
                    <strong>{Session.Id}</strong><span>{Session.Protocol} · {Session.Draining ? '排空中' : Session.Active ? '活动中' : '已结束'}</span><small>{Session.Target}</small>
                </Link>)}<Link className="text-link" to={WorkerTargetPath('sessions', Worker)}>查看连接清单{Input.SessionsHasMore ? '（还有未载入记录）' : ''} <ArrowRight size={13} /></Link></div>} /></Tabs.Content>
        <Tabs.Content value="accounts"><QueryState Pending={Input.SessionsPending} Error={Input.SessionsError} Label="关联账户" HasData={Input.SessionsHasData}
            Children={<div className="related-list">{Accounts.length === 0 ? <p className="field-hint">已载入连接快照中没有账户关联。</p> : Accounts.map(Id =>
                <Link className="related-row" key={Id} to={`/accounts?account=${encodeURIComponent(Id)}`}><strong>{Id}</strong><span>打开账户 <ArrowRight size={13} /></span></Link>)}</div>} /></Tabs.Content>
        </Tabs.Root>
    </Panel>;
}
function Fact(Input: Readonly<{ Label: string; Value: string }>): ReactNode { return <div><dt>{Input.Label}</dt><dd>{Input.Value}</dd></div>; }
