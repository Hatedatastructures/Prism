import { TimeLink as Link } from '../TimeLink';
import { Fragment, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { ArrowRight, ChevronDown, ChevronRight, RefreshCw, Search, Pause, Play } from 'lucide-react';
import { useSearchParams } from 'react-router';
import { EventSessionPath } from '../../Components/ResourcePaths';
import { Badge, EmptyState, FormatCount, FormatTime, LoadMoreButton, PageHeader, Panel,
    QueryState, StatusBadge, ToneForState } from '../../Components/Ui';
import type { EventPage, EventRecord, EventSeverity } from '../../Services/AdminDataSource';
import { useAdminInfiniteQuery } from '../UseOperations';

type SeverityFilter = 'all' | EventSeverity;
const Severities = [{ Value: 'all', Label: '全部' }, { Value: 'error', Label: '错误' }, { Value: 'warning', Label: '警告' },
    { Value: 'info', Label: '信息' }, { Value: 'debug', Label: '调试' }] as const;

export default function EventsPage(): ReactNode {
    const [Params, SetParams] = useSearchParams();
    const SessionId = Params.get('session') ?? '';
    const WorkerId = Params.get('worker') ?? '';
    const AccountId = Params.get('account') ?? '';
    const ProcessId = Params.get('process') ?? '';
    const GenerationId = Params.get('generation') ?? '';
    const SeverityValue = Params.get('severity') ?? 'all';
    const Severity: SeverityFilter = SeverityValue === 'error' || SeverityValue === 'warning' || SeverityValue === 'info' || SeverityValue === 'debug' ? SeverityValue : 'all';
    const SearchText = Params.get('q') ?? '';
    const [Expanded, SetExpanded] = useState('');
    const [Advanced, SetAdvanced] = useState(Boolean(SessionId || WorkerId || AccountId));
    const [Frozen, SetFrozen] = useState<Readonly<{ Pages: readonly EventPage[]; ScopeKey: string }> | null>(null);
    const Update = (Key: string, Value: string): void => {
        SetFrozen(null);
        const Next = new URLSearchParams(Params);
        if (Value && Value !== 'all') Next.set(Key, Value); else Next.delete(Key);
        SetParams(Next, { replace: Key === 'q' || Key === 'session' || Key === 'worker' || Key === 'account' });
    };
    const ClearFilters = (): void => {
        const Next = new URLSearchParams(Params);
        for (const Key of ['q', 'severity', 'session', 'worker', 'account', 'process', 'generation']) Next.delete(Key);
        SetFrozen(null);
        SetParams(Next);
    };
    const Filter = { ...(SessionId.trim() ? { SessionId: SessionId.trim() } : {}),
        ...(WorkerId.trim() ? { WorkerId: WorkerId.trim() } : {}), ...(AccountId.trim() ? { AccountId: AccountId.trim() } : {}),
        ...(ProcessId ? { ProcessId } : {}), ...(GenerationId ? { GenerationId } : {}),
        ...(Severity === 'all' ? {} : { Severity }) };
    const Scope = [Filter.SessionId ?? '', Filter.WorkerId ?? '', Filter.AccountId ?? '', Filter.Severity ?? 'all', ProcessId, GenerationId];
    const ScopeKey = JSON.stringify([...Scope, SearchText, Params.get('source') ?? '']);
    const PreviousScopeKey = useRef(ScopeKey);
    useEffect(() => {
        if (PreviousScopeKey.current === ScopeKey) return;
        PreviousScopeKey.current = ScopeKey;
        SetFrozen(null);
    }, [ScopeKey]);
    const Paused = Frozen !== null && Frozen.ScopeKey === ScopeKey;
    const Query = useAdminInfiniteQuery('events', (Source, Page) => Source.GetEvents(Page, Filter), Scope, { Refresh: !Paused });
    const Pages = Paused && Frozen ? Frozen.Pages : Query.data?.pages ?? [];
    const First = Pages[0];
    const Last = Pages[Pages.length - 1];
    const Rows = Pages.flatMap(Page => Page.Items);
    const HasMore = Last?.HasMore ?? false;
    const Summary = Last ?? First;
    const Lost = Pages.some(Page => Page.Lost);
    const LostRanges = Pages.flatMap(Page => Page.LostRanges).filter((Range, Index, Ranges) =>
        Ranges.findIndex(Value => Value.First === Range.First && Value.Last === Range.Last) === Index);
    const Visible = useMemo(() => Rows.filter(Event => (!ProcessId || Event.ProcessId === ProcessId) && (!GenerationId || Event.GenerationId === GenerationId) &&
        (!SearchText || [Event.Message, Event.Detail, Event.Kind, Event.Scope, Event.CorrelationId, Event.WorkerId, Event.SessionId, Event.AccountId].join(' ').toLowerCase().includes(SearchText.toLowerCase())))
        .sort((Left, Right) => BigInt(Left.Sequence) > BigInt(Right.Sequence) ? -1 : BigInt(Left.Sequence) < BigInt(Right.Sequence) ? 1 : 0), [Rows, SearchText, ProcessId, GenerationId]);
    return <div className="resource-workspace events-workspace">
        <PageHeader Title="事件流" Description="先看异常与关联资源，再展开完整事件。"
            Actions={<><button className="button button-secondary" type="button" disabled={!Paused && (!Query.data || Query.isFetchingNextPage)} onClick={() => { SetFrozen(Paused ? null : Query.data ? { Pages: Query.data.pages, ScopeKey } : null); }}>
                {Paused ? <Play size={14} /> : <Pause size={14} />}{Paused ? '继续追随' : '暂停追随'}</button><button className="button button-secondary" type="button" disabled={Query.isFetching || Paused} onClick={() => void Query.refetch()}><RefreshCw size={14} />刷新事件</button></>} />
        {Paused && <div className="notice notice-info" role="status">已暂停：固定显示暂停时已载入的 {FormatCount(Rows.length)} 条事件及各分页返回的游标、丢失状态。服务端仍继续采集；恢复追随后读取新窗口。</div>}
        <div className="page-metric-strip six-metrics" aria-label="事件缓冲区状态">
            <CursorMetric Label="已载入窗口" Value={First ? FormatCount(Rows.length) + (HasMore ? '+' : '') : '—'} />
            <CursorMetric Label="窗口内错误" Value={First ? String(Rows.filter(Event => Event.Severity === 'error').length) : '—'} Warning />
            <CursorMetric Label="窗口内警告" Value={First ? String(Rows.filter(Event => Event.Severity === 'warning').length) : '—'} Warning />
            <CursorMetric Label="累计丢弃" Value={Summary ? FormatCount(Summary.Dropped) : '—'} Warning />
            <CursorMetric Label="终止丢弃" Value={Summary ? FormatCount(Summary.TerminalDropped) : '—'} Warning />
            <CursorMetric Label="累计被覆盖" Value={Summary ? FormatCount(Summary.Overwritten) : '—'} Warning />
        </div>
        <Panel Title="运行事件" Action={<span className="list-scope">按序号倒序 · 当前已载入窗口</span>}>
            <div className="toolbar">
                <label className="search-field"><Search size={16} aria-hidden="true" /><input aria-label="搜索事件内容" placeholder="在已载入事件中搜索内容或关联 ID"
                    value={SearchText} onChange={Event => Update('q', Event.target.value)} /></label>
                <div className="state-filters" role="group" aria-label="按严重级别筛选">{Severities.map(Item => <button key={Item.Value}
                    type="button" aria-pressed={Severity === Item.Value} onClick={() => Update('severity', Item.Value)}>{Item.Label}</button>)}</div>
                <button className="button button-secondary" type="button" aria-expanded={Advanced} aria-controls="event-resource-filters"
                    onClick={() => SetAdvanced(!Advanced)}>资源筛选 <ChevronDown size={14} /></button>
            </div>
            <p className="table-footnote">Process、Generation 和内容搜索仅匹配当前已载入事件样本；继续载入可扩大样本范围。{Paused ? '暂停期间样本与游标状态保持固定。' : ''}</p>
            {(SessionId || WorkerId || AccountId || ProcessId || GenerationId || SearchText || Severity !== 'all') && <div className="applied-filters">
                {ProcessId && <span>Process: {ProcessId}</span>}{GenerationId && <span>Generation: {GenerationId}</span>}
                {SessionId && <span>Session: {SessionId}</span>}{WorkerId && <span>Worker: {WorkerId}</span>}{AccountId && <span>账户: {AccountId}</span>}
                {Severity !== 'all' && <span>级别: {Severities.find(Value => Value.Value === Severity)?.Label}</span>}{SearchText && <span>搜索: {SearchText}</span>}
                <button className="button button-quiet" type="button" onClick={ClearFilters}>清除筛选并恢复追随</button>
            </div>}
            {Advanced && <div id="event-resource-filters" className="event-resource-filters">
                <label>Session ID<input className="field-input" aria-label="按 Session ID 过滤" value={SessionId} onChange={Event => Update('session', Event.target.value)} /></label>
                <label>Worker ID<input className="field-input" aria-label="按 Worker ID 过滤" value={WorkerId} onChange={Event => Update('worker', Event.target.value)} /></label>
                <label>账户 ID<input className="field-input" aria-label="按账户 ID 过滤" value={AccountId} onChange={Event => Update('account', Event.target.value)} /></label>
            </div>}
            {First && <div className={`event-window-line ${Lost ? 'window-has-gap' : ''}`} role="status">
                <Badge Tone={Lost ? 'warning' : 'neutral'}>{Lost ? '窗口有缺口' : '窗口未报告缺口'}</Badge>
                <span>首载入页最早游标 {First.EarliestCursor} · 末载入页下一游标 {Last?.NextCursor ?? First.NextCursor}</span>
                <span>{Summary?.SeverityFilterSupported ? '支持服务端级别过滤' : '数据源未声明支持级别过滤'}</span>
                {Lost && <span>丢失范围：{LostRanges.map(Range => Range.First + '–' + Range.Last).join('、') || '未提供'}</span>}
            </div>}
            {Pages.length > 1 && <p className="table-footnote">累计计数取末载入页元数据；游标跨度连接首、末载入页，各页在不同请求时刻返回，并非同一时刻快照。</p>}
            <QueryState Pending={Query.isPending} Error={Query.error} Label="事件记录" HasData={Query.data !== undefined}
                Children={Visible.length === 0 ? <EmptyState Title="当前已载入范围无匹配事件" Detail={(HasMore && !Paused ? '继续载入以扩大检查范围。' : '调整筛选条件。') + (Lost ? '此窗口还存在不可恢复的丢失段。' : '')} /> :
                    <div className="table-scroll resource-table-scroll" tabIndex={0} role="region" aria-label="事件记录表，可横向滚动">
                        <table className="data-table event-table"><thead><tr><th>时间 / 序号</th><th>级别</th><th>事件内容</th><th>关联资源</th><th>详情</th></tr></thead>
                            <tbody>{Visible.map(Event => { const Key = `${Event.ProcessId}:${Event.Id}`; return <Fragment key={Key}>
                                <tr className={Expanded === Key ? 'row-selected' : ''}><td><time dateTime={Event.Time}>{FormatTime(Event.Time)}</time><small>#{FormatCount(Event.Sequence)}</small></td>
                                    <td><StatusBadge Label={SeverityLabel(Event.Severity)} Tone={ToneForState(Event.Severity)} /></td>
                                    <td className="event-message"><strong>{Event.Message}</strong><span>{Event.Detail || Event.Kind}{Event.Truncated ? ' · 已截断' : ''}</span></td>
                                    <td><EventResources Value={Event} /></td>
                                    <td><button className="button button-quiet" type="button" aria-label={`事件 ${Event.Id} 详情`} aria-expanded={Expanded === Key}
                                        aria-controls={`event-detail-${Event.Id}`} onClick={() => SetExpanded(Expanded === Key ? '' : Key)}>
                                        {Expanded === Key ? <ChevronDown size={15} /> : <ChevronRight size={15} />}<span>详情</span></button></td>
                                </tr>
                                {Expanded === Key && <tr id={`event-detail-${Event.Id}`} className="event-detail-row"><td colSpan={5}><EventDetail Value={Event} /></td></tr>}
                            </Fragment>; })}</tbody>
                        </table>
                    </div>} />
            <LoadMoreButton HasMore={!Paused && Query.hasNextPage} Busy={Query.isFetchingNextPage} OnLoad={() => void Query.fetchNextPage()} />
            <p className="table-footnote">显示 {Visible.length} / {Rows.length} 条已载入事件；累计丢弃与当前筛选结果分别统计。<span className="mobile-table-hint">表格可横向滚动查看关联资源与详情。</span></p>
        </Panel>
    </div>;
}
function CursorMetric(Input: Readonly<{ Label: string; Value: string; Warning?: boolean }>): ReactNode {
    return <div className="page-metric"><span>{Input.Label}</span><strong className={Input.Warning && Input.Value !== '0' && Input.Value !== '—' ? 'counter-warning' : ''}>{Input.Value}</strong></div>;
}
function SeverityLabel(Value: EventSeverity): string { return Value === 'error' ? '错误' : Value === 'warning' ? '警告' : Value === 'debug' ? '调试' : '信息'; }
function EventResources(Input: Readonly<{ Value: EventRecord }>): ReactNode {
    const Event = Input.Value;
    return <div className="event-resource-links">
        {Event.WorkerId && <Link to={EventWorkerPath(Event)}>{Event.WorkerId}</Link>}
        {Event.SessionId && <Link to={EventSessionPath(Event)}>{Event.SessionId}</Link>}
        {!Event.WorkerId && !Event.SessionId && Event.AccountId && <Link to={`/accounts?account=${encodeURIComponent(Event.AccountId)}`}>{Event.AccountId}</Link>}
        {!Event.WorkerId && !Event.SessionId && !Event.AccountId && <span>Process · G{Event.GenerationId}</span>}
    </div>;
}
function EventWorkerPath(Event: Pick<EventRecord, 'WorkerId' | 'ProcessId' | 'GenerationId'>): string {
    const Query = new URLSearchParams({ worker: Event.WorkerId ?? '', process: Event.ProcessId, generation: Event.GenerationId });
    return `/workers?${Query.toString()}`;
}
function EventDetail(Input: Readonly<{ Value: EventRecord }>): ReactNode {
    const Event = Input.Value;
    const [Copied, SetCopied] = useState(false);
    const [CopyError, SetCopyError] = useState(false);
    async function CopyCorrelation(): Promise<void> {
        try { await navigator.clipboard.writeText(Event.CorrelationId); SetCopied(true); SetCopyError(false); }
        catch { SetCopyError(true); }
    }
    return <div className="event-expanded"><p>{Event.Detail || '没有额外描述。'}{Event.Truncated ? ' 原始详情已截断。' : ''}</p>
        <dl className="inline-facts"><div><dt>类型 / 范围</dt><dd>{Event.Kind} / {Event.Scope}</dd></div>
            <div><dt>Process / Generation</dt><dd>{Event.ProcessId} / {Event.GenerationId}</dd></div>
            <div><dt>关联 ID</dt><dd>{Event.CorrelationId} <button className="button button-quiet" type="button" onClick={() => void CopyCorrelation()}>{Copied ? '已复制' : '复制关联 ID'}</button></dd></div>
            <div><dt>时间</dt><dd>{FormatTime(Event.Time, true)} · {Event.Terminal ? '终止事件' : '非终止事件'}</dd></div>
        </dl><div className="row-links">
            {Event.AccountId && <Link to={`/accounts?account=${encodeURIComponent(Event.AccountId)}`}>账户 {Event.AccountId}</Link>}
            {Event.OperationId && <Link to={`/operations?operation=${encodeURIComponent(Event.OperationId)}`}>操作 {Event.OperationId} <ArrowRight size={13} /></Link>}
            {Event.StreamId && <span>Stream {Event.StreamId}</span>}{Event.TaskId && <span>Task {Event.TaskId}</span>}
            {Event.ParentTaskId && <span>Parent Task {Event.ParentTaskId}</span>}
        </div>{CopyError && <p role="status">复制不可用，请选择上方关联 ID 手动复制。</p>}
    </div>;
}
