import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { FormatTime } from '../../Api/Decimal';
import { DecodeEventsQuery, EventKindValues, VerifyProcessScope } from '../../Api/OperationsApi';
import type { Event, EventKind, EventPage, EventScope, EventSeverity } from '../../Api/OperationsApi';
import { DataCell, EmptyState, QueryView, SectionHeading, StatusBadge } from '../../Components/ResultView';
import { useAdminServices } from '../UseOperations';

const PageSize = 100;

export default function EventsPage(): React.ReactNode {
    const Services = useAdminServices();
    const [Cursor, SetCursor] = useState('0');
    const [History, SetHistory] = useState<readonly string[]>([]);
    const [IncludeDetails, SetIncludeDetails] = useState(true);
    const [TerminalOnly, SetTerminalOnly] = useState(false);
    const [Severity, SetSeverity] = useState<EventSeverity | 'all'>('all');
    const [Kind, SetKind] = useState<EventKind | 'all'>('all');
    const Params = new URLSearchParams({ cursor: Cursor, limit: String(PageSize),
        include_details: String(IncludeDetails) });
    const Path = `/Operations/Events?${Params.toString()}`;
    const Query = useQuery({
        queryKey: ['events', Services.Bootstrap.Process, Services.Bootstrap.Incarnation,
            Cursor, IncludeDetails],
        queryFn: ({ signal }) => Services.Client.Query({ Path, Signal: signal,
            Decode: Response => VerifyProcessScope(DecodeEventsQuery(Response), Services.Bootstrap.Process) }),
        refetchInterval: 5000,
        refetchIntervalInBackground: false,
        retry: false,
    });
    function Next(Value: string): void {
        SetHistory([...History, Cursor]);
        SetCursor(Value);
    }
    function Previous(): void {
        const Value = History[History.length - 1];
        if (Value === undefined) return;
        SetHistory(History.slice(0, -1));
        SetCursor(Value);
    }
    return <>
        <SectionHeading Eyebrow="EVENTS" Title="事件流"
            Description="按事件序号浏览当前保留窗口，查看记录缺口、结束状态和详情截断提示。" />
        <section className="panel">
            <div className="panel-heading"><div><h2>事件查询</h2>
            <p>每 5 秒刷新当前页；页面隐藏时暂停刷新。</p></div></div>
            <div className="panel-body">
                <div className="toolbar" role="group" aria-label="事件显示选项">
                    <label className="filter-check"><input type="checkbox" checked={IncludeDetails}
                        onChange={Event => SetIncludeDetails(Event.target.checked)} />显示事件详情</label>
                    <label className="filter-check"><input type="checkbox" checked={TerminalOnly}
                        onChange={Event => SetTerminalOnly(Event.target.checked)} />只看终态（当前页过滤）</label>
                    <label className="field">级别（当前页）
                        <select value={Severity} onChange={Event => {
                            const Value = Event.target.value;
                            if (Value === 'all' || Value === 'debug' || Value === 'info' ||
                                Value === 'warning' || Value === 'error' || Value === 'unknown') SetSeverity(Value);
                        }}>
                            <option value="all">全部级别</option><option value="debug">调试</option>
                            <option value="info">信息</option><option value="warning">警告</option>
                            <option value="error">错误</option><option value="unknown">未知级别</option>
                        </select></label>
                    <label className="field">类型（当前页）
                        <select value={Kind} onChange={Event => {
                            const Value = Event.target.value;
                            if (Value === 'all' || EventKindValues.includes(Value as EventKind)) {
                                SetKind(Value as EventKind | 'all');
                            }
                        }}>
                            <option value="all">全部类型</option>
                            {EventKindValues.map(Value => <option value={Value} key={Value}>{EventKindLabel(Value)}</option>)}
                        </select></label>
                </div>
                <QueryView Query={Query} Label="事件页面" Children={Value => <EventsTable
                    Value={Value} TerminalOnly={TerminalOnly} Severity={Severity} Kind={Kind} OnNext={Next} /> } />
                {History.length > 0 && <button className="button button-secondary" onClick={Previous}>
                    上一页
                </button>}
            </div>
        </section>
    </>;
}

function EventsTable(Input: Readonly<{
    Value: EventPage; TerminalOnly: boolean; Severity: EventSeverity | 'all'; Kind: EventKind | 'all';
    OnNext: (Cursor: string) => void;
}>): React.ReactNode {
    const Events = Input.Value.Items.filter(Event => (!Input.TerminalOnly || Event.Terminal) &&
        (Input.Severity === 'all' || Event.Severity === Input.Severity) &&
        (Input.Kind === 'all' || Event.Kind === Input.Kind));
    let SeveritySupport = '暂不可用';
    if (Input.Value.SeverityFilterSupported) SeveritySupport = '可用';
    if (Input.Value.Lost || Input.Value.LostRanges.length > 0) {
        return <>
            <EventWindow Value={Input.Value} SeveritySupport={SeveritySupport} />
            <div className="notice notice-warn" role="status">
                <div><strong>保留窗口中有事件缺口</strong><p>以下序号区间没有对应记录，页面不会补写事件。</p>
                    <LostRanges Ranges={Input.Value.LostRanges} /></div>
            </div>
            <EventRows Events={Events} HasMore={Input.Value.HasMore}
                NextCursor={Input.Value.NextCursor} OnNext={Input.OnNext} />
        </>;
    }
    return <>
        <EventWindow Value={Input.Value} SeveritySupport={SeveritySupport} />
        <EventRows Events={Events} HasMore={Input.Value.HasMore}
            NextCursor={Input.Value.NextCursor} OnNext={Input.OnNext} />
    </>;
}

function EventWindow(Input: Readonly<{
    Value: EventPage; SeveritySupport: string;
}>): React.ReactNode {
    return <>
        <div className="data-grid">
            <DataCell Label="最早可读序号" Value={Input.Value.EarliestCursor} />
            <DataCell Label="下一页起点" Value={Input.Value.NextCursor} />
            <DataCell Label="跨页级别筛选" Value={Input.SeveritySupport} />
            <DataCell Label="普通事件丢弃" Value={Input.Value.Dropped} />
            <DataCell Label="终态事件丢弃" Value={Input.Value.TerminalDropped} />
            <DataCell Label="已覆盖事件" Value={Input.Value.Overwritten} />
        </div>
        <div className="notice notice-info" role="status">
            <p>事件来自当前管理进程保留的窗口。类型、级别和结束状态条件只筛选当前页；跨页级别筛选当前不可用。</p>
        </div>
    </>;
}

function LostRanges(Input: Readonly<{ Ranges: EventPage['LostRanges'] }>): React.ReactNode {
    if (Input.Ranges.length === 0) return <p>服务确认存在缺口，但没有提供序号区间。</p>;
    return <ul>{Input.Ranges.map(Range => <li key={`${Range.First}-${Range.Last}`}>
        {Range.First}–{Range.Last}</li>)}</ul>;
}

function EventRows(Input: Readonly<{
    Events: readonly Event[]; HasMore: boolean; NextCursor: string; OnNext: (Cursor: string) => void;
}>): React.ReactNode {
    return <>
        {Input.Events.length === 0 && <EmptyState Title="当前页没有匹配事件"
            Detail="筛选只作用于当前页，仍可继续浏览后续页面。" />}
        {Input.Events.length > 0 && <div className="data-table-wrap" role="region" tabIndex={0}
            aria-label="事件表格，可横向滚动"><table className="data-table">
            <thead><tr><th scope="col">时间 / 序号</th><th scope="col">类型 / 级别</th>
                <th scope="col">作用范围</th><th scope="col">操作编号 / 父任务</th>
                <th scope="col">事件标志</th><th scope="col">详情</th></tr></thead>
            <tbody>{Input.Events.map(EventValue => <EventRow key={EventValue.Sequence} Value={EventValue} />)}</tbody>
        </table></div>}
        <div className="pagination"><span>当前序号 {Input.NextCursor}
            {Input.HasMore && ' · 存在后续页'}</span>
            <button className="button button-secondary" disabled={!Input.HasMore}
                onClick={() => Input.OnNext(Input.NextCursor)}>下一页</button></div>
    </>;
}

function EventRow(Input: Readonly<{ Value: Event }>): React.ReactNode {
    const Value = Input.Value;
    let TerminalLabel = '普通';
    let Tone: 'good' | 'warn' | 'bad' | 'neutral' = 'neutral';
    if (Value.Terminal) {
        TerminalLabel = '终态';
        Tone = 'neutral';
    }
    if (Value.Severity === 'warning') Tone = 'warn';
    if (Value.Severity === 'error') Tone = 'bad';
    let Detail = '未提供详情';
    if (Value.Detail !== null) Detail = Value.Detail;
    return <tr><td>{FormatTime(Value.Timestamp)}<br /><span className="mono">#{Value.Sequence}</span></td>
        <td><span className="badge">{EventKindLabel(Value.Kind)}</span><br />
            <StatusBadge Label={EventSeverityLabel(Value.Severity)} Tone={Tone} /></td>
        <td><strong>{EventScopeLabel(Value.Scope)}</strong><br /><span className="mono">进程 {Value.Process}</span><br />
            Worker {Value.Worker} · 账户 {Value.Account}<br />会话 {Value.Session} · Stream {Value.Stream} · Task {Value.Task}</td>
        <td>操作 <span className="mono">{Value.Operation}</span><br />
            父任务 <span className="mono">{Value.ParentTask}</span></td>
        <td><span className="badge">{TerminalLabel}</span>
            {Value.Truncated && <span className="badge badge-warn">已截断</span>}</td>
        <td className="event-detail">{Detail}</td></tr>;
}

function EventKindLabel(Value: EventKind): string {
    if (Value === 'data') return '数据';
    if (Value === 'started') return '已启动';
    if (Value === 'failed') return '失败';
    if (Value === 'session_closed') return '会话关闭';
    if (Value === 'stream_closed') return '流关闭';
    if (Value === 'task_completed') return '任务完成';
    if (Value === 'task_canceled') return '任务取消';
    if (Value === 'worker_drained') return 'Worker 已排空';
    if (Value === 'generation_reloaded') return '配置已重载';
    if (Value === 'operation_accepted') return '操作已受理';
    if (Value === 'operation_completed') return '操作完成';
    return '操作失败';
}

function EventSeverityLabel(Value: EventSeverity): string {
    if (Value === 'debug') return '调试';
    if (Value === 'info') return '信息';
    if (Value === 'warning') return '警告';
    if (Value === 'error') return '错误';
    return '未知级别';
}

function EventScopeLabel(Value: EventScope): string {
    if (Value === 'process') return '进程';
    if (Value === 'worker') return 'Worker';
    if (Value === 'account') return '账户';
    if (Value === 'session') return '会话';
    if (Value === 'stream') return 'Stream';
    return 'Task';
}
