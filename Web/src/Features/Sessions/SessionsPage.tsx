import { useEffect, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { DecodeDecimal } from '../../Api/Decimal';
import { DecodeSessionsQuery, VerifyProcessScope } from '../../Api/OperationsApi';
import type { Page, Session } from '../../Api/OperationsApi';
import { SessionResources } from './SessionResources';
import { ConfirmAction } from '../../Components/ConfirmAction';
import { EmptyState, InlineCommandResult, QueryView, SectionHeading, StatusBadge, TrafficSummary } from '../../Components/ResultView';
import { HasCapability, useAdminServices, useCommandRunner } from '../UseOperations';

const PageSize = 100;

export default function SessionsPage(): ReactNode {
    const Services = useAdminServices();
    const Runner = useCommandRunner();
    const [Cursor, SetCursor] = useState('0');
    const [History, SetHistory] = useState<readonly string[]>([]);
    const [FilterInput, SetFilterInput] = useState('');
    const [Filter, SetFilter] = useState('');
    const [Selected, SetSelected] = useState<Session | null>(null);
    const FilterValid = IsValidId(Filter);
    const FilterInputValid = IsValidId(FilterInput.trim());
    const Params = new URLSearchParams({ cursor: Cursor, limit: String(PageSize) });
    if (Filter.length > 0) Params.set('id', Filter);
    const Path = `/Operations/Sessions?${Params.toString()}`;
    const Query = useQuery({
        queryKey: ['sessions', Services.Bootstrap.Process, Services.Bootstrap.Incarnation, Cursor, Filter],
        queryFn: ({ signal }) => Services.Client.Query({ Path, Signal: signal,
            Decode: Response => VerifyProcessScope(DecodeSessionsQuery(Response), Services.Bootstrap.Process) }),
        refetchInterval: 5000,
        refetchIntervalInBackground: false,
        retry: false,
        enabled: FilterValid,
    });
    useEffect(() => {
        if (Selected === null) return;
        const ResultValue = Query.data;
        if (ResultValue?.Ok !== true || ResultValue.Value.Status !== 'ok' ||
            ResultValue.Value.Value === null) return;
        const Updated = ResultValue.Value.Value.Items.find(Value => Value.Id === Selected.Id);
        if (Updated === undefined) {
            SetSelected(null);
            return;
        }
        SetSelected(Current => Current?.Id === Updated.Id ? Updated : Current);
    }, [Query.data, Selected]);
    function ApplyFilter(Event: FormEvent<HTMLFormElement>): void {
        Event.preventDefault();
        const Value = FilterInput.trim();
        if (!FilterInputValid) return;
        SetHistory([]);
        SetCursor('0');
        SetFilter(Value);
        SetSelected(null);
    }
    function Next(Value: string): void {
        SetHistory([...History, Cursor]);
        SetCursor(Value);
        SetSelected(null);
    }
    function Previous(): void {
        const Value = History[History.length - 1];
        if (Value === undefined) return;
        SetHistory(History.slice(0, -1));
        SetCursor(Value);
        SetSelected(null);
    }
    const CanCancel = HasCapability(Services, 'sessions.cancel');
    return <>
        <SectionHeading Eyebrow="SESSIONS" Title="Session、Stream 与 Task"
            Description="选择 Session 查看其 Stream 和 Task；重置与取消前会再次确认具体资源。" />
        <form className="toolbar" onSubmit={ApplyFilter} aria-label="Session 查询条件">
            <label className="field">Session ID
                <input inputMode="numeric" value={FilterInput} onChange={Event => SetFilterInput(Event.target.value)}
                    placeholder="留空显示分页列表"
                    aria-invalid={FilterInput.trim().length > 0 && !FilterInputValid} /></label>
            <button className="button button-secondary" type="submit">应用筛选</button>
        </form>
        {!FilterInputValid && <div className="notice notice-error" role="alert">Session ID 必须为大于 0 的 uint64 十进制字符串。</div>}
        {FilterValid && <section className="panel">
            <div className="panel-heading"><div><h2>Session 快照</h2>
                <p>每 5 秒刷新；选择一行后可在完整身份范围中查询。</p></div></div>
            <div className="panel-body">
                <QueryView Query={Query} Label="Session 列表" Children={Value => <SessionTable
                    Value={Value} Selected={Selected?.Id || null} CanCancel={CanCancel}
                    CurrentProcess={Services.Bootstrap.Process} Runner={Runner}
                    OnSelect={SetSelected} OnNext={Next} /> } />
                {History.length > 0 && <button className="button button-secondary" onClick={Previous}>上一页</button>}
            </div>
        </section>}
        {!FilterValid && <div className="notice notice-error" role="alert">Session ID 无效。</div>}
        {Selected && <SessionResources key={`${Selected.Process}-${Selected.Id}-${Selected.Generation}-${Selected.Worker}`}
            SessionValue={Selected} Runner={Runner} />}
        <InlineCommandResult Result={Runner.Result} Process={Services.Bootstrap.Process} />
    </>;
}

function IsValidId(Value: string): boolean {
    if (Value.length === 0) return true;
    const Decoded = DecodeDecimal(Value);
    if (!Decoded.Ok) return false;
    return Decoded.Value !== '0';
}

function SessionTable(Input: Readonly<{
    Value: Page<Session>; Selected: string | null; CanCancel: boolean;
    CurrentProcess: string;
    Runner: ReturnType<typeof useCommandRunner>; OnSelect: (Value: Session) => void;
    OnNext: (Cursor: string) => void;
}>): ReactNode {
    if (Input.Value.Items.length === 0) return <EmptyState Title="没有匹配的 Session"
        Detail="当前查询范围内没有活动或已保留 Session 快照。" />;
    return <>
        <div className="data-table-wrap" role="region" tabIndex={0} aria-label="Session 表格，可横向滚动">
            <table className="data-table">
            <thead><tr><th scope="col">Session</th><th scope="col">Worker / Account</th>
                <th scope="col">协议与目标</th><th scope="col">状态</th>
                <th scope="col">流量</th><th scope="col">操作</th></tr></thead>
            <tbody>{Input.Value.Items.map(SessionValue => <SessionRow key={SessionValue.Id}
                SessionValue={SessionValue} Selected={Input.Selected === SessionValue.Id}
                CanCancel={Input.CanCancel} CurrentProcess={Input.CurrentProcess}
                Runner={Input.Runner} OnSelect={Input.OnSelect} />)}</tbody>
        </table></div>
        <div className="pagination"><span>本页 {Input.Value.Items.length} 项
            {Input.Value.HasMore && ' · 存在后续页面'}</span>
            <button className="button button-secondary" disabled={!Input.Value.HasMore}
                onClick={() => Input.OnNext(Input.Value.NextCursor)}>下一页</button></div>
    </>;
}

function SessionRow(Input: Readonly<{
    SessionValue: Session; Selected: boolean; CanCancel: boolean;
    CurrentProcess: string;
    Runner: ReturnType<typeof useCommandRunner>; OnSelect: (Value: Session) => void;
}>): ReactNode {
    const Value = Input.SessionValue;
    let Status = '已结束';
    let Tone: 'good' | 'warn' | 'neutral' = 'neutral';
    if (Value.Active && Value.Draining) { Status = '排空中'; Tone = 'warn'; }
    else if (Value.Active) { Status = '活动'; Tone = 'good'; }
    async function Cancel(): Promise<unknown> {
        return Input.Runner.Submit({ Path: `/Operations/Processes/${Value.Process}/Sessions/${Value.Id}/Cancel`,
            Body: null, Label: '会话取消', Target: `进程 ${Value.Process} / 会话 ${Value.Id}` });
    }
    const IsCurrentProcess = Value.Process === Input.CurrentProcess;
    const Description = `只请求取消进程 ${Value.Process} 中的会话 ${Value.Id}。`;
    return <tr className={Input.Selected ? 'session-row-selected' : undefined}>
        <td><button className="button-link mono" onClick={() => Input.OnSelect(Value)}
            aria-label={`选择 Session ${Value.Id}`} aria-pressed={Input.Selected}>{Value.Id}</button></td>
        <td>Worker <span className="mono">{Value.Worker}</span><br />Account <span className="mono">{Value.Account}</span></td>
        <td>{Value.Protocol}<br /><span className="muted">{Value.Target}</span></td>
        <td><StatusBadge Label={Status} Tone={Tone} /></td>
        <td><TrafficSummary Value={Value.Traffic} /></td>
        <td><div className="button-row">
            <button className="button button-secondary" onClick={() => Input.OnSelect(Value)}>查看子资源</button>
            {Input.CanCancel && Value.Active && IsCurrentProcess && <ConfirmAction Label="取消 Session"
                Title="取消此 Session？" Description={Description} ConfirmLabel="提交取消"
                Tone="danger" Busy={Input.Runner.IsPending} OnConfirm={Cancel} />}
            {!Input.CanCancel && <small className="muted">当前服务不允许单独取消会话</small>}
            {Input.CanCancel && !Value.Active && <small className="muted">Session 非活动状态</small>}
            {Input.CanCancel && Value.Active && !IsCurrentProcess && <small className="muted">非当前进程资源</small>}
        </div></td>
    </tr>;
}

