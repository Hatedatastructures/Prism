import { useState } from 'react';
import type { ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { FormatBytes, FormatTime } from '../../Api/Decimal';
import { ContractFailure } from '../../Api/Decode';
import type { ResponseDecoder } from '../../Api/ApiClient';
import { DecodeStreamsQuery, DecodeTasksQuery } from '../../Api/OperationsApi';
import type { Page, QueryEnvelope, Session, Stream, Task } from '../../Api/OperationsApi';
import { ConfirmAction } from '../../Components/ConfirmAction';
import { EmptyState, QueryView, StatusBadge } from '../../Components/ResultView';
import { HasCapability, useAdminServices, useCommandRunner } from '../UseOperations';

type CommandRunner = ReturnType<typeof useCommandRunner>;
const PageSize = 100;

export function SessionResources(Input: Readonly<{
    SessionValue: Session; Runner: CommandRunner;
}>): ReactNode {
    const Value = Input.SessionValue;
    return <section className="panel">
        <div className="panel-heading"><div><h2>所选 Session 的子资源</h2>
            <p>Session {Value.Id} · Worker {Value.Worker} · 配置版本 {Value.Generation}</p>
        </div></div>
        <div className="panel-body"><div className="data-grid">
            <ScopeValue Label="Process" Value={Value.Process} />
            <ScopeValue Label="Account" Value={Value.Account} />
            <ScopeValue Label="开始时间" Value={FormatTime(Value.StartedAt)} />
            <ScopeValue Label="活动任务" Value={Value.ActiveTasks ?? '未提供'} />
        </div>
            <StreamCollection SessionValue={Value} Runner={Input.Runner} />
            <TaskCollection SessionValue={Value} Runner={Input.Runner} />
        </div>
    </section>;
}

function StreamCollection(Input: Readonly<{
    SessionValue: Session; Runner: CommandRunner;
}>): ReactNode {
    const Services = useAdminServices();
    const Value = Input.SessionValue;
    const [Cursor, SetCursor] = useState('0');
    const [History, SetHistory] = useState<readonly string[]>([]);
    const Params = new URLSearchParams({ generation: Value.Generation, worker: Value.Worker,
        cursor: Cursor, limit: String(PageSize) });
    const Path = `/Operations/Processes/${Value.Process}/Sessions/${Value.Id}/Streams?${Params.toString()}`;
    const CanRead = HasCapability(Services, 'streams.read');
    const Query = useQuery({
        queryKey: ['streams', Value.Process, Value.Generation, Value.Worker, Value.Id, Cursor],
        queryFn: ({ signal }) => Services.Client.Query({ Path, Signal: signal,
            Decode: ScopedStreamsDecoder(Value) }),
        enabled: CanRead,
        retry: false,
        refetchInterval: 5000,
        refetchIntervalInBackground: false,
    });
    function Next(NextCursor: string): void {
        SetHistory([...History, Cursor]);
        SetCursor(NextCursor);
    }
    function Previous(): void {
        const PreviousCursor = History[History.length - 1];
        if (PreviousCursor === undefined) return;
        SetHistory(History.slice(0, -1));
        SetCursor(PreviousCursor);
    }
    if (!CanRead) return <EmptyState Title="Stream 查询不可用" Detail="当前服务未提供 Stream 列表。" />;
    return <div className="scope-area"><h3>Streams</h3>
        <QueryView Query={Query} Label="Stream 列表" Children={PageValue => <StreamTable
            Value={PageValue} Runner={Input.Runner} CanReset={HasCapability(Services, 'streams.reset')}
            CurrentProcess={Services.Bootstrap.Process} OnNext={Next} />} />
        {History.length > 0 && <button className="button button-secondary" onClick={Previous}>上一页 Streams</button>}
    </div>;
}

function TaskCollection(Input: Readonly<{
    SessionValue: Session; Runner: CommandRunner;
}>): ReactNode {
    const Services = useAdminServices();
    const Value = Input.SessionValue;
    const [Cursor, SetCursor] = useState('0');
    const [History, SetHistory] = useState<readonly string[]>([]);
    const Params = new URLSearchParams({ generation: Value.Generation,
        cursor: Cursor, limit: String(PageSize) });
    const Path = `/Operations/Processes/${Value.Process}/Workers/${Value.Worker}/Sessions/${Value.Id}/Tasks?${Params.toString()}`;
    const CanRead = HasCapability(Services, 'tasks.read');
    const Query = useQuery({
        queryKey: ['tasks', Value.Process, Value.Generation, Value.Worker, Value.Id, Cursor],
        queryFn: ({ signal }) => Services.Client.Query({ Path, Signal: signal,
            Decode: ScopedTasksDecoder(Value) }),
        enabled: CanRead,
        retry: false,
        refetchInterval: 5000,
        refetchIntervalInBackground: false,
    });
    function Next(NextCursor: string): void {
        SetHistory([...History, Cursor]);
        SetCursor(NextCursor);
    }
    function Previous(): void {
        const PreviousCursor = History[History.length - 1];
        if (PreviousCursor === undefined) return;
        SetHistory(History.slice(0, -1));
        SetCursor(PreviousCursor);
    }
    if (!CanRead) return <EmptyState Title="Task 查询不可用" Detail="当前服务未提供 Task 列表。" />;
    return <div className="scope-area"><h3>Tasks</h3>
        <QueryView Query={Query} Label="Task 列表" Children={PageValue => <TaskTable
            Value={PageValue} Runner={Input.Runner} CanCancel={HasCapability(Services, 'tasks.cancel')}
            CurrentProcess={Services.Bootstrap.Process} OnNext={Next} />} />
        {History.length > 0 && <button className="button button-secondary" onClick={Previous}>上一页 Tasks</button>}
    </div>;
}

function ScopedStreamsDecoder(Scope: Session): ResponseDecoder<QueryEnvelope<Page<Stream>>> {
    return Response => {
        const Decoded = DecodeStreamsQuery(Response);
        if (!Decoded.Ok || Decoded.Value.Value === null) return Decoded;
        for (const Value of Decoded.Value.Value.Items) {
            if (Value.Process !== Scope.Process || Value.Session !== Scope.Id ||
                Value.Worker !== Scope.Worker || Value.Generation !== Scope.Generation ||
                Value.Account !== Scope.Account) return ContractFailure();
        }
        return Decoded;
    };
}

function ScopedTasksDecoder(Scope: Session): ResponseDecoder<QueryEnvelope<Page<Task>>> {
    return Response => {
        const Decoded = DecodeTasksQuery(Response);
        if (!Decoded.Ok || Decoded.Value.Value === null) return Decoded;
        for (const Value of Decoded.Value.Value.Items) {
            if (Value.Process !== Scope.Process || Value.Session !== Scope.Id ||
                Value.Worker !== Scope.Worker || Value.Generation !== Scope.Generation) return ContractFailure();
        }
        return Decoded;
    };
}

function StreamTable(Input: Readonly<{
    Value: Page<Stream>; Runner: CommandRunner; CanReset: boolean; CurrentProcess: string;
    OnNext: (Cursor: string) => void;
}>): ReactNode {
    return <>
        {Input.Value.Items.length === 0 && <EmptyState Title="没有保留的 Stream"
            Detail="此 Session 的当前查询页没有 Stream。" />}
        {Input.Value.Items.length > 0 && <div className="data-table-wrap" role="region" tabIndex={0}
            aria-label="Stream 表格，可横向滚动"><table className="data-table">
            <thead><tr><th scope="col">Stream / Task</th><th scope="col">协议</th>
                <th scope="col">状态</th><th scope="col">流量</th><th scope="col">操作</th></tr></thead>
            <tbody>{Input.Value.Items.map(Value => <StreamRow key={Value.Id} Value={Value}
                Runner={Input.Runner} CanReset={Input.CanReset} CurrentProcess={Input.CurrentProcess} />)}</tbody>
        </table></div>}
        <Pagination Value={Input.Value} Label="Streams" OnNext={Input.OnNext} />
    </>;
}

function StreamRow(Input: Readonly<{
    Value: Stream; Runner: CommandRunner; CanReset: boolean; CurrentProcess: string;
}>): ReactNode {
    const Value = Input.Value;
    const HasIdentity = Value.Task !== '0' && Value.ParentTask !== '0';
    const CanReset = Input.CanReset && Value.State === 'active' && HasIdentity &&
        Value.Process === Input.CurrentProcess;
    const Params = new URLSearchParams({ generation: Value.Generation, worker: Value.Worker,
        parent_task: Value.ParentTask, task: Value.Task });
    async function Reset(): Promise<unknown> {
        return Input.Runner.Submit({
            Path: `/Operations/Processes/${Value.Process}/Sessions/${Value.Session}/Streams/${Value.Id}/Reset?${Params.toString()}`,
            Body: null, Label: 'Stream 重置',
            Target: `进程 ${Value.Process} / 配置版本 ${Value.Generation} / Worker ${Value.Worker} / 会话 ${Value.Session} / Stream ${Value.Id} / 父任务 ${Value.ParentTask} / 任务 ${Value.Task}`,
        });
    }
    let Traffic = '未采集';
    if (Value.Traffic !== null) Traffic = `↑ ${FormatBytes(Value.Traffic.UpBytes)} · ↓ ${FormatBytes(Value.Traffic.DownBytes)}`;
    return <tr><td><span className="mono">{Value.Id}</span><br /><small>Task {Value.Task}</small></td>
        <td>{Value.Protocol}</td><td><StatusBadge Label={Value.State} Tone="neutral" /></td><td>{Traffic}</td>
        <td>{CanReset && <ConfirmAction Label="重置 Stream" Title="重置此 Stream？"
            Description={`只重置进程 ${Value.Process} / 配置版本 ${Value.Generation} / Worker ${Value.Worker} / 会话 ${Value.Session} 下的 Stream ${Value.Id}（父任务 ${Value.ParentTask}，任务 ${Value.Task}）；其他 Stream 继续运行。`}
            ConfirmLabel="提交重置" Tone="danger" Busy={Input.Runner.IsPending} OnConfirm={Reset} />}
            {!HasIdentity && <small className="muted">未提供控制任务身份</small>}
            {!Input.CanReset && <small className="muted">当前服务未提供重置操作</small>}</td></tr>;
}

function TaskTable(Input: Readonly<{
    Value: Page<Task>; Runner: CommandRunner; CanCancel: boolean; CurrentProcess: string;
    OnNext: (Cursor: string) => void;
}>): ReactNode {
    return <>
        {Input.Value.Items.length === 0 && <EmptyState Title="没有保留的 Task"
            Detail="此 Session 的当前查询页没有任务。" />}
        {Input.Value.Items.length > 0 && <div className="data-table-wrap" role="region" tabIndex={0}
            aria-label="Task 表格，可横向滚动"><table className="data-table">
            <thead><tr><th scope="col">Task / Stream</th><th scope="col">状态</th><th scope="col">时间</th>
                <th scope="col">错误与 Drain</th><th scope="col">操作</th></tr></thead>
            <tbody>{Input.Value.Items.map(Value => <TaskRow key={Value.Id} Value={Value}
                Runner={Input.Runner} CanCancel={Input.CanCancel} CurrentProcess={Input.CurrentProcess} />)}</tbody>
        </table></div>}
        <Pagination Value={Input.Value} Label="Tasks" OnNext={Input.OnNext} />
    </>;
}

function TaskRow(Input: Readonly<{
    Value: Task; Runner: CommandRunner; CanCancel: boolean; CurrentProcess: string;
}>): ReactNode {
    const Value = Input.Value;
    const IsActive = Value.Status === 'pending' || Value.Status === 'running';
    const CanCancel = Input.CanCancel && Value.Cancellable && IsActive &&
        !Value.CancelRequested && Value.Process === Input.CurrentProcess;
    const Params = new URLSearchParams({ generation: Value.Generation,
        stream: Value.Stream, parent_task: Value.ParentTask });
    async function Cancel(): Promise<unknown> {
        return Input.Runner.Submit({
            Path: `/Operations/Processes/${Value.Process}/Workers/${Value.Worker}/Sessions/${Value.Session}/Tasks/${Value.Id}/Cancel?${Params.toString()}`,
            Body: null, Label: '任务取消',
            Target: `进程 ${Value.Process} / 配置版本 ${Value.Generation} / Worker ${Value.Worker} / 会话 ${Value.Session} / Stream ${Value.Stream} / 父任务 ${Value.ParentTask} / 任务 ${Value.Id}`,
        });
    }
    let Tone: 'good' | 'warn' | 'bad' | 'neutral' = 'neutral';
    if (IsActive) Tone = 'warn';
    if (Value.Status === 'succeeded') Tone = 'good';
    if (Value.Status === 'failed' || Value.Status === 'quarantined') Tone = 'bad';
    let Failure = '无终态错误';
    if (Value.Failure !== null) Failure = `${Value.Failure.Code} · ${Value.Failure.NativeCategory ?? ''} ${Value.Failure.NativeValue ?? ''}`;
    let DrainFailure = '';
    if (Value.DrainFailure !== null) DrainFailure = `Drain ${Value.DrainFailure.Code} · ${Value.DrainFailure.NativeCategory ?? ''} ${Value.DrainFailure.NativeValue ?? ''}`;
    return <tr><td><span className="mono">{Value.Id}</span><br /><small>Stream {Value.Stream} · Parent {Value.ParentTask}</small></td>
        <td><StatusBadge Label={Value.Status} Tone={Tone} /></td>
        <td>{FormatTime(Value.StartedAt)}<br />{FormatTime(Value.CompletedAt)}</td>
        <td>{Failure}<br />{DrainFailure}{Value.DrainBlocked && <span className="badge badge-warn">Drain 尚未完成</span>}</td>
        <td>{CanCancel && <ConfirmAction Label="取消 Task" Title="取消此任务？"
            Description={`只取消进程 ${Value.Process} / 配置版本 ${Value.Generation} / Worker ${Value.Worker} / 会话 ${Value.Session} 中 Stream ${Value.Stream} 下的任务 ${Value.Id}（父任务 ${Value.ParentTask}）。`}
            ConfirmLabel="提交取消" Tone="danger" Busy={Input.Runner.IsPending} OnConfirm={Cancel} />}
            {!Value.Cancellable && <small className="muted">此任务不支持单独取消</small>}
            {Value.CancelRequested && <small className="muted">已请求取消</small>}</td></tr>;
}

function Pagination(Input: Readonly<{
    Value: Readonly<{ Items: readonly unknown[]; HasMore: boolean; NextCursor: string }>;
    Label: string; OnNext: (Cursor: string) => void;
}>): ReactNode {
    return <div className="pagination"><span>本页 {Input.Value.Items.length} 项</span>
        <button className="button button-secondary" disabled={!Input.Value.HasMore}
            onClick={() => Input.OnNext(Input.Value.NextCursor)}>下一页 {Input.Label}</button></div>;
}

function ScopeValue(Input: Readonly<{ Label: string; Value: string }>): ReactNode {
    return <div className="data-cell"><span>{Input.Label}</span><strong className="mono">{Input.Value}</strong></div>;
}
