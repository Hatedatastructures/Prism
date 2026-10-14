import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { DecodeCommandResponse, VerifyCommandProcess } from '../../Api/OperationsApi';
import type { CommandEnvelope, CommandStatus } from '../../Api/OperationsApi';
import { Fail } from '../../Api/Result';
import type { Result } from '../../Api/Result';
import { FailureNotice, LoadingState, SectionHeading, StatusBadge } from '../../Components/ResultView';
import { Remove, useOperationNotice, useOperationTickets } from './OperationStore';
import type { OperationTicket } from './OperationStore';
import { HasCapability, useAdminServices } from '../UseOperations';

export default function OperationsPage(): ReactNode {
    const Services = useAdminServices();
    const Tickets = useOperationTickets();
    const Notice = useOperationNotice();
    const CanRead = HasCapability(Services, 'operations.status');
    return <>
        <SectionHeading Eyebrow="OPERATIONS" Title="操作中心"
            Description="这里只跟踪本标签页收到操作编号的命令。刷新后会尝试恢复当前管理进程的操作进度；检测到进程更换后，旧编号会清除。" />
        {!CanRead && <div className="notice notice-unavailable" role="status">
            此服务暂不提供操作进度查询。</div>}
        {Notice.length > 0 && <div className="notice notice-info" role="status">{Notice}</div>}
        {CanRead && Tickets.length === 0 && Notice.length === 0 && <section className="panel"><div className="panel-body">
            <div className="empty-state"><span className="empty-mark" aria-hidden="true">—</span>
                <strong>当前没有已保存的操作编号</strong>
                <p>提交命令后，只有服务端确认接收并分配操作编号时才会加入这里。</p>
            </div></div></section>}
        {CanRead && Tickets.map(Ticket => <OperationCard key={`${Ticket.Process}-${Ticket.Incarnation}-${Ticket.Operation}`}
            Ticket={Ticket} />)}
    </>;
}

function OperationCard(Input: Readonly<{ Ticket: OperationTicket }>): ReactNode {
    const Services = useAdminServices();
    const Ticket = Input.Ticket;
    const [LastConfirmed, SetLastConfirmed] = useState<CommandEnvelope | null>(null);
    const [LastConfirmedAt, SetLastConfirmedAt] = useState<string | null>(null);
    const SameProcess = Ticket.Process === Services.Bootstrap.Process &&
        Ticket.Incarnation === Services.Bootstrap.Incarnation;
    const Path = `/Operations/Operations/${Ticket.Operation}`;
    const Query = useQuery({
        queryKey: ['operation', Ticket.Process, Ticket.Incarnation, Ticket.Operation],
        queryFn: async ({ signal }) => {
            const ResultValue = await Services.Client.Query({ Path, Signal: signal, Decode: DecodeCommandResponse });
            return ValidateIdentity(ResultValue, Ticket);
        },
        enabled: SameProcess,
        retry: false,
        refetchInterval: State => PollInterval(State.state.data),
        refetchIntervalInBackground: false,
        refetchOnWindowFocus: true,
    });
    const OperationUnavailable = Query.data?.Ok === true && Query.data.Value.Status === 'invalid' &&
        Query.data.Value.Operation === '0';
    useEffect(() => {
        const Response = Query.data;
        if (Response === undefined || !Response.Ok ||
            (Response.Value.Status === 'invalid' && Response.Value.Operation === '0')) return;
        SetLastConfirmed(Response.Value);
        SetLastConfirmedAt(new Date().toLocaleString('zh-CN'));
    }, [Query.data]);
    let Tone: 'good' | 'warn' | 'bad' | 'neutral' = 'warn';
    let Status = '等待首次状态确认';
    const Command = LastConfirmed || (OperationUnavailable ? null : ReadCommand(Query.data));
    if (OperationUnavailable && Command === null) Status = '当前无法查询';
    if (Command !== null) {
        Status = StatusLabel(Command.Status);
        Tone = StatusTone(Command.Status);
    }
    function Forget(): void {
        Remove(Ticket.Operation);
    }
    return <section className="panel operation-panel">
        <div className="panel-heading"><div><h2>{Ticket.Label}</h2>
            <p>{Ticket.Target}</p></div><StatusBadge Label={Status} Tone={Tone} /></div>
        <div className="panel-body">
            <dl className="operation-meta">
                <div><dt>进程编号</dt><dd>{Ticket.Process}</dd></div>
                <div><dt>操作编号</dt><dd>{Ticket.Operation}</dd></div>
                <div><dt>本页记录时间</dt><dd>{Ticket.RecordedAt}</dd></div>
            </dl>
            {!SameProcess && <div className="notice notice-warn" role="status">
                当前管理进程与提交操作时不同，已停止查询旧操作。</div>}
            {SameProcess && Query.isPending && <LoadingState Label="操作终态" />}
            {SameProcess && Query.isError && <div className="notice notice-unavailable" role="status">
                <div><strong>{Command === null ? '尚未确认操作状态' : '本次查询失败'}</strong>
                    <p>{Command === null ? '服务端尚未返回可确认的操作状态。' : '下方保留最近一次成功查询的状态；当前进度仍未知。'}</p></div>
                <button className="button button-secondary" onClick={() => void Query.refetch()}>
                    重新查询
                </button>
            </div>}
            {SameProcess && Query.data && !Query.data.Ok && <FailureNotice Failure={Query.data.Failure}
                Heading={Command === null ? '尚未确认操作状态' : '本次查询失败；保留最近一次确认状态'}
                OnRetry={() => void Query.refetch()} />}
            {SameProcess && OperationUnavailable && <div className="notice notice-warn" role="status">
                <strong>服务端当前未保留此操作的状态</strong>
                <p>无法据此判断操作是否完成；下方仅保留此前成功查询的状态。</p>
            </div>}
            {Command && <CommandDetails Value={Command} />}
            {Command && LastConfirmedAt !== null && <p className="muted">最近成功查询：{LastConfirmedAt}</p>}
            {SameProcess && Command === null && !OperationUnavailable && Query.data?.Ok && <div className="notice notice-info" role="status">
                等待服务端返回当前 Operation 状态。</div>}
            <button className="button button-secondary" onClick={Forget}>从此列表移除</button>
        </div>
    </section>;
}

function ValidateIdentity(
    ResultValue: Result<CommandEnvelope>, Ticket: OperationTicket,
): Result<CommandEnvelope> {
    const ProcessResult = VerifyCommandProcess(ResultValue, Ticket.Process, false);
    if (!ProcessResult.Ok) return ProcessResult;
    const Value = ProcessResult.Value;
    if (Value.Status === 'invalid' && Value.Operation === '0') return ProcessResult;
    if (Value.Operation !== Ticket.Operation) {
        return Fail({ Kind: 'contract', Message: '状态响应的 Operation ID 与请求不一致',
            HttpStatus: null, MayHaveExecuted: false });
    }
    return ProcessResult;
}

function PollInterval(Data: Result<CommandEnvelope> | undefined): number | false {
    if (Data === undefined) return 1500;
    if (!Data.Ok) return 4000;
    if (Data.Value.Status === 'accepted') return 1500;
    return false;
}

function ReadCommand(Data: Result<CommandEnvelope> | undefined): CommandEnvelope | null {
    if (Data === undefined || !Data.Ok) return null;
    return Data.Value;
}

function StatusLabel(Status: CommandStatus): string {
    if (Status === 'accepted') return '处理中';
    if (Status === 'completed') return '已完成';
    if (Status === 'rejected') return '已拒绝';
    if (Status === 'unavailable') return '不可用';
    if (Status === 'failed') return '失败';
    if (Status === 'timed_out') return '已超时';
    if (Status === 'blocked') return '已阻止';
    if (Status === 'conflict') return '配置版本已变化';
    if (Status === 'restart_required') return '需要重启';
    return '无法查询此操作';
}

function StatusTone(Status: CommandStatus): 'good' | 'warn' | 'bad' | 'neutral' {
    if (Status === 'completed') return 'good';
    if (Status === 'accepted' || Status === 'unavailable' || Status === 'blocked') return 'warn';
    if (Status === 'failed' || Status === 'timed_out' || Status === 'rejected') return 'bad';
    return 'neutral';
}

function CommandDetails(Input: Readonly<{ Value: CommandEnvelope }>): ReactNode {
    const Value = Input.Value;
    const Scope: readonly (readonly [string, string | null])[] = [
        ['Process', Value.Process],
        ['Generation', Value.Generation], ['Worker', Value.Worker], ['Account', Value.Account],
        ['Session', Value.Session], ['Stream', Value.Stream], ['Task', Value.Task],
        ['Parent Task', Value.ParentTask],
    ];
    const ActiveScope = Scope.filter(([, Identifier]) => Identifier !== '0' && Identifier !== null);
    let Failure = '无错误';
    if (Value.Failure !== null) {
        Failure = Value.Failure.Code;
        if (Value.Failure.NativeCategory !== null) Failure += ` · ${Value.Failure.NativeCategory}`;
        if (Value.Failure.NativeValue !== null) Failure += ` · ${Value.Failure.NativeValue}`;
    }
    return <div className="status-detail">
        <div>服务状态：<strong>{StatusLabel(Value.Status)}</strong></div>
        <div>服务说明：{Value.Message || '未提供'}</div>
        <div>错误详情：{Failure}</div>
        {ActiveScope.length > 0 && <div className="data-grid">
            {ActiveScope.map(([Label, Identifier]) => <div className="data-cell" key={Label}>
                <span>{ScopeLabel(Label)}</span><strong className="mono">{Identifier}</strong></div>)}
        </div>}
        {ActiveScope.length === 0 && <div>服务端未提供具体资源编号。</div>}
        {Value.RestartRequiredFields.length > 0 && <div><strong>需要重启的字段</strong>
            <ul>{Value.RestartRequiredFields.map(Field => <li key={Field}>{Field}</li>)}</ul></div>}
        {Value.ConfigurationIssues.length > 0 && <div><strong>配置问题</strong>
            <ul>{Value.ConfigurationIssues.map((Issue, Index) => <li key={`${Issue.Path}-${Index}`}>
                {Issue.Path || 'Configuration'} · {Issue.Code} · {Issue.Message}</li>)}</ul></div>}
    </div>;
}

function ScopeLabel(Value: string): string {
    if (Value === 'Process') return '进程';
    if (Value === 'Generation') return '配置版本';
    if (Value === 'Worker') return 'Worker';
    if (Value === 'Account') return '账户';
    if (Value === 'Session') return '会话';
    if (Value === 'Stream') return 'Stream';
    if (Value === 'Parent Task') return '父任务';
    return '任务';
}
