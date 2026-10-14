import type { ReactNode } from 'react';
import type { UseQueryResult } from '@tanstack/react-query';
import { FormatBytes } from '../Api/Decimal';
import type { ApiFailure, Result } from '../Api/Result';
import type { CommandEnvelope, CommandStatus, QueryEnvelope, Traffic } from '../Api/OperationsApi';
import { QueryFailureMessage } from '../Api/OperationsApi';

export function FailureNotice(Input: Readonly<{
    Failure: ApiFailure; OnRetry?: () => void; Heading?: string;
}>): ReactNode {
    return <section className="notice notice-error" role="alert">
        <div><strong>{Input.Heading || '无法验证管理响应'}</strong>
            <p>{Input.Failure.Message}</p>
            {Input.Failure.HttpStatus !== null &&
                <small>HTTP {Input.Failure.HttpStatus} · {FailureKindLabel(Input.Failure.Kind)}</small>}
            {Input.Failure.MayHaveExecuted &&
                <p className="warning-text">命令结果未知：服务端是否接收尚未确认；这次响应没有提供可查询的操作编号，无法按编号确认这条命令。页面不会自动重发，请勿再次提交。</p>}
        </div>
        {Input.OnRetry && <button className="button button-secondary" onClick={Input.OnRetry}>重新查询</button>}
    </section>;
}

function FailureKindLabel(Kind: ApiFailure['Kind']): string {
    if (Kind === 'network') return '连接错误';
    if (Kind === 'cancelled') return '查询已取消';
    if (Kind === 'http') return '服务拒绝请求';
    if (Kind === 'contract') return '响应无法确认';
    if (Kind === 'version') return '版本不匹配';
    if (Kind === 'authority') return '访问来源不允许';
    return '管理进程已更换';
}

export function LoadingState(Input: Readonly<{ Label: string }>): ReactNode {
    return <div className="loading-state" role="status" aria-live="polite">
        <span className="spinner" aria-hidden="true" />正在读取{Input.Label}…
    </div>;
}

export function EmptyState(Input: Readonly<{ Title: string; Detail: string }>): ReactNode {
    return <div className="empty-state"><span className="empty-mark" aria-hidden="true">—</span>
        <strong>{Input.Title}</strong><p>{Input.Detail}</p></div>;
}

export function QueryView<Value>(Input: Readonly<{
    Query: UseQueryResult<Result<QueryEnvelope<Value>>>;
    Label: string;
    Children: (Value: Value) => ReactNode;
}>): ReactNode {
    if (Input.Query.isPending) return <LoadingState Label={Input.Label} />;
    if (Input.Query.isError) return <FailureNotice Failure={{ Kind: 'network',
        Message: '查询未得到可验证响应', HttpStatus: null, MayHaveExecuted: false }}
        OnRetry={() => void Input.Query.refetch()} />;
    const ResultValue = Input.Query.data;
    if (!ResultValue.Ok) return <FailureNotice Failure={ResultValue.Failure}
        OnRetry={() => void Input.Query.refetch()} />;
    if (ResultValue.Value.Status !== 'ok' || ResultValue.Value.Value === null) {
        const Failure = ResultValue.Value;
        let Heading = '没有可用结果';
        if (Failure.Status === 'unavailable') Heading = '当前不可用';
        return <section className="notice notice-unavailable" role="status">
            <strong>{Heading}</strong>
            <p>{QueryFailureMessage(Failure)}</p>
            {Failure.Failure !== null && <FailureDetail Value={Failure.Failure} />}
            <button className="button button-secondary" onClick={() => void Input.Query.refetch()}>
                重新查询
            </button>
        </section>;
    }
    return <>{Input.Children(ResultValue.Value.Value)}</>;
}

export function InlineCommandResult(Input: Readonly<{
    Result: Result<CommandEnvelope> | null; Process: string;
}>): ReactNode {
    if (Input.Result === null) return null;
    if (!Input.Result.Ok) return <FailureNotice Failure={Input.Result.Failure} />;
    const Value = Input.Result.Value;
    let Process = Input.Process;
    if (Value.Process !== null) Process = Value.Process;
    return <section className="notice notice-info" role="status" aria-live="polite">
        <strong>服务状态：{CommandStatusLabel(Value.Status)}</strong>
        <p>{Value.Message || '服务端未提供额外说明。'}</p>
        <small>进程编号：{Process}</small>
        {Value.Operation !== '0' && <small>操作编号：{Value.Operation}</small>}
        {Value.Failure !== null && <FailureDetail Value={Value.Failure} />}
        {Value.Status === 'conflict' && <p>配置已被其他操作更新。请读取当前版本 {Value.Generation}，比较草稿后重新校验。</p>}
        {Value.Status === 'restart_required' && <p>服务端确认以下变更需要重启；本次没有发布配置。</p>}
        {Value.RestartRequiredFields.length > 0 && <ul>
            {Value.RestartRequiredFields.map(Field => <li key={Field}>{Field}</li>)}
        </ul>}
        {Value.ConfigurationIssues.length > 0 && <ul>
            {Value.ConfigurationIssues.map((Issue, Index) => <li key={`${Issue.Path}-${Index}`}>
                <strong>{Issue.Path || 'Configuration'}</strong> · {Issue.Code} · {Issue.Message}
            </li>)}
        </ul>}
    </section>;
}

export function TrafficSummary(Input: Readonly<{ Value: Traffic | null }>): ReactNode {
    if (Input.Value === null) return <span className="muted">未采集</span>;
    return <>↑ {FormatBytes(Input.Value.UpBytes)}<br />↓ {FormatBytes(Input.Value.DownBytes)}</>;
}

function CommandStatusLabel(Status: CommandStatus): string {
    if (Status === 'accepted') return '处理中';
    if (Status === 'completed') return '已完成';
    if (Status === 'rejected') return '已拒绝';
    if (Status === 'unavailable') return '不可用';
    if (Status === 'failed') return '失败';
    if (Status === 'timed_out') return '已超时';
    if (Status === 'blocked') return '已阻止';
    if (Status === 'invalid') return '无效';
    if (Status === 'restart_required') return '需要重启';
    return '配置版本冲突';
}

function FailureDetail(Input: Readonly<{ Value: NonNullable<CommandEnvelope['Failure']> }>): ReactNode {
    let Detail = Input.Value.Code;
    if (Input.Value.NativeCategory !== null) Detail += ` · ${Input.Value.NativeCategory}`;
    if (Input.Value.NativeValue !== null) Detail += ` · ${Input.Value.NativeValue}`;
    return <small>错误详情：{Detail}</small>;
}

export function SectionHeading(Input: Readonly<{
    Eyebrow: string; Title: string; Description: string; Action?: ReactNode;
}>): ReactNode {
    return <header className="section-heading">
        <div><span className="eyebrow">{Input.Eyebrow}</span><h1>{Input.Title}</h1>
            <p>{Input.Description}</p></div>
        {Input.Action && <div className="section-actions">{Input.Action}</div>}
    </header>;
}

export function StatusBadge(Input: Readonly<{ Label: string; Tone?: 'good' | 'warn' | 'bad' | 'neutral' }>): ReactNode {
    const Tone = Input.Tone || 'neutral';
    return <span className={`badge badge-${Tone}`}>{Input.Label}</span>;
}

export function DataCell(Input: Readonly<{ Label: string; Value: ReactNode }>): ReactNode {
    return <div className="data-cell"><span>{Input.Label}</span><strong>{Input.Value}</strong></div>;
}
