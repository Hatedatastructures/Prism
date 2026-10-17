import { TimeLink as Link } from './TimeLink';
import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';

import { OperationScopeChangedError } from '../Services/AdminDataSource';
import type { AdminActionResult } from '../Services/AdminDataSource';
import { useAdminServices } from './UseOperations';

export function ActionFeedback(Input: Readonly<{ Result: AdminActionResult | undefined }>): ReactNode {
    const Services = useAdminServices(), QueryClient = useQueryClient();
    const Id = Input.Result?.OperationId ?? Input.Result?.Operation?.Id;
    const Scope = Input.Result?.OperationScope;
    const [StartedAt, SetStartedAt] = useState(() => Date.now());
    useEffect(() => SetStartedAt(Date.now()), [Id]);
    const Query = useQuery({ queryKey: ['operations', 'operation-status', Scope?.ProcessId, Scope?.Incarnation, Id],
        enabled: !!Id && !!Scope && Input.Result?.Status === 'accepted', retry: false,
        queryFn: () => Services.Data.GetOperationStatus(Id ?? '', Scope!),
        refetchInterval: State => (State.state.error as { Code?: string } | null)?.Code === 'operation-scope-changed'
            ? false : State.state.data && State.state.data.State !== 'accepted' && State.state.data.State !== 'running' ? false : Date.now() - StartedAt < 30_000 ? 1000 : 5000,
        refetchIntervalInBackground: false });
    useEffect(() => {
        if (Query.data && Query.data.State !== 'accepted' && Query.data.State !== 'running') void QueryClient.invalidateQueries({ queryKey: ['operations'], predicate: Value => !Value.queryKey.includes('operation-status') });
    }, [Query.data, QueryClient]);
    if (!Input.Result) return null;
    const ScopeChanged = Query.error instanceof OperationScopeChangedError;
    const ScopeUnavailable = !!Id && Input.Result.Status === 'accepted' && (!Scope || !!Query.error && !ScopeChanged);
    const StatusRecord = Query.error ? undefined : Query.data;
    const State = StatusRecord?.State ?? Input.Result.Status;
    const Pending = !ScopeUnavailable && (State === 'accepted' || State === 'running');
    const Unknown = ScopeUnavailable || State === 'unknown' || State === 'interrupted';
    const DetailsPath = Id && Scope && !Unknown
        ? `/operations?${new URLSearchParams({ operation: Id, process: Scope.ProcessId, incarnation: Scope.Incarnation })}`
        : '/operations';
    const Issues = Input.Result.ConfigurationIssues ?? [];
    const RestartFields = Input.Result.RestartRequiredFields ?? [];
    return <div className={`notice ${Unknown || State === 'blocked' || Query.error ? 'notice-warning' : Input.Result.Ok ? 'notice-info' : 'notice-danger'}`} role="status">
        <div><strong>{Pending ? '命令已受理，正在核对实际结果' : State === 'completed' ? '操作已完成' : ScopeChanged ? '来源实例已变' : ScopeUnavailable ? '当前无法核实操作来源' : Unknown ? '操作结果待核对' : '操作结果'}</strong>
            <p>{ScopeChanged ? '来源实例已变，未查询同号操作。请在当前操作列表按目标与时间核对。'
                : ScopeUnavailable ? `当前无法核实操作来源${Query.error ? `：${Query.error.message}` : '；该结果没有实例范围'}。请在当前操作列表按目标与时间核对。`
                    : StatusRecord?.Message || Input.Result.Message}</p>
            {(StatusRecord?.Failure || Input.Result.Failure) && <p>{StatusRecord?.Failure ?? Input.Result.Failure}</p>}
            {Issues.length > 0 && <div className="action-feedback-extra"><strong>配置问题</strong><ul>{Issues.map((Issue, Index) =>
                <li key={`${Issue.Path}:${Issue.Code}:${Index}`}><code>{Issue.Path}</code> · {Issue.Code}：{Issue.Message}</li>)}</ul></div>}
            {RestartFields.length > 0 && <div className="action-feedback-extra"><strong>需要重启的字段</strong><ul>{RestartFields.map(Field => <li key={Field}><code>{Field}</code></li>)}</ul></div>}
            {Unknown && Input.Result.LocalAttemptId && <details className="action-feedback-extra"><summary>请求排查信息</summary>
                <p>本地尝试编号 <code>{Input.Result.LocalAttemptId}</code> 仅供当前浏览器记录；服务端未接入按它查询或去重，不能据此恢复结果。</p></details>}
        </div><Link className="text-link" to={DetailsPath}>查看操作中心</Link>
    </div>;
}
