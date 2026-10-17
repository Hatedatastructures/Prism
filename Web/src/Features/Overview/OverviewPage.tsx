import { TimeLink as Link } from '../TimeLink';
import type { ReactNode } from 'react';
import { ArrowRight, CircleAlert, CircleCheck, CircleHelp, RefreshCw } from 'lucide-react';
import { useSearchParams } from 'react-router';
import { EmptyState, FormatBytes, FormatCount, FormatRate, FormatTime, Panel, ProgressBar, QueryState, StatusBadge } from '../../Components/Ui';
import { Fraction } from '../../Api/Analysis';
import type { AccountRecord, EventRecord, IngressRecord, OverviewSnapshot, WorkerRecord } from '../../Services/AdminDataSource';
import { DecideOverview } from './OverviewDecision';
import type { OverviewDecision as OverviewDecisionValue, OverviewQueryState } from './OverviewDecision';
import { useAdminQuery } from '../UseOperations';
import { HistoryPanel } from '../HistoryPanel';
import { TimeRangeControl, WithTime } from '../TimeRange';
import { ProtocolShare } from '../Protocols/ProtocolsPage';
import { WorkerTargetPath } from '../Workers/WorkerIdentity';
import { DecideIngressRowPresentation, PresentIngressRows } from '../Ingresses/IngressPresentation';
import { AvailableBytes, DecideBytePoolUsage } from '../Resources/ResourceAvailability';

export default function OverviewPage(): ReactNode {
    const [Params] = useSearchParams();
    const Query = useAdminQuery('overview', Source => Source.GetOverview());
    const Workers = useAdminQuery('overview-workers', Source => Source.GetWorkers({ Cursor: '0', Limit: 5 }));
    const Ingresses = useAdminQuery('overview-ingresses', Source => Source.GetIngresses({ Cursor: '0', Limit: 50 }));
    const Accounts = useAdminQuery('overview-accounts', Source => Source.GetAccounts({ Cursor: '0', Limit: 5 }));
    const Events = useAdminQuery('overview-events', Source => Source.GetEvents({ Cursor: '0', Limit: 5 }));
    const Snapshot = Query.data;
    const Decision = DecideOverview({
        NowMs: Date.now(),
        Snapshot: Snapshot ?? null,
        Ingresses: Ingresses.data ?? null,
        Events: Events.data ?? null,
        Queries: {
            Overview: QueryStatus(Query.isPending, Query.error, Snapshot !== undefined),
            Ingresses: QueryStatus(Ingresses.isPending, Ingresses.error, Ingresses.data !== undefined),
            Events: QueryStatus(Events.isPending, Events.error, Events.data !== undefined),
        },
    });
    return <div className="operations-dashboard-v2">
        <div className="overview-toolbar"><div><h1>运行概览</h1><span>连接、消耗与当前运行质量</span></div>
            <div className="page-actions"><TimeRangeControl /><button type="button" className="button button-secondary" disabled={Query.isFetching}
                onClick={() => { void Promise.all([Query.refetch(), Workers.refetch(), Ingresses.refetch(), Accounts.refetch(), Events.refetch()]); }}><RefreshCw size={15} />刷新</button></div></div>
        <OverviewVerdict Value={Decision} Params={Params} Snapshot={Snapshot ?? null} />
        <QueryState Pending={Query.isPending} Error={Query.error} HasData={Snapshot !== undefined} Label="运行概览" Children={Snapshot ? <>
            <RuntimeSummary Value={Snapshot} />
            <div className="overview-grid-v2">
                <HistoryPanel Scope="process" ClassName="overview-traffic-v2" Variant="banded" />
                <HistoryPanel Scope="process" Kind="latency" ClassName="overview-latency-v2" />
                <Panel Title="入口能力" ClassName="overview-ingress-v2" Variant="banded" Action={<Link className="text-link" to={WithTime('/ingresses', Params)}>全部入口 <ArrowRight size={13} /></Link>}>
                    <QueryState Pending={Ingresses.isPending} Error={Ingresses.error} HasData={Ingresses.data !== undefined} Label="入口" Children={<IngressSummary Rows={Ingresses.data?.Items ?? []} HasMore={Ingresses.data?.HasMore ?? false} />} />
                </Panel>
                <div className="overview-lower-v2"><div className="overview-primary-v2">
                <Panel Title="Worker 派发与执行" ClassName="overview-worker-v2" Action={<Link className="text-link" to={WithTime('/workers', Params)}>全部 Worker <ArrowRight size={13} /></Link>}>
                    <QueryState Pending={Workers.isPending} Error={Workers.error} HasData={Workers.data !== undefined} Label="Worker" Children={<WorkerSummary Rows={Workers.data?.Items ?? []} Params={Params} />} />
                </Panel>
                <Panel Title="协议分布" Subtitle="活动 TCP Session · 当前快照" ClassName="overview-protocol-v2" Action={<Link className="text-link" to={WithTime('/protocols', Params)}>分析 <ArrowRight size={13} /></Link>}>
                    <ProtocolShare Rows={Snapshot.Protocols} Total={Snapshot.Counts.TcpSessions} />
                </Panel>
                <Panel Title="账户消耗" Subtitle="当前目录首 5 项 · 观测流量与额度账本分别查询" ClassName="overview-account-v2" Action={<Link className="text-link" to={WithTime('/accounts', Params)}>账户与额度 <ArrowRight size={13} /></Link>}>
                    <QueryState Pending={Accounts.isPending} Error={Accounts.error} HasData={Accounts.data !== undefined} Label="账户" Children={<AccountSummary Rows={Accounts.data?.Items ?? []} />} />
                </Panel>

                </div>
                <div className="overview-aside-v2">
                <Panel Title="近期事件" ClassName="overview-events-v2" Action={<Link className="text-link" to={WithTime('/events', Params)}>全部事件 <ArrowRight size={13} /></Link>}>
                    <QueryState Pending={Events.isPending} Error={Events.error} HasData={Events.data !== undefined} Label="近期事件" Children={<>
                        {Events.data?.Lost && <div className="notice notice-warning">事件缓冲已覆盖部分记录</div>}
                        {Events.data?.Items.length ? <div className="overview-event-list">{Events.data.Items.slice(0, 5).map(Event => <EventPreview key={`${Event.ProcessId}-${Event.Id}`} Value={Event} />)}</div>
                            : <EmptyState Title="没有近期事件" Detail="当前事件窗口没有记录。" />}
                    </>} />
                </Panel>
                <Panel Title="资源与观测质量" ClassName="overview-resource-v2" Action={<Link className="text-link" to={WithTime('/resources', Params)}>详细分析 <ArrowRight size={13} /></Link>}><ResourceSummary Value={Snapshot} /></Panel>
                </div>
                </div>
            </div>
            <p className="snapshot-caption">实例 {Snapshot.Process.Id} · Generation {Snapshot.Process.GenerationId}</p>
        </> : null} />
    </div>;
}
function RuntimeSummary(Input: Readonly<{ Value: OverviewSnapshot }>): ReactNode {
    const Value = Input.Value;
    return <div className="runtime-summary" aria-label="当前运行摘要">
        <div className="summary-throughput" role="group" aria-label="实时吞吐">
            <div className="summary-flow"><span className="summary-metric-heading">当前下行</span><strong className="rate-down"><RateReading Value={Value.Traffic.DownBytesPerSecond} /></strong><small>累计 {FormatBytes(Value.Traffic.DownBytes)}</small></div>
            <div className="summary-flow"><span className="summary-metric-heading">当前上行</span><strong className="rate-up"><RateReading Value={Value.Traffic.UpBytesPerSecond} /></strong><small>累计 {FormatBytes(Value.Traffic.UpBytes)}</small></div>
        </div>
        <Link to="/sessions"><span className="summary-metric-heading">活动连接</span><strong>{FormatCount(Value.Counts.TcpSessions)} <small>TCP Session</small></strong>
            <small>UDP {Value.Counts.UdpConnections === null ? '未采集' : FormatCount(Value.Counts.UdpConnections)} · QUIC {Value.Counts.QuicConnections === null ? '未采集' : FormatCount(Value.Counts.QuicConnections)}</small></Link>
        <Link to="/workers"><span className="summary-metric-heading">接收 Worker</span><strong>{FormatCount(Value.Counts.WorkersAccepting)} <small>/ {FormatCount(Value.Counts.WorkersTotal)}</small></strong><small>不接收可能是计划排空</small></Link>
        <Link className="summary-account" to="/accounts"><span className="summary-metric-heading">活动账户</span><strong>{FormatCount(Value.Counts.ActiveAccounts)} <small>/ {FormatCount(Value.Counts.ConfiguredAccounts)}</small></strong><small>未分组 {FormatCount(Value.Counts.UngroupedAccounts)}</small></Link>
    </div>;
}
function RateReading(Input: Readonly<{ Value: OverviewSnapshot['Traffic']['UpBytesPerSecond'] }>): ReactNode {
    const Text = FormatRate(Input.Value), UnitIndex = Text.lastIndexOf(' ');
    return UnitIndex < 0 ? Text : <>{Text.slice(0, UnitIndex)}<small className="metric-unit">{Text.slice(UnitIndex + 1)}</small></>;
}
function QueryStatus(Pending: boolean, ErrorValue: Error | null | undefined, HasData: boolean): OverviewQueryState {
    if (ErrorValue) return 'error';
    return Pending || !HasData ? 'pending' : 'success';
}
function OverviewVerdict(Input: Readonly<{ Value: OverviewDecisionValue; Params: URLSearchParams; Snapshot: OverviewSnapshot | null }>): ReactNode {
    const Availability = Input.Value.Availability, Observation = Input.Value.Observation;
    const Mark = Availability.State === 'normal' ? CircleCheck
        : Availability.State === 'affected' ? CircleAlert : CircleHelp;
    const ObservationLabel = Observation.State === 'gaps' ? '存在覆盖缺口'
        : Observation.State === 'unavailable' ? '当前不可用'
        : Observation.State === 'pending' ? '正在载入' : '当前已报告';
    const Eyebrow = Availability.State === 'normal' ? '当前接入'
        : Availability.State === 'affected' ? '接入未就绪' : '判断受限';
    const SnapshotEvidence = Input.Snapshot ? `最近采样 ${FormatTime(Input.Snapshot.SampledAt, true)}` : null;
    return <section className="overview-verdict" data-state={Availability.State} aria-label="当前接入判断">
        <div className="overview-verdict__heading" role="status" aria-live="polite">
            <Mark size={19} aria-hidden="true" />
            <div className="overview-verdict__copy"><span className="overview-verdict__eyebrow">{Eyebrow}</span>
                <h2>{Availability.Title}</h2><p>{Availability.Detail}</p>
                {SnapshotEvidence && <p className="overview-verdict__primary-evidence">{SnapshotEvidence}</p>}</div>
            <Link className="overview-verdict__action" to={WithTime(Availability.NextPath, Input.Params)}>
                {Availability.NextLabel}<ArrowRight size={14} aria-hidden="true" />
            </Link>
        </div>
        {Availability.Evidence.length > 0 && <details className="overview-verdict__details">
            <summary>查看 readiness 与入口证据（{Availability.Evidence.length}）</summary>
            <ul className="overview-verdict__evidence" aria-label="判断依据">
                {Availability.Evidence.map(Value => <li key={Value}>{Value}</li>)}
            </ul>
        </details>}
        <details className="overview-verdict__observation" data-state={Observation.State} aria-label="观测记录完整性">
            <summary>诊断记录 · {ObservationLabel}</summary><p>{Observation.Detail}</p>
        </details>
    </section>;
}
function WorkerSummary(Input: Readonly<{ Rows: readonly WorkerRecord[]; Params: URLSearchParams }>): ReactNode {
    if (!Input.Rows.length) return <EmptyState Title="没有 Worker" Detail="运行时尚未返回 Worker 记录。" />;
    return <div className="table-scroll"><table className="data-table"><thead><tr><th>Worker</th><th>活动任务</th><th>命令邮箱 / 容量</th><th>派发拒绝累计</th><th>状态</th></tr></thead>
        <tbody>{Input.Rows.map(Row => {
            const QueueUsage = Fraction(Row.QueueDepth, Row.QueueCapacity);
            return <tr key={`${Row.ProcessId}-${Row.GenerationId}-${Row.Id}`}><td><Link className="table-link" to={WithTime(WorkerTargetPath('workers', Row), Input.Params)}>{Row.Name}</Link></td><td>{FormatCount(Row.ActiveTasks)}</td>
            <td><div className="summary-queue"><span>{FormatCount(Row.QueueDepth)} / {FormatCount(Row.QueueCapacity)}</span>
                {QueueUsage === null ? <small className="field-hint">容量为 0，使用率不可计算。</small>
                    : <ProgressBar Value={QueueUsage} Tone="mint" Label={`${Row.Name} 命令邮箱`} />}</div></td>
            <td>{FormatCount((BigInt(Row.DispatchFull) + BigInt(Row.DispatchClosed) + BigInt(Row.DispatchUnavailable) + BigInt(Row.DispatchGenerationRejected)).toString())}</td>
            <td><StatusBadge Label={Row.Accepting ? '接收中' : Row.Running ? '不接收' : '已停止'} Tone={Row.Accepting ? 'good' : 'neutral'} /></td></tr>;
        })}</tbody></table>
        <p className="field-hint">最多显示 5 个 Worker；活动任务、Session、邮箱是独立计数。</p></div>;
}
function IngressSummary(Input: Readonly<{ Rows: readonly IngressRecord[]; HasMore: boolean }>): ReactNode {
    if (!Input.Rows.length) return <EmptyState Title="没有配置入口" Detail="配置并发布监听后显示实际绑定能力。" />;
    return <>
        <div className="ingress-summary-list">{PresentIngressRows(Input.Rows).map(({ Value: Row, HasRuntimeState }) => {
            const Presentation = DecideIngressRowPresentation(Row, HasRuntimeState);
            const Detail = [Row.Reason, Presentation.Binding, Row.Protocols.join(' · ') || '协议未提供',
                Row.ActiveConnections === null ? '活动量未采集' : `${FormatCount(Row.ActiveConnections)} 活动`]
                .filter(Boolean).join(' · ');
            return <Link key={Row.Id} to={`/ingresses?ingress=${encodeURIComponent(Row.Id)}`}>
                <span><strong>{Row.Transport.toUpperCase()}</strong><code>{Row.ConfiguredAddress}</code></span>
                <StatusBadge Label={Presentation.Label} Tone={Presentation.Tone} />
                <small>{Detail}</small>
            </Link>;
        })}</div>
        <p className="field-hint">{Input.HasMore
            ? `当前显示前 ${Input.Rows.length} 条入口配置，仍有更多记录；后续配置行的绑定状态可能未单独采集。`
            : `当前返回 ${Input.Rows.length} 条入口配置；同一传输的后续配置行不代表独立 socket。`}</p>
    </>;
}
function AccountSummary(Input: Readonly<{ Rows: readonly AccountRecord[] }>): ReactNode {
    if (!Input.Rows.length) return <EmptyState Title="没有账户记录" Detail="配置账户后显示使用情况。" />;
    return <div className="table-scroll"><table className="data-table"><thead><tr><th>账户</th><th>用户组</th><th>根连接租约</th><th>累计上行</th><th>累计下行</th><th>状态</th></tr></thead>
        <tbody>{Input.Rows.map(Row => <tr key={Row.Id}><td><Link className="table-link" to={`/accounts?account=${encodeURIComponent(Row.Id)}`}><strong>{Row.Label}</strong><small>{Row.Id}</small></Link></td>
            <td>{Row.GroupId ?? '未分组'}</td><td>{FormatCount(Row.ActiveSessions)}</td><td>{FormatBytes(Row.Traffic?.Up)}</td><td>{FormatBytes(Row.Traffic?.Down)}</td><td><StatusBadge Label={Row.Revoked ? '已撤销' : '有效'} Tone={Row.Revoked ? 'danger' : 'good'} /></td></tr>)}</tbody></table></div>;
}
function ResourceSummary(Input: Readonly<{ Value: OverviewSnapshot }>): ReactNode {
    const Memory = Input.Value.Memory, Observations = Input.Value.Observations;
    return <><dl className="detail-kv"><div><dt>进程 RSS</dt><dd>{AvailableBytes(Memory.ProcessAvailable, Memory.ProcessRssBytes)}</dd></div><div><dt>Prism PMR</dt><dd>{AvailableBytes(Memory.Allocations.Available, Memory.Allocations.CurrentBytes)}</dd></div>
        <div><dt>BytePool</dt><dd>{AvailableBytes(Memory.BytePool.Available, Memory.BytePool.UsedBytes)} / {AvailableBytes(Memory.BytePool.Available, Memory.BytePool.CapacityBytes)}</dd></div></dl>
        <BytePoolUsage Available={Memory.BytePool.Available} UsedBytes={Memory.BytePool.UsedBytes} CapacityBytes={Memory.BytePool.CapacityBytes} />
        <div className="quality-summary"><span>观测丢弃 <b>{FormatCount(Observations.Dropped)}</b></span><span>聚合失败 <b>{FormatCount(Observations.AggregationFailures)}</b></span></div>
        <p className="field-hint">累计计数；丢失不代表真实字节量，历史缺口另行标记。</p></>;
}
function BytePoolUsage(Input: Readonly<{
    Available: boolean; UsedBytes: OverviewSnapshot['Memory']['BytePool']['UsedBytes'];
    CapacityBytes: OverviewSnapshot['Memory']['BytePool']['CapacityBytes'];
}>): ReactNode {
    const Usage = DecideBytePoolUsage(Input.Available, Input.UsedBytes, Input.CapacityBytes);
    if (Usage.State === 'available' && Usage.Value !== null) return <ProgressBar Value={Usage.Value} Tone="mint" Label="BytePool 使用率" />;
    const Detail = Usage.State === 'unavailable' ? 'BytePool 使用率未采集。'
        : Usage.State === 'zero-capacity' ? 'BytePool 容量为 0，无法计算使用率。'
        : Usage.State === 'missing' ? 'BytePool 使用量或容量未采集，无法计算使用率。'
        : 'BytePool 使用率不可用。';
    return <p className="field-hint">{Detail}</p>;
}
function EventPreview(Input: Readonly<{ Value: EventRecord }>): ReactNode {
    const Value = Input.Value;
    const Path = Value.OperationId && Value.OperationId !== '0' ? `/operations?operation=${encodeURIComponent(Value.OperationId)}` :
        Value.SessionId && Value.SessionId !== '0' ? `/sessions?${new URLSearchParams({ session: Value.SessionId, process: Value.ProcessId, generation: Value.GenerationId, identity_worker: Value.WorkerId ?? '', identity_account: Value.AccountId ?? '' })}` : '/events';
    return <Link className={`overview-event severity-${Value.Severity}`} to={Path}><span className="event-severity-dot" aria-hidden="true" />
        <div><strong><small className="event-inline-severity">{Value.Severity === 'error' ? '错误' : Value.Severity === 'warning' ? '告警' : '信息'}</small>{Value.Message}</strong><p>{Value.Detail || `${Value.Scope} · ${Value.Kind}`}</p></div>
        <time dateTime={Value.Time}>{FormatTime(Value.Time)}</time></Link>;
}
