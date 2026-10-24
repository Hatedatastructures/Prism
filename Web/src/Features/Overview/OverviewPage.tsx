import { TimeLink as Link } from '../TimeLink';
import { useDeferredValue, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import {
    Activity, ArrowRight, ArrowUpDown, CircleAlert, CircleCheck, CircleHelp, Cpu, LayoutGrid, List, RefreshCw,
    Search, Users, X,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { useSearchParams } from 'react-router';
import {
    EmptyState, FormatBytes, FormatCount, FormatRate, FormatTime, Panel, ProgressBar, QueryState,
    StatusBadge, TrendMini,
} from '../../Components/Ui';
import { Fraction } from '../../Api/Analysis';
import type {
    AccountRecord, EventRecord, IngressRecord, OverviewSnapshot, UInt64Value, WorkerRecord,
} from '../../Services/AdminDataSource';
import { DecideOverview } from './OverviewDecision';
import type { OverviewDecision as OverviewDecisionValue, OverviewQueryState } from './OverviewDecision';
import { useAdminQuery } from '../UseOperations';
import { HistoryPanel } from '../HistoryPanel';
import { TimeRangeControl, WithTime } from '../TimeRange';
import { ProtocolShare } from '../Protocols/ProtocolsPage';
import { WorkerTargetPath } from '../Workers/WorkerIdentity';
import { DecideIngressRowPresentation, PresentIngressRows } from '../Ingresses/IngressPresentation';
import { AvailableBytes, DecideBytePoolUsage } from '../Resources/ResourceAvailability';
import { BuildTrafficSeries } from './TrafficChart';
import { FilterOverviewWorkers } from './OverviewFleet';
import type { OverviewWorkerView } from './OverviewFleet';

export default function OverviewPage(): ReactNode {
    const [Params] = useSearchParams();
    const Query = useAdminQuery('overview', Source => Source.GetOverview());
    const Workers = useAdminQuery('overview-workers', Source => Source.GetWorkers({ Cursor: '0', Limit: 50 }));
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
    return <div className="operations-dashboard-v2 overview-page">
        <header className="overview-toolbar">
            <div className="overview-intro">
                <span className="overview-kicker">PRISM CONTROL PLANE</span>
                <h1>运行概览</h1>
                <p>代理入口、Worker 派发和账户连接的当前运行面。</p>
            </div>
            <div className="page-actions">
                <TimeRangeControl />
                <button type="button" className="button button-secondary" disabled={Query.isFetching}
                    onClick={() => { void Promise.all([
                        Query.refetch(), Workers.refetch(), Ingresses.refetch(), Accounts.refetch(), Events.refetch(),
                    ]); }}>
                    <RefreshCw size={15} className={Query.isFetching ? 'spin' : ''} aria-hidden="true" />刷新
                </button>
            </div>
        </header>
        <QueryState Pending={Query.isPending} Error={Query.error} HasData={Snapshot !== undefined} Label="运行概览"
            Children={Snapshot ? <>
                <OverviewVerdict Value={Decision} Params={Params} Snapshot={Snapshot} />
                <OverviewKpis Value={Snapshot} />
                <div className="overview-grid-v2">
                    <HistoryPanel Scope="process" ClassName="overview-traffic-v2" Variant="banded" />
                    <HistoryPanel Scope="process" Kind="latency" ClassName="overview-latency-v2" Variant="banded" />
                    <Panel Title="Worker 运行面" Subtitle="队列、活动任务与派发结果"
                        ClassName="overview-worker-v2"
                        Action={<Link className="text-link" to={WithTime('/workers', Params)}>
                            全部 Worker <ArrowRight size={13} aria-hidden="true" />
                        </Link>}>
                        <QueryState Pending={Workers.isPending} Error={Workers.error}
                            HasData={Workers.data !== undefined} Label="Worker"
                            Children={<WorkerFleet Rows={Workers.data?.Items ?? []} Params={Params}
                                HasMore={Workers.data?.HasMore ?? false} />} />
                    </Panel>
                    <aside className="overview-runtime-v2"><RuntimeSummary Value={Snapshot} /></aside>
                    <Panel Title="入口状态" Subtitle="监听就绪与当前连接"
                        ClassName="overview-ingress-v2"
                        Action={<Link className="text-link" to={WithTime('/ingresses', Params)}>
                            全部入口 <ArrowRight size={13} aria-hidden="true" />
                        </Link>}>
                        <QueryState Pending={Ingresses.isPending} Error={Ingresses.error}
                            HasData={Ingresses.data !== undefined} Label="入口"
                            Children={<IngressSummary Rows={Ingresses.data?.Items ?? []} Params={Params}
                                HasMore={Ingresses.data?.HasMore ?? false} />} />
                    </Panel>
                    <Panel Title="账户消耗" Subtitle="当前目录首 5 项 · 流量与额度分别观测"
                        ClassName="overview-account-v2"
                        Action={<Link className="text-link" to={WithTime('/accounts', Params)}>
                            账户与额度 <ArrowRight size={13} aria-hidden="true" />
                        </Link>}>
                        <QueryState Pending={Accounts.isPending} Error={Accounts.error}
                            HasData={Accounts.data !== undefined} Label="账户"
                            Children={<AccountSummary Rows={Accounts.data?.Items ?? []} />} />
                    </Panel>
                    <Panel Title="协议分布" Subtitle="活动 TCP Session · 当前快照"
                        ClassName="overview-protocol-v2"
                        Action={<Link className="text-link" to={WithTime('/protocols', Params)}>
                            分析 <ArrowRight size={13} aria-hidden="true" />
                        </Link>}>
                        <ProtocolShare Rows={Snapshot.Protocols} Total={Snapshot.Counts.TcpSessions} />
                    </Panel>
                    <Panel Title="近期事件" ClassName="overview-events-v2"
                        Action={<Link className="text-link" to={WithTime('/events', Params)}>
                            全部事件 <ArrowRight size={13} aria-hidden="true" />
                        </Link>}>
                        <QueryState Pending={Events.isPending} Error={Events.error}
                            HasData={Events.data !== undefined} Label="近期事件" Children={<>
                                {Events.data?.Lost && <div className="notice notice-warning">事件缓冲已覆盖部分记录</div>}
                                {Events.data?.Items.length
                                    ? <div className="overview-event-list">{Events.data.Items.slice(0, 5).map(Event =>
                                        <EventPreview key={`${Event.ProcessId}-${Event.Id}`} Value={Event} />)}</div>
                                    : <EmptyState Title="没有近期事件" Detail="当前事件窗口没有记录。" />}
                            </>} />
                    </Panel>
                    <Panel Title="资源与观测质量" ClassName="overview-resource-v2"
                        Action={<Link className="text-link" to={WithTime('/resources', Params)}>
                            详细分析 <ArrowRight size={13} aria-hidden="true" />
                        </Link>}>
                        <ResourceSummary Value={Snapshot} />
                    </Panel>
                </div>
                <p className="snapshot-caption">实例 {Snapshot.Process.Id} · Generation {Snapshot.Process.GenerationId}</p>
            </> : null} />
    </div>;
}

function OverviewVerdict(Input: Readonly<{
    Value: OverviewDecisionValue; Params: URLSearchParams; Snapshot: OverviewSnapshot | null;
}>): ReactNode {
    const Availability = Input.Value.Availability;
    const Observation = Input.Value.Observation;
    const Mark = Availability.State === 'normal' ? CircleCheck
        : Availability.State === 'affected' ? CircleAlert : CircleHelp;
    const ObservationLabel = Observation.State === 'gaps' ? '存在覆盖缺口'
        : Observation.State === 'unavailable' ? '当前不可用'
            : Observation.State === 'pending' ? '正在载入' : '当前已报告';
    const SnapshotEvidence = Input.Snapshot ? `最近采样 ${FormatTime(Input.Snapshot.SampledAt, true)}` : null;
    return <section className="overview-verdict" data-state={Availability.State} aria-label="当前接入判断">
        <div className="overview-verdict__heading" role="status" aria-live="polite">
            <span className="overview-verdict__icon"><Mark size={18} aria-hidden="true" /></span>
            <div className="overview-verdict__copy">
                <span className="overview-verdict__eyebrow">{Availability.State === 'normal' ? '接入正常' : '当前判断'}</span>
                <strong>{Availability.Title}</strong>
                <p>{Availability.Detail}</p>
            </div>
            {SnapshotEvidence && <time className="overview-verdict__sample">{SnapshotEvidence}</time>}
            <Link className="overview-verdict__action" to={WithTime(Availability.NextPath, Input.Params)}>
                {Availability.NextLabel}<ArrowRight size={13} aria-hidden="true" />
            </Link>
        </div>
        <div className="overview-verdict__foot">
            {Availability.Evidence.length > 0 && <details className="overview-verdict__details">
                <summary>readiness 与入口证据（{Availability.Evidence.length}）</summary>
                <ul className="overview-verdict__evidence" aria-label="判断依据">
                    {Availability.Evidence.map(Value => <li key={Value}>{Value}</li>)}
                </ul>
            </details>}
            <details className="overview-verdict__observation" data-state={Observation.State}
                aria-label="观测记录完整性">
                <summary>诊断记录 · {ObservationLabel}</summary><p>{Observation.Detail}</p>
            </details>
        </div>
    </section>;
}

function OverviewKpis(Input: Readonly<{ Value: OverviewSnapshot }>): ReactNode {
    const Value = Input.Value;
    const Down = SafeMetricNumber(Value.Traffic.DownBytesPerSecond);
    const Up = SafeMetricNumber(Value.Traffic.UpBytesPerSecond);
    const Total = (Down + Up).toString();
    const WorkerRatio = Fraction(Value.Counts.WorkersAccepting, Value.Counts.WorkersTotal);
    const AccountRatio = Fraction(Value.Counts.ActiveAccounts, Value.Counts.ConfiguredAccounts);
    const TrafficSpark = BuildTrafficSeries(Value.History)
        .slice(-28)
        .map(Point => Point.Up !== null && Point.Down !== null ? Point.Up + Point.Down : null)
        .filter((Point): Point is number => Point !== null && Number.isFinite(Point));
    const SessionSpark = Value.TcpSessionHistory.slice(-28).map(Sample => Number(Sample.Count))
        .filter(Number.isFinite);
    return <section className="overview-kpis" aria-label="关键运行指标">
        <KpiTile Icon={ArrowUpDown} Tone="cyan" Label="总吞吐" Value={FormatRate(Total)}
            Detail={`下行 ${FormatRate(Value.Traffic.DownBytesPerSecond)} · 上行 ${FormatRate(Value.Traffic.UpBytesPerSecond)}`}
            To="/resources" Spark={TrafficSpark} Ratio={null} RatioLabel="总吞吐" />
        <KpiTile Icon={Activity} Tone="blue" Label="活动会话" Value={FormatCount(Value.Counts.TcpSessions)} Unit="TCP"
            Detail={`UDP ${Value.Counts.UdpConnections === null ? '未采集' : FormatCount(Value.Counts.UdpConnections)} · QUIC ${Value.Counts.QuicConnections === null ? '未采集' : FormatCount(Value.Counts.QuicConnections)}`}
            To="/sessions" Spark={SessionSpark} Ratio={null} RatioLabel="活动会话" />
        <KpiTile Icon={Cpu} Tone="violet" Label="接收 Worker" Value={FormatCount(Value.Counts.WorkersAccepting)}
            Unit={`/ ${FormatCount(Value.Counts.WorkersTotal)}`}
            Detail={Value.Counts.WorkersTotal === '0' ? '当前没有 Worker' : '正在接收新派发'}
            To="/workers" Spark={[]} Ratio={WorkerRatio} RatioLabel="Worker 接收比例" />
        <KpiTile Icon={Users} Tone="amber" Label="活跃账户" Value={FormatCount(Value.Counts.ActiveAccounts)}
            Unit={`/ ${FormatCount(Value.Counts.ConfiguredAccounts)}`}
            Detail={`未分组 ${FormatCount(Value.Counts.UngroupedAccounts)}`}
            To="/accounts" Spark={[]} Ratio={AccountRatio} RatioLabel="账户活跃比例" />
    </section>;
}

function KpiTile(Input: Readonly<{
    Icon: LucideIcon; Tone: 'cyan' | 'blue' | 'violet' | 'amber'; Label: string; Value: string;
    Unit?: string; Detail: string; To: string;
    Spark: readonly number[]; Ratio: number | null; RatioLabel: string;
}>): ReactNode {
    return <Link className="overview-kpi" to={Input.To} data-tone={Input.Tone}>
        <span className="overview-kpi__top">
            <span className="overview-kpi__icon"><Input.Icon size={17} aria-hidden="true" /></span>
            <span>{Input.Label}</span>
            <span className="overview-kpi__reading">{Input.Ratio === null ? 'LIVE' : 'RATIO'}</span>
            <ArrowRight size={14} aria-hidden="true" />
        </span>
        <span className="overview-kpi__body">
            <strong>{Input.Value}{Input.Unit && <small>{Input.Unit}</small>}</strong>
            {Input.Ratio !== null
                ? <span className="overview-kpi__ratio"><b>{Math.round(Input.Ratio)}<small>%</small></b>
                    <span>{Input.RatioLabel}</span></span>
                : <KpiSpark Values={Input.Spark} Label={`${Input.Label}趋势`} />}
        </span>
        <span className="overview-kpi__foot">{Input.Detail}</span>
    </Link>;
}

function KpiSpark(Input: Readonly<{ Values: readonly number[]; Label: string }>): ReactNode {
    if (Input.Values.length < 2) return <span className="overview-kpi__spark-empty" aria-hidden="true" />;
    return <span className="overview-kpi__spark">
        <TrendMini Values={Input.Values.slice(-22)} Tone="accent" Label={Input.Label} />
    </span>;
}

function MiniRing(Input: Readonly<{ Value: number; Label: string }>): ReactNode {
    const Value = Math.max(0, Math.min(100, Input.Value));
    const Radius = 15.5;
    const Circumference = 2 * Math.PI * Radius;
    return <span className="mini-ring" role="img" aria-label={`${Input.Label} ${Math.round(Value)}%`}>
        <svg viewBox="0 0 40 40" aria-hidden="true">
            <circle cx="20" cy="20" r={Radius} className="mini-ring__track" />
            <circle cx="20" cy="20" r={Radius} className="mini-ring__value"
                strokeDasharray={`${Circumference * Value / 100} ${Circumference}`} />
        </svg>
        <b>{Math.round(Value)}<small>%</small></b>
    </span>;
}

function RuntimeSummary(Input: Readonly<{ Value: OverviewSnapshot }>): ReactNode {
    const Value = Input.Value;
    const Memory = Value.Memory;
    const BytePoolUsage = Fraction(Memory.BytePool.UsedBytes ?? '0', Memory.BytePool.CapacityBytes ?? '0');
    return <section className="runtime-summary" aria-label="当前运行摘要">
        <div className="runtime-summary__title">
            <div><span>进程运行面</span><small>LIVE RUNTIME</small></div>
            <span className="runtime-summary__health"><i className={`health-dot health-${Value.Health.Status}`} aria-hidden="true" />
                {Value.Health.Status === 'healthy' ? '健康' : HealthReading(Value.Health.Status)}</span>
        </div>
        <div className="runtime-metric-list">
            <RuntimeMetric Label="进程 RSS" Value={AvailableBytes(Memory.ProcessAvailable, Memory.ProcessRssBytes)}
                Detail={Memory.ProcessAvailable && Memory.ProcessPeakRssBytes !== null ? `峰值 ${FormatBytes(Memory.ProcessPeakRssBytes)}` : '未采集峰值'} />
            <RuntimeMetric Label="Prism PMR" Value={AvailableBytes(Memory.Allocations.Available, Memory.Allocations.CurrentBytes)}
                Detail={Memory.Allocations.Available ? `峰值 ${FormatBytes(Memory.Allocations.PeakBytes)}` : '未提供'} />
            <RuntimeMetric Label="BytePool" Value={AvailableBytes(Memory.BytePool.Available, Memory.BytePool.UsedBytes)}
                Detail={BytePoolUsage === null ? '容量未采集' : `${BytePoolUsage.toFixed(1)}% 容量`} Ratio={BytePoolUsage} />
            <RuntimeMetric Label="观测丢弃" Value={FormatCount(Value.Observations.Dropped)}
                Detail={`聚合失败 ${FormatCount(Value.Observations.AggregationFailures)}`}
                Tone={Nonzero(Value.Observations.Dropped) ? 'warning' : 'neutral'} />
        </div>
        <div className="runtime-summary__links">
            <Link to="/workers"><span>接收 Worker</span><strong>{FormatCount(Value.Counts.WorkersAccepting)} / {FormatCount(Value.Counts.WorkersTotal)}</strong></Link>
            <Link to="/accounts"><span>活跃账户</span><strong>{FormatCount(Value.Counts.ActiveAccounts)} / {FormatCount(Value.Counts.ConfiguredAccounts)}</strong></Link>
        </div>
    </section>;
}

function RuntimeMetric(Input: Readonly<{
    Label: string; Value: string; Detail: string; Ratio?: number | null; Tone?: 'warning' | 'neutral';
}>): ReactNode {
    return <div className="runtime-metric" data-tone={Input.Tone ?? 'neutral'}>
        <span>{Input.Label}</span><strong>{Input.Value}</strong><small>{Input.Detail}</small>
        {Input.Ratio !== undefined && <span className="runtime-metric__bar"><i style={{ width: `${Input.Ratio ?? 0}%` }} /></span>}
    </div>;
}

function WorkerFleet(Input: Readonly<{
    Rows: readonly WorkerRecord[]; Params: URLSearchParams; HasMore: boolean;
}>): ReactNode {
    const [SearchText, SetSearchText] = useState('');
    const [View, SetView] = useState<OverviewWorkerView>('grid');
    const DeferredSearch = useDeferredValue(SearchText);
    const Filtered = useMemo(() => FilterOverviewWorkers(Input.Rows, DeferredSearch), [Input.Rows, DeferredSearch]);
    return <>
        <div className="fleet-controls">
            <label className="fleet-search"><Search size={16} aria-hidden="true" />
                <input aria-label="搜索概览 Worker" placeholder="搜索 Worker 名称或状态"
                    value={SearchText} onChange={Event => SetSearchText(Event.target.value)} />
                {SearchText && <button type="button" aria-label="清除 Worker 搜索" onClick={() => SetSearchText('')}>
                    <X size={14} aria-hidden="true" />
                </button>}
            </label>
            <span className="fleet-count">{Filtered.length} / {Input.Rows.length}{Input.HasMore ? '+' : ''}</span>
            <div className="fleet-view" role="group" aria-label="Worker 视图">
                <button type="button" aria-label="网格视图" aria-pressed={View === 'grid'}
                    onClick={() => SetView('grid')}><LayoutGrid size={15} aria-hidden="true" /></button>
                <button type="button" aria-label="列表视图" aria-pressed={View === 'list'}
                    onClick={() => SetView('list')}><List size={15} aria-hidden="true" /></button>
            </div>
        </div>
        {Filtered.length === 0
            ? <EmptyState Title="没有匹配的 Worker" Detail="更换搜索词后重试。" />
            : View === 'grid'
                ? <div className="fleet-grid">{Filtered.map(Row =>
                    <WorkerCard key={`${Row.ProcessId}-${Row.GenerationId}-${Row.Id}`} Row={Row} Params={Input.Params} />)}
                </div>
                : <WorkerSummary Rows={Filtered} Params={Input.Params} />}
        {Input.HasMore && <p className="field-hint">仅显示已载入的 Worker；继续载入后显示完整范围。</p>}
    </>;
}

function WorkerCard(Input: Readonly<{ Row: WorkerRecord; Params: URLSearchParams }>): ReactNode {
    const Row = Input.Row;
    const QueueRatio = Fraction(Row.QueueDepth, Row.QueueCapacity);
    const Status = Row.Accepting ? '接收中' : Row.State === 'draining' ? '排空中' : '已停止';
    return <article className="fleet-card">
        <div className="fleet-card__head">
            <span className={`health-dot health-${Row.Health}`} aria-hidden="true" />
            <div>
                <Link to={WithTime(WorkerTargetPath('workers', Row), Input.Params)}>{Row.Name}</Link>
                <small>{Row.Id} · G{Row.GenerationId}</small>
            </div>
            <StatusBadge Label={Status} Tone={Row.Accepting ? 'good' : Row.State === 'draining' ? 'warning' : 'neutral'} />
        </div>
        <div className="fleet-card__body">
            <MiniRing Value={QueueRatio ?? 0} Label={`${Row.Name} 队列使用率`} />
            <dl>
                <div><dt>活动任务</dt><dd>{FormatCount(Row.ActiveTasks)}</dd></div>
                <div><dt>队列</dt><dd>{FormatCount(Row.QueueDepth)} / {FormatCount(Row.QueueCapacity)}</dd></div>
                <div><dt>负载</dt><dd>{Row.LoadPercent === null ? '—' : `${Row.LoadPercent}%`}</dd></div>
            </dl>
        </div>
        <div className="fleet-card__foot">
            <span>拒绝 {FormatCount(WorkerRejections(Row))}</span>
            <span>下行 {Row.Traffic ? FormatBytes(Row.Traffic.Down) : '—'}</span>
            <Link to={WithTime(WorkerTargetPath('workers', Row), Input.Params)} aria-label={`打开 ${Row.Name}`}>
                <ArrowRight size={14} aria-hidden="true" />
            </Link>
        </div>
    </article>;
}

function WorkerSummary(Input: Readonly<{ Rows: readonly WorkerRecord[]; Params: URLSearchParams }>): ReactNode {
    if (!Input.Rows.length) return <EmptyState Title="没有 Worker" Detail="运行时尚未返回 Worker 记录。" />;
    return <div className="table-scroll"><table className="data-table overview-worker-table">
        <thead><tr><th>Worker</th><th>状态</th><th>活动任务</th><th>命令邮箱</th><th>派发拒绝</th></tr></thead>
        <tbody>{Input.Rows.map(Row => {
            const QueueUsage = Fraction(Row.QueueDepth, Row.QueueCapacity);
            return <tr key={`${Row.ProcessId}-${Row.GenerationId}-${Row.Id}`}>
                <td><Link className="table-link" to={WithTime(WorkerTargetPath('workers', Row), Input.Params)}>{Row.Name}</Link></td>
                <td><StatusBadge Label={Row.Accepting ? '接收中' : Row.State === 'draining' ? '排空中' : '已停止'}
                    Tone={Row.Accepting ? 'good' : Row.State === 'draining' ? 'warning' : 'neutral'} /></td>
                <td>{FormatCount(Row.ActiveTasks)}</td>
                <td><div className="summary-queue"><span>{FormatCount(Row.QueueDepth)} / {FormatCount(Row.QueueCapacity)}</span>
                    {QueueUsage === null ? <small className="field-hint">容量为 0</small>
                        : <ProgressBar Value={QueueUsage} Tone="mint" Label={`${Row.Name} 命令邮箱`} />}</div></td>
                <td>{FormatCount(WorkerRejections(Row))}</td>
            </tr>;
        })}</tbody></table></div>;
}

function WorkerRejections(Row: WorkerRecord): string {
    return (BigInt(Row.DispatchFull) + BigInt(Row.DispatchClosed) + BigInt(Row.DispatchUnavailable) +
        BigInt(Row.DispatchGenerationRejected)).toString();
}

function IngressSummary(Input: Readonly<{
    Rows: readonly IngressRecord[]; Params: URLSearchParams; HasMore: boolean;
}>): ReactNode {
    if (!Input.Rows.length) return <EmptyState Title="没有配置入口" Detail="配置并发布监听后显示实际绑定能力。" />;
    return <>
        <div className="ingress-summary-list">{PresentIngressRows(Input.Rows).map(({ Value: Row, HasRuntimeState }) => {
            const Presentation = DecideIngressRowPresentation(Row, HasRuntimeState);
            const Detail = [Row.Reason, Presentation.Binding, Row.Protocols.join(' · ') || '协议未提供',
                Row.ActiveConnections === null ? '活动量未采集' : `${FormatCount(Row.ActiveConnections)} 活动`]
                .filter(Boolean).join(' · ');
            return <Link key={Row.Id} to={WithTime(`/ingresses?ingress=${encodeURIComponent(Row.Id)}`, Input.Params)}>
                <span><strong>{Row.Transport.toUpperCase()}</strong><code>{Row.ConfiguredAddress}</code></span>
                <StatusBadge Label={Presentation.Label} Tone={Presentation.Tone} />
                <small>{Detail}</small>
            </Link>;
        })}</div>
        <p className="field-hint">{Input.HasMore
            ? `当前显示前 ${Input.Rows.length} 条入口配置，仍有更多记录。`
            : `当前返回 ${Input.Rows.length} 条入口配置；同一传输的后续配置行不代表独立 socket。`}</p>
    </>;
}

function AccountSummary(Input: Readonly<{ Rows: readonly AccountRecord[] }>): ReactNode {
    if (!Input.Rows.length) return <EmptyState Title="没有账户记录" Detail="配置账户后显示使用情况。" />;
    return <div className="table-scroll"><table className="data-table"><thead>
        <tr><th>账户</th><th>用户组</th><th>根连接租约</th><th>累计上行</th><th>累计下行</th><th>状态</th></tr>
    </thead><tbody>{Input.Rows.map(Row => <tr key={Row.Id}>
        <td><Link className="table-link" to={`/accounts?account=${encodeURIComponent(Row.Id)}`}>
            <strong>{Row.Label}</strong><small>{Row.Id}</small></Link></td>
        <td>{Row.GroupId ?? '未分组'}</td><td>{FormatCount(Row.ActiveSessions)}</td>
        <td>{FormatBytes(Row.Traffic?.Up)}</td><td>{FormatBytes(Row.Traffic?.Down)}</td>
        <td><StatusBadge Label={Row.Revoked ? '已撤销' : '有效'} Tone={Row.Revoked ? 'danger' : 'good'} /></td>
    </tr>)}</tbody></table></div>;
}

function ResourceSummary(Input: Readonly<{ Value: OverviewSnapshot }>): ReactNode {
    const Memory = Input.Value.Memory;
    const Observations = Input.Value.Observations;
    return <>
        <dl className="detail-kv">
            <div><dt>进程 RSS</dt><dd>{AvailableBytes(Memory.ProcessAvailable, Memory.ProcessRssBytes)}</dd></div>
            <div><dt>Prism PMR</dt><dd>{AvailableBytes(Memory.Allocations.Available, Memory.Allocations.CurrentBytes)}</dd></div>
            <div><dt>BytePool</dt><dd>{AvailableBytes(Memory.BytePool.Available, Memory.BytePool.UsedBytes)} / {AvailableBytes(Memory.BytePool.Available, Memory.BytePool.CapacityBytes)}</dd></div>
        </dl>
        <BytePoolUsage Available={Memory.BytePool.Available} UsedBytes={Memory.BytePool.UsedBytes}
            CapacityBytes={Memory.BytePool.CapacityBytes} />
        <div className="quality-summary"><span>观测丢弃 <b>{FormatCount(Observations.Dropped)}</b></span>
            <span>聚合失败 <b>{FormatCount(Observations.AggregationFailures)}</b></span></div>
        <p className="field-hint">累计计数；丢失不代表真实字节量，历史缺口另行标记。</p>
    </>;
}

function BytePoolUsage(Input: Readonly<{
    Available: boolean; UsedBytes: OverviewSnapshot['Memory']['BytePool']['UsedBytes'];
    CapacityBytes: OverviewSnapshot['Memory']['BytePool']['CapacityBytes'];
}>): ReactNode {
    const Usage = DecideBytePoolUsage(Input.Available, Input.UsedBytes, Input.CapacityBytes);
    if (Usage.State === 'available' && Usage.Value !== null)
        return <ProgressBar Value={Usage.Value} Tone="mint" Label="BytePool 使用率" />;
    const Detail = Usage.State === 'unavailable' ? 'BytePool 使用率未采集。'
        : Usage.State === 'zero-capacity' ? 'BytePool 容量为 0，无法计算使用率。'
            : Usage.State === 'missing' ? 'BytePool 使用量或容量未采集。' : 'BytePool 使用率不可用。';
    return <p className="field-hint">{Detail}</p>;
}

function EventPreview(Input: Readonly<{ Value: EventRecord }>): ReactNode {
    const Value = Input.Value;
    const Path = Value.OperationId && Value.OperationId !== '0'
        ? `/operations?operation=${encodeURIComponent(Value.OperationId)}`
        : Value.SessionId && Value.SessionId !== '0'
            ? `/sessions?${new URLSearchParams({ session: Value.SessionId, process: Value.ProcessId,
                generation: Value.GenerationId, identity_worker: Value.WorkerId ?? '',
                identity_account: Value.AccountId ?? '' })}`
            : '/events';
    return <Link className={`overview-event severity-${Value.Severity}`} to={Path}>
        <span className="event-severity-dot" aria-hidden="true" />
        <div><strong><small className="event-inline-severity">{Value.Severity === 'error' ? '错误'
            : Value.Severity === 'warning' ? '告警' : '信息'}</small>{Value.Message}</strong>
            <p>{Value.Detail || `${Value.Scope} · ${Value.Kind}`}</p></div>
        <time dateTime={Value.Time}>{FormatTime(Value.Time)}</time>
    </Link>;
}

function SafeMetricNumber(Value: UInt64Value | null): number {
    if (Value === null) return 0;
    try {
        const Parsed = BigInt(Value);
        return Parsed > 0n ? Number(Parsed) : 0;
    } catch { return 0; }
}

function Nonzero(Value: UInt64Value | null | undefined): boolean {
    if (Value === null || Value === undefined) return false;
    try { return BigInt(Value) > 0n; } catch { return false; }
}

function HealthReading(Value: string): string {
    if (Value === 'degraded') return '存在告警';
    if (Value === 'unhealthy') return '运行异常';
    if (Value === 'draining') return '正在排空';
    if (Value === 'sampling-failed') return '采样失败';
    return '等待采样';
}

function QueryStatus(Pending: boolean, ErrorValue: Error | null | undefined, HasData: boolean): OverviewQueryState {
    if (ErrorValue) return 'error';
    return Pending || !HasData ? 'pending' : 'success';
}
