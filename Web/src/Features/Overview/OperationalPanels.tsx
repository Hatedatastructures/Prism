import { TimeLink as Link } from '../TimeLink';
import type { ReactNode } from 'react';
import { ArrowDown, ArrowRight, ArrowUp, UserRound, Users } from 'lucide-react';

import { EmptyState, FormatBytes, FormatCount, Panel, ProgressBar, QueryState, StatusBadge, TrendMini } from '../../Components/Ui';
import type { IngressRecord, OverviewSnapshot, SessionRecord, UInt64Value } from '../../Services/AdminDataSource';
import { BuildTrafficSeries } from './TrafficChart';

/** @brief 首屏只使用已有的管理计数；累计错误不换算为请求失败率。 */
export function OperationalMetrics(Input: Readonly<{ Snapshot: OverviewSnapshot }>): ReactNode {
    const Value = Input.Snapshot;
    const Points = BuildTrafficSeries(Value.History);
    return <section className="operational-metrics" aria-label="核心运行指标">
        <OperationalMetric Label="活动 TCP 会话" Value={FormatCount(Value.Counts.TcpSessions)} Path="/sessions"
            Icon={<Users size={21} />} Tone="sessions" Trend={Value.TcpSessionHistory.map(Sample => Number(Sample.Count))}
            Detail={`UDP ${OptionalCount(Value.Counts.UdpConnections)} · QUIC ${OptionalCount(Value.Counts.QuicConnections)}`} />
        <OperationalMetric Label="当前下行" Value={RateLabel(Value.Traffic.Available, Value.Traffic.DownBytesPerSecond)}
            Icon={<ArrowDown size={20} />} Trend={LatestRun(Points.map(Point => Point.Down))}
            Detail={`累计 ${Value.Traffic.Available ? FormatBytes(Value.Traffic.DownBytes) : '未提供'}`} Tone="down" />
        <OperationalMetric Label="当前上行" Value={RateLabel(Value.Traffic.Available, Value.Traffic.UpBytesPerSecond)}
            Icon={<ArrowUp size={20} />} Trend={LatestRun(Points.map(Point => Point.Up))}
            Detail={`累计 ${Value.Traffic.Available ? FormatBytes(Value.Traffic.UpBytes) : '未提供'}`} Tone="up" />
        <OperationalMetric Label="活跃账户" Value={`${FormatCount(Value.Counts.ActiveAccounts)} / ${FormatCount(Value.Counts.ConfiguredAccounts)}`}
            Icon={<UserRound size={21} />} Path="/accounts" Detail={`已配置 ${FormatCount(Value.Counts.ConfiguredAccounts)} 个代理账户`} />
    </section>;
}

export function OperationalSignals(Input: Readonly<{ Snapshot: OverviewSnapshot }>): ReactNode {
    const Value = Input.Snapshot;
    return <div className="operational-signals" role="group" aria-label="关键服务信号">
        <Link to="/workers"><span>接收中 Worker</span><strong>{FormatCount(Value.Counts.WorkersAccepting)} / {FormatCount(Value.Counts.WorkersTotal)}</strong><ArrowRight size={12} /></Link>
        <Link to="/events?severity=error"><span>累计数据面错误</span><strong className={Nonzero(Value.Traffic.Errors) ? 'counter-warning' : ''}>
            {Value.Traffic.Available ? FormatCount(Value.Traffic.Errors) : '未提供'}</strong></Link>
        <Link to="/events"><span>观测入队丢弃</span><strong className={Nonzero(Value.Observations.Dropped) ? 'counter-warning' : ''}>{FormatCount(Value.Observations.Dropped)}</strong></Link>
    </div>;
}

function OperationalMetric(Input: Readonly<{
    Label: string; Value: string; Detail: string; Icon: ReactNode; Path?: string; Tone?: string; Trend?: readonly number[];
}>): ReactNode {
    const [NumberLabel, Unit] = Input.Value.includes('/s') ? Input.Value.split(' ') : [Input.Value];
    const Content = <><span className="operational-label">{Input.Label}<i aria-hidden="true">{Input.Icon}</i></span>
        <strong>{NumberLabel}{Unit && <span>{Unit}</span>}</strong>
        {Input.Trend && <TrendMini Values={Input.Trend} Tone={Input.Tone === 'up' ? 'blue' : 'accent'} Label={`${Input.Label} · 最近采样趋势`} />}
        <small>{Input.Detail}</small></>;
    const ClassName = `operational-metric operational-${Input.Tone ?? ''}`;
    return Input.Path ? <Link className={ClassName} to={Input.Path}>{Content}</Link> : <div className={ClassName}>{Content}</div>;
}

function OptionalCount(Value: UInt64Value | null): string { return Value === null ? '未提供' : FormatCount(Value); }

function RateLabel(Available: boolean, Value: UInt64Value | null): string {
    if (!Available || Value === null) return '未提供';
    const Bytes = BigInt(Value);
    const MiB = Number(Bytes / 1_048_576n) + Number(Bytes % 1_048_576n) / 1_048_576;
    if (Bytes > 0n && MiB < .01) return `${FormatBytes(Value, 2)}/s`;
    return `${MiB.toFixed(2)} MiB/s`;
}

/** @brief 小趋势只绘制最后一段连续采样，累计计数重置不连线。 */
function LatestRun(Values: readonly (number | null)[]): number[] {
    const Start = Values.findLastIndex(Value => Value === null);
    return Values.slice(Start + 1).filter((Value): Value is number => Value !== null && Number.isFinite(Value));
}

/** @brief 保留大整数精度，仅用已存在的非负管理计数进行求和。 */
export function SumCounters(Values: readonly UInt64Value[]): string {
    return Values.reduce<bigint>((Total, Value) => Total + BigInt(Value), 0n).toString();
}

export function Nonzero(Value: UInt64Value | null): boolean { return Value !== null && BigInt(Value) > 0n; }

export function IngressStatusPanel(Input: Readonly<{
    Rows: readonly IngressRecord[]; Snapshot: OverviewSnapshot; Pending: boolean; Error: Error | null; HasMore: boolean;
}>): ReactNode {
    const Health = Input.Snapshot.Health;
    const Admission = Input.Snapshot.Latency.RecognitionAdmission;
    const QuicStage = !Health.QuicSocketReady ? 'QUIC socket 未就绪'
        : !Health.QuicHandshakeReady ? 'QUIC 握手未就绪' : !Health.QuicProtocolReady ? 'QUIC 协议未就绪' : 'QUIC 接入已就绪';
    return <Panel Title="入口状态" ClassName="dashboard-ingresses"
        Action={<Link className="text-link" to="/ingresses">入口详情 <ArrowRight size={12} /></Link>}>
        <QueryState Pending={Input.Pending} Error={Input.Error} Label="入口状态" HasData={Input.Rows.length > 0}
            Children={Input.Rows.length === 0 ? <EmptyState Title="没有入口数据" Detail="当前数据源没有返回入口。" /> : <>
                <div className="dashboard-table-scroll"><table className="data-table ingress-compact-table">
                    <thead><tr><th>入口</th><th>实际监听地址</th><th>活动连接</th><th>状态</th></tr></thead>
                    <tbody>{Input.Rows.slice(0, 4).map(Row => <tr key={Row.Id}>
                        <td><Link className="table-link" to={`/ingresses?ingress=${encodeURIComponent(Row.Id)}`}>{Row.Transport.toUpperCase()}</Link></td>
                        <td title={`配置地址 ${Row.ConfiguredAddress}`}><code>{Row.BoundAddress ?? '未提供'}</code></td>
                        <td>{OptionalCount(Row.ActiveConnections)}</td>
                        <td><StatusBadge Label={Row.Ready ? '就绪' : '未就绪'} Tone={Row.Ready ? 'good' : 'warning'} /></td>
                    </tr>)}</tbody>
                </table></div>
                {(Input.HasMore || Input.Rows.length > 4) && <p className="dashboard-table-note">已载入 {Input.Rows.length}{Input.HasMore ? '+' : ''} 个入口 · 展示前 4 个</p>}
            </>} />
        <div className="ingress-runtime-peek">
            <div><span>入口已就绪</span><strong>{Input.Rows.length === 0 && (Input.Pending || Input.Error) ? '—' : <>{FormatCount(Input.Rows.filter(Row => Row.Ready).length)} <small>/ {Input.Rows.length}{Input.HasMore ? '+' : ''}</small></>}</strong></div>
            <Link to="/?view=resources"><span>识别准入 P95</span><strong>{Admission.Available && Admission.P95Ms !== null ? Admission.P95Ms : '—'} <small>ms</small></strong></Link>
            <Link to="/?view=resources"><span>进程 RSS</span><strong>{Input.Snapshot.Memory.ProcessAvailable ? FormatBytes(Input.Snapshot.Memory.ProcessRssBytes) : '未提供'}</strong></Link>
        </div>
        <details className="readiness-details"><summary><span>{QuicStage}</span><span>接入能力详情</span></summary>
        <div className="readiness-chain" role="group" aria-label="进程接入能力就绪状态">
            <span>UDP socket <Readiness Ready={Health.UdpSocketReady} /></span>
            <span>QUIC socket <Readiness Ready={Health.QuicSocketReady} /></span>
            <span>QUIC 握手 <Readiness Ready={Health.QuicHandshakeReady} /></span>
            <span>QUIC 协议 <Readiness Ready={Health.QuicProtocolReady} /></span>
        </div>
        </details>
    </Panel>;
}

function Readiness(Input: Readonly<{ Ready: boolean }>): ReactNode {
    return <strong className={Input.Ready ? 'counter-good' : 'counter-warning'}>{Input.Ready ? '就绪' : '未就绪'}</strong>;
}

export function ResourcePressurePanel(Input: Readonly<{ Snapshot: OverviewSnapshot }>): ReactNode {
    const Memory = Input.Snapshot.Memory;
    const Pool = Memory.BytePool;
    const Observation = Input.Snapshot.Observations;
    const Backlog = BigInt(Observation.Accepted) - BigInt(Observation.Consumed);
    const PoolPercent = Pool.Available && Pool.UsedBytes !== null && Pool.CapacityBytes !== null && BigInt(Pool.CapacityBytes) > 0n
        ? Number(BigInt(Pool.UsedBytes) * 10_000n / BigInt(Pool.CapacityBytes)) / 100 : null;
    return <Panel Title="资源与观测完整性" ClassName="dashboard-resources"
        Action={<Link className="text-link" to="/?view=resources">详细分析 <ArrowRight size={12} /></Link>}>
        <dl className="runtime-facts">
            <div><dt>进程 RSS</dt><dd>{Memory.ProcessAvailable ? FormatBytes(Memory.ProcessRssBytes) : '未提供'}
                <small>峰值 {Memory.ProcessAvailable ? FormatBytes(Memory.ProcessPeakRssBytes) : '—'}</small></dd></div>
            <div><dt>Prism PMR</dt><dd title={Memory.Allocations.Coverage}>{Memory.Allocations.Available ? FormatBytes(Memory.Allocations.CurrentBytes) : '未提供'}
                <small>峰值 {Memory.Allocations.Available ? FormatBytes(Memory.Allocations.PeakBytes) : '—'}</small></dd></div>
            <div><dt>BytePool</dt><dd>{Pool.Available ? `${FormatBytes(Pool.UsedBytes)} / ${FormatBytes(Pool.CapacityBytes)}` : '未提供'}
                {PoolPercent !== null && <small>{PoolPercent.toFixed(1)}%</small>}</dd></div>
        </dl>
        {PoolPercent !== null && <ProgressBar Value={PoolPercent} Tone={PoolPercent >= 80 ? 'warning' : 'mint'} Label="BytePool 使用率" />}
        <div className="observation-facts" role="group" aria-label="观测管线计数">
            <div><span>队列待消费</span><strong>{Backlog >= 0n ? FormatCount(Backlog.toString()) : '跨采样不可比'}</strong></div>
            <div><span>入队丢弃</span><strong className={Nonzero(Observation.Dropped) ? 'counter-warning' : ''}>{FormatCount(Observation.Dropped)}</strong></div>
            <div><span>聚合失败</span><strong className={Nonzero(Observation.AggregationFailures) ? 'counter-warning' : ''}>{FormatCount(Observation.AggregationFailures)}</strong></div>
        </div>
        <p className="dashboard-table-note">观测为累计计数；待消费 = 已接收 − 已消费</p>
    </Panel>;
}

export function SessionFocusPanel(Input: Readonly<{
    Rows: readonly SessionRecord[]; Pending: boolean; Error: Error | null; HasMore: boolean;
}>): ReactNode {
    const Current = Input.Rows.filter(Value => Value.Active || Value.Draining);
    const Active = Input.Rows.filter(Value => Value.Active).length;
    const Draining = Current.filter(Value => Value.Draining).length;
    const Rows = [...Current].sort((Left, Right) => Number(Right.Draining) - Number(Left.Draining)).slice(0, 4);
    return <Panel Title="当前连接" ClassName="dashboard-sessions"
        Action={<Link className="text-link" to="/sessions">全部追踪 <ArrowRight size={12} /></Link>}>
        <QueryState Pending={Input.Pending} Error={Input.Error} Label="连接快照" HasData={Input.Rows.length > 0}
            Children={Rows.length === 0 ? <EmptyState Title="暂无活动连接" Detail="新连接将出现在这里。" /> : <>
                <div className="dashboard-table-scroll" role="region" aria-label="当前连接表，可横向滚动" tabIndex={0}><table className="data-table session-compact-table">
                    <thead><tr><th>Session / 协议</th><th>账户</th><th>Worker</th><th>目标地址</th><th>状态</th></tr></thead>
                    <tbody>{Rows.map(Row => <tr key={[Row.ProcessId, Row.GenerationId, Row.WorkerId, Row.AccountId, Row.Id].join(':')}>
                        <td><Link className="table-link" to={SessionPath(Row)}>{Row.Id}</Link><small>{Row.Protocol}</small></td>
                        <td>{Row.Identity}</td><td>{Row.WorkerId}</td><td><code>{Row.Target || '未提供'}</code></td>
                        <td><StatusBadge Label={Row.Draining ? '排空中' : '活动中'} Tone={Row.Draining ? 'warning' : 'good'} /></td>
                    </tr>)}</tbody>
                </table></div>
                <p className="dashboard-table-note"><span className="dashboard-scroll-hint">横向滑动查看目标地址和连接状态。</span>
                    已载入 {Input.Rows.length}{Input.HasMore ? '+' : ''} 条 · 活动 {Active} · 排空 {Draining} · 排空优先展示</p>
            </>} />
    </Panel>;
}

/** @brief 深链保留完整复合身份，避免跨 Worker 或代次同名连接被误选。 */
function SessionPath(Value: SessionRecord): string {
    const Params = new URLSearchParams({ session: Value.Id, process: Value.ProcessId, generation: Value.GenerationId,
        identity_worker: Value.WorkerId, identity_account: Value.AccountId });
    return `/sessions?${Params}`;
}
