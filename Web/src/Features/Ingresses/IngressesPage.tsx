import type { ReactNode } from 'react';
import { useSearchParams } from 'react-router';
import { CheckCircle2, Radio, Router, Waypoints } from 'lucide-react';
import { Badge, EmptyState, FormatCount, LoadMoreButton, PageHeader, Panel, QueryState, StatusBadge } from '../../Components/Ui';
import type { IngressRecord } from '../../Services/AdminDataSource';
import { useAdminInfiniteQuery } from '../UseOperations';
import { TimeRangeControl } from '../TimeRange';
import { HistoryPanel } from '../HistoryPanel';
import { DecideIngressRowPresentation, PresentIngressRows } from './IngressPresentation';

export default function IngressesPage(): ReactNode {
    const [Params, SetParams] = useSearchParams();
    const FocusId = Params.get('ingress') ?? '';
    const Query = useAdminInfiniteQuery('ingresses', (Source, Page) => Source.GetIngresses(Page));
    const Rows = Query.data?.pages.flatMap(Page => Page.Items) ?? [];
    const DisplayRows = PresentIngressRows(Rows);
    const RuntimeRows = DisplayRows.filter(Row => Row.HasRuntimeState).map(Row => Row.Value);
    const Ready = RuntimeRows.filter(Row => Row.Ready).length;
    const Bound = RuntimeRows.filter(Row => Row.BoundAddress !== null).length;
    const IsUnavailable = Query.isPending || !!Query.error;
    const SummaryValue = (Value: string): string => Query.isPending ? '…' : Query.error ? '不可用' : Value;
    const Connections = ['tcp', 'udp', 'quic'].map(Transport => {
        if (Query.isPending) return `${Transport.toUpperCase()} …`;
        if (Query.error) return `${Transport.toUpperCase()} 不可用`;
        const Configured = Rows.some(Row => Row.Transport.toLowerCase() === Transport);
        const Matching = RuntimeRows.filter(Row => Row.Transport.toLowerCase() === Transport);
        if (!Matching.length) return `${Transport.toUpperCase()} ${Query.hasNextPage ? '未出现在已载入范围' : Configured ? '未单独观测' : '未配置'}`;
        return `${Transport.toUpperCase()} ${Matching.some(Row => Row.ActiveConnections === null) ? '未采集' : FormatCount(Matching.reduce((Total, Row) => Total + BigInt(Row.ActiveConnections ?? 0), 0n).toString())}`;
    }).join(' · ');
    const Readiness = Query.isPending ? '入口状态载入中' : Query.error ? '入口状态不可用'
        : RuntimeRows.length === 0 ? '没有已观测 listener' : `${Ready} / ${RuntimeRows.length} 已观测 listener 就绪`;
    return <>
        <PageHeader Title="代理入口"
            Description="核对配置监听、实际绑定、承载协议与就绪状态。未返回实际地址时会明确标为未提供。"
            Actions={<><TimeRangeControl /><Badge Tone={!IsUnavailable && RuntimeRows.length > 0 && Ready === RuntimeRows.length ? 'good' : 'neutral'} Dot>{Readiness}</Badge></>} />
        <div className="ingress-summary" aria-label="入口汇总">
            <IngressStat Icon={<Router size={17} />} Label="已配置入口" Value={SummaryValue(FormatCount(Rows.length))}
                Detail={Query.error ? '入口查询失败；不显示旧数据为当前计数' : Query.isPending ? '正在读取配置范围' : `当前已载入 ${Rows.length} 条配置${Query.hasNextPage ? '，仍有更多记录' : ''}`} />
            <IngressStat Icon={<CheckCircle2 size={17} />} Label="已返回绑定地址" Value={SummaryValue(FormatCount(Bound))}
                Detail="每种传输仅首行提供实际 listener 状态" />
            <IngressStat Icon={<Radio size={17} />} Label="按传输活动量" Value={Connections} Detail="只使用每种传输的首条运行态行；连接、关联和子流各自统计" />
        </div>
        <Panel Title="监听清单" Subtitle="配置地址与运行时绑定地址不是同一字段">
            {FocusId && <div className="active-filter-strip"><span>当前定位</span><code>{FocusId}</code>
                <button className="button button-quiet" type="button" onClick={() => SetParams({})}>清除定位</button></div>}
            <QueryState Pending={Query.isPending} Error={Query.error} Label="入口记录" HasData={Query.data !== undefined}
                Children={Rows.length === 0 ? <EmptyState Title="没有入口记录" Detail="当前数据源尚未返回监听配置。" /> : <>
                    <div className="ingress-table-wrap table-scroll">
                        <table className="data-table ingress-table">
                            <thead><tr><th>传输</th><th>配置监听</th><th>实际绑定</th><th>连接数</th><th>代理协议</th><th>状态</th></tr></thead>
                    <tbody>{DisplayRows.map(({ Value, HasRuntimeState }) => <IngressTableRow key={Value.Id} Value={Value} HasRuntimeState={HasRuntimeState} FocusId={FocusId} />)}</tbody>
                        </table>
                    </div>
                    <div className="ingress-mobile-list">{DisplayRows.map(({ Value, HasRuntimeState }) => <IngressMobileCard key={Value.Id} Value={Value} HasRuntimeState={HasRuntimeState} FocusId={FocusId} />)}</div>
                    <LoadMoreButton HasMore={Query.hasNextPage ?? false} Busy={Query.isFetchingNextPage}
                        OnLoad={() => void Query.fetchNextPage()} />
                </>} />
        </Panel>
        {FocusId && <HistoryPanel Scope="ingress" ResourceKey={FocusId} Title={`${FocusId} 接入流量历史`} />}
        <Panel Title="配置覆盖" Subtitle="入口能力来自当前配置快照，不推测未提供的绑定行为" ClassName="page-surface">
            <div className="ingress-capability-grid">
                {Rows.map(Row => <div className="ingress-capability" key={Row.Id}>
                    <div className="ingress-capability-title"><span className={`transport-mark transport-${Row.Transport}`}>{Row.Transport.slice(0, 1).toUpperCase()}</span>
                        <div><strong>{Row.Transport.toUpperCase()}</strong><small>{Row.Id}</small></div></div>
                    <div className="ingress-capability-list"><span><Waypoints size={13} />承载方式</span>
                        <div>{Row.Carriers.length ? Row.Carriers.map(Carrier => <code key={Carrier}>{Carrier}</code>) : <small>未提供</small>}</div>
                        <span>代理协议</span><div>{Row.Protocols.length ? Row.Protocols.map(Protocol => <code key={Protocol}>{Protocol}</code>) : <small>未提供</small>}</div>
                    </div>
                </div>)}
            </div>
        </Panel>
    </>;
}

function IngressStat(Input: Readonly<{ Icon: ReactNode; Label: string; Value: string; Detail: string }>): ReactNode {
    return <div className="ingress-stat group"><span className="ingress-stat-icon">{Input.Icon}</span>
        <div><span>{Input.Label}</span><strong>{Input.Value}</strong><small>{Input.Detail}</small></div></div>;
}

function IngressTableRow(Input: Readonly<{ Value: IngressRecord; HasRuntimeState: boolean; FocusId: string }>): ReactNode {
    const Row = Input.Value;
    const Presentation = DecideIngressRowPresentation(Row, Input.HasRuntimeState);
    return <tr className={Row.Id === Input.FocusId ? 'row-selected' : ''}>
        <td data-label="传输"><span className={`transport-mark transport-${Row.Transport}`}>{Row.Transport.slice(0, 1).toUpperCase()}</span>
            <strong className="ingress-transport-label">{Row.Transport.toUpperCase()}</strong></td>
        <td data-label="配置监听"><span className="endpoint-cell"><small>ConfiguredAddress</small><code>{Row.ConfiguredAddress}</code></span></td>
        <td data-label="实际绑定"><span className="endpoint-cell"><small>BoundAddress</small><code>{Row.BoundAddress ?? '未提供'}</code></span></td>
        <td data-label="活动连接">{Row.ActiveConnections === null ? '未提供' : FormatCount(Row.ActiveConnections)}</td>
        <td data-label="代理协议"><span className="ingress-protocols">{Row.Protocols.length ? Row.Protocols.map(Protocol => <span key={Protocol}>{Protocol}</span>) : '未提供'}</span></td>
        <td data-label="状态"><StatusBadge Label={Presentation.Label} Tone={Presentation.Tone} />{Row.Reason && <small>{Row.Reason}</small>}</td>
    </tr>;
}

function IngressMobileCard(Input: Readonly<{ Value: IngressRecord; HasRuntimeState: boolean; FocusId: string }>): ReactNode {
    const Row = Input.Value;
    const Presentation = DecideIngressRowPresentation(Row, Input.HasRuntimeState);
    return <article className={`ingress-mobile-card ${Row.Id === Input.FocusId ? 'ingress-focused' : ''}`}>
        <div className="ingress-mobile-head"><span className={`transport-mark transport-${Row.Transport}`}>{Row.Transport.slice(0, 1).toUpperCase()}</span>
            <strong>{Row.Transport.toUpperCase()}</strong><StatusBadge Label={Presentation.Label} Tone={Presentation.Tone} /></div>
        <dl><dt>配置监听</dt><dd>{Row.ConfiguredAddress}</dd><dt>实际绑定</dt><dd>{Row.BoundAddress ?? '未提供'}</dd>
            <dt>活动连接</dt><dd>{Row.ActiveConnections === null ? '未提供' : FormatCount(Row.ActiveConnections)}</dd>
            <dt>代理协议</dt><dd>{Row.Protocols.join(' · ') || '未提供'}</dd><dt>承载方式</dt><dd>{Row.Carriers.join(' · ') || '未提供'}</dd>
            {!Input.HasRuntimeState && <><dt>运行态</dt><dd>该传输的后续配置行未单独采集 Ready/绑定/活动量。</dd></>}
            {Row.Reason && <><dt>状态原因</dt><dd>{Row.Reason}</dd></>}</dl>
    </article>;
}
