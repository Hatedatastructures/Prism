import { TimeLink as Link } from '../TimeLink';
import type { ReactNode } from 'react';
import { useSearchParams } from 'react-router';
import { Layers } from 'lucide-react';
import { EmptyState, FormatBytes, FormatCount, LoadMoreButton, PageHeader, Panel, ProgressBar, QueryState } from '../../Components/Ui';
import { ProtocolDistribution } from '../../Api/Analysis';
import type { ProtocolRecord, UInt64Value } from '../../Services/AdminDataSource';
import { useAdminInfiniteQuery, useAdminQuery } from '../UseOperations';
import { HistoryPanel } from '../HistoryPanel';
import { TimeRangeControl, WithTime } from '../TimeRange';

export default function ProtocolsPage(): ReactNode {
    const [Params, SetParams] = useSearchParams();
    const Overview = useAdminQuery('overview', Source => Source.GetOverview());
    const Query = useAdminInfiniteQuery('protocols', (Source, Page) => Source.GetProtocols ? Source.GetProtocols(Page) :
        Source.GetOverview().then(Value => ({ Items: Value.Protocols, NextCursor: '0', HasMore: false })));
    const Rows = Query.data?.pages.flatMap(Page => Page.Items) ?? [];
    const SelectedId = Params.get('protocol') ?? '';
    const ListedTarget = Query.isSuccess ? Rows.find(Row => Row.Id === SelectedId) ?? null : null;
    const OverviewTarget = Overview.isSuccess ? Overview.data?.Protocols.find(Row => Row.Id === SelectedId) ?? null : null;
    const Selected = SelectedId ? ListedTarget ?? OverviewTarget : Query.isSuccess ? Rows[0] ?? null : null;
    return <><PageHeader Title="协议分析" Description="分别查看代理协议、配置实例与统计覆盖，传输和承载保持独立。" Actions={<TimeRangeControl />} />
        <div className="analysis-split"><Panel Title="活动 TCP Session 协议分布" Subtitle="当前快照 · 同一类型只归集一次">
            {Overview.data ? <ProtocolShare Rows={Overview.data.Protocols} Total={Overview.data.Counts.TcpSessions} /> : <QueryState Pending={Overview.isPending} Error={Overview.error} HasData={false} Label="协议分布" Children={null} />}
        </Panel><Panel Title="统计口径"><div className="explanation-list">
            <p><Layers size={16} />协议类型与配置实例分别定位。TCP、QUIC 连接、UDP 关联、Mux 子流不能作为一个分母相加。</p>
            <p>当前占比使用活动 TCP Session；窗口流量使用相同方向与覆盖。未识别、未归属和缺测始终保留。</p>
            <p>类型统计不能重复累计到多个实例；未提供实例归属时不计算实例流量占比。</p>
        </div></Panel></div>
        <Panel Title="协议与配置实例" Subtitle="标明类型共享统计，只有实际归属的实例数据才表示实例用量">
            <QueryState Pending={Query.isPending} Error={Query.error} HasData={Query.data !== undefined} Label="协议实例" Children={Rows.length ? <>
                <div className="table-scroll" tabIndex={0}><table className="data-table"><thead><tr><th>实例 / 协议</th><th>绑定</th><th>活动 Session</th><th>累计上行</th><th>累计下行</th><th>统计覆盖</th></tr></thead>
                    <tbody>{Rows.map(Row => <tr key={Row.Id} className={Row.Id === Selected?.Id ? 'row-selected' : ''}>
                        <td><button className="table-link" type="button" onClick={() => { const Next = new URLSearchParams(Params); Next.set('protocol', Row.Id); SetParams(Next); }}><strong>{Row.Name}</strong><small>{Row.Id}</small></button></td>
                        <td>{FormatCount(Row.ConfiguredBindings)}</td><td>{Row.Kind === 'instance' ? FormatCount(Row.ActiveSessions) : `类型共享 ${FormatCount(Row.ActiveSessions)}`}</td><td>{Row.Kind === 'instance' ? FormatBytes(Row.Traffic?.Up) : `类型共享 ${FormatBytes(Row.Traffic?.Up)}`}</td><td>{Row.Kind === 'instance' ? FormatBytes(Row.Traffic?.Down) : `类型共享 ${FormatBytes(Row.Traffic?.Down)}`}</td><td className="coverage-cell">{Row.Kind === undefined ? '实例独立统计未提供；' : ''}{Row.Coverage}</td>
                    </tr>)}</tbody></table></div><LoadMoreButton HasMore={Query.hasNextPage} Busy={Query.isFetchingNextPage} OnLoad={() => void Query.fetchNextPage()} />
            </> : <EmptyState Title="没有配置协议实例" Detail="配置并发布协议绑定后显示在此。" />} />
        </Panel>
        {Selected ? <><div className="detail-links"><Link to={WithTime(`/sessions?protocol=${encodeURIComponent(Selected.Name)}`, Params)}>相关连接</Link><Link to={WithTime('/ingresses', Params)}>入口与承载</Link></div>
            <div className="analysis-split"><HistoryPanel Scope="protocol_type" ResourceKey={Selected.Name} Title={`${Selected.Name} 类型流量`} />
                <HistoryPanel Scope="protocol_instance" ResourceKey={Selected.Id} Title={`${Selected.Id} 实例流量`} /></div></>
            : SelectedId ? <Panel Title="指定协议核验">
                {Query.isPending || Overview.isPending ? <EmptyState Title="正在核对协议范围" Detail={`当前尚未确认 ${SelectedId} 是否存在。`} />
                    : Query.error || Overview.error ? <EmptyState Title="无法确认指定协议" Detail={`当前查询失败；未将 ${SelectedId} 替换为其他协议。`} />
                    : Query.hasNextPage ? <EmptyState Title="目标不在当前已载入页" Detail={`${SelectedId} 尚未在已载入记录中出现；继续载入后再确认。`} />
                    : <EmptyState Title="当前协议快照未返回此 ID" Detail={`${SelectedId} 未出现在完整已载入清单或 Overview 快照中；未选择其他实例替代。`} />}
            </Panel> : null}
    </>;
}
export function ProtocolShare(Input: Readonly<{ Rows: readonly ProtocolRecord[]; Total: UInt64Value }>): ReactNode {
    const Distribution = ProtocolDistribution(Input.Rows, Input.Total);
    if (!Distribution.Available) return <EmptyState Title="类型分布尚未提供" Detail="当前只返回实例记录，不将实例统计冒充类型占比。" />;
    if (BigInt(Input.Total) === 0n) return <EmptyState Title="当前没有活动 TCP Session" Detail="接入后按实际协议统计，零连接不显示虚构占比。" />;
    if (!Distribution.Complete) return <div className="notice notice-warning">协议分项超过当前总量，快照范围不一致，暂不计算占比。</div>;
    return <><div className="protocol-share">{Distribution.Rows.map(Row => <div className="protocol-share-row" key={Row.Id} data-protocol={Row.Name.toLowerCase()}>
        <span><strong>{Row.Name}</strong><small>{FormatCount(Row.Count)} 条</small></span>
        <ProgressBar Value={Row.Percent ?? 0} Tone="mint" Label={`${Row.Name} 占比`} /><b>{Row.Percent === null ? '—' : `${Row.Percent.toFixed(1)}%`}</b>
    </div>)}</div><p className="field-hint">分母 {FormatCount(Input.Total)} 个活动 TCP Session{Distribution.DuplicateTypes ? ' · 已合并共享类型统计，实例归属需独立采集' : ''}</p></>;
}
