import { TimeLink as Link } from '../TimeLink';
import type { ReactNode } from 'react';

import { FormatCount, PageHeader, Panel, QueryState, ProgressBar } from '../../Components/Ui';
import { useAdminQuery } from '../UseOperations';
import { TimeRangeControl } from '../TimeRange';
import { HistoryPanel } from '../HistoryPanel';
import type { UInt64Value } from '../../Services/AdminDataSource';
import { WorkerTargetPath } from '../Workers/WorkerIdentity';
import { AvailableBytes as Bytes, AvailableCount as Count, DecideBytePoolUsage } from './ResourceAvailability';

export default function ResourcesPage(): ReactNode {
    const Query = useAdminQuery('overview', Source => Source.GetOverview());
    const Snapshot = Query.data;
    const Memory = Snapshot?.Memory, Observations = Snapshot?.Observations;
    return <><PageHeader Title="资源与数据质量" Description="区分进程内存、受追踪分配和池容量，同时核对观测是否完整。" Actions={<TimeRangeControl />} />
        <QueryState Pending={Query.isPending} Error={Query.error} HasData={Query.data !== undefined} Label="资源快照" Children={Snapshot && Memory && Observations ? <>
            <div className="page-metric-strip"><div className="page-metric"><span>进程 RSS</span><strong>{Bytes(Memory.ProcessAvailable, Memory.ProcessRssBytes)}</strong><small>峰值 {Bytes(Memory.ProcessAvailable, Memory.ProcessPeakRssBytes)}</small></div>
                <div className="page-metric"><span>Prism PMR</span><strong>{Bytes(Memory.Allocations.Available, Memory.Allocations.CurrentBytes)}</strong><small>仅受追踪分配</small></div>
                <div className="page-metric"><span>BytePool</span><strong>{Bytes(Memory.BytePool.Available, Memory.BytePool.UsedBytes)}</strong><small>容量 {Bytes(Memory.BytePool.Available, Memory.BytePool.CapacityBytes)}</small></div>
                <div className="page-metric"><span>观测丢弃 / 聚合失败</span><strong>{FormatCount(Observations.Dropped)} / {FormatCount(Observations.AggregationFailures)}</strong><small>累计事件数量，不是丢失字节</small></div></div>
            <div className="analysis-split"><Panel Title="内存覆盖与容量"><dl className="detail-kv">
                <div><dt>进程工作集</dt><dd>{Bytes(Memory.ProcessAvailable, Memory.WorkingSetBytes)}</dd></div><div><dt>PMR 分配 / 释放</dt><dd>{Count(Memory.Allocations.Available, Memory.Allocations.AllocationCount)} / {Count(Memory.Allocations.Available, Memory.Allocations.ReleaseCount)}</dd></div>
                <div><dt>PMR 覆盖</dt><dd>{Memory.Allocations.Coverage}</dd></div><div><dt>BytePool 峰值</dt><dd>{Bytes(Memory.BytePool.Available, Memory.BytePool.PeakUsedBytes)}</dd></div></dl>
                {BytePoolUsage(Memory.BytePool.Available, Memory.BytePool.UsedBytes, Memory.BytePool.CapacityBytes)}
            </Panel><Panel Title="观测完整性"><dl className="detail-kv"><div><dt>已入队观测</dt><dd>{FormatCount(Observations.Accepted)}</dd></div><div><dt>已消费观测</dt><dd>{FormatCount(Observations.Consumed)}</dd></div>
                <div><dt>入队丢弃</dt><dd>{FormatCount(Observations.Dropped)}</dd></div><div><dt>聚合失败</dt><dd>{FormatCount(Observations.AggregationFailures)}</dd></div></dl>
                <p className="field-hint">独立累计计数的差值不代表精确队列长度；观测丢失影响分析覆盖，不改变账户额度账本。</p></Panel></div>
            <Panel Title="Worker 受追踪分配"><div className="table-scroll"><table className="data-table"><thead><tr><th>Worker</th><th>当前</th><th>峰值</th><th>分配次数</th><th>释放次数</th><th>覆盖</th></tr></thead>
                <tbody>{Memory.WorkerAllocations.length === 0
                    ? <tr><td colSpan={6}>当前快照没有可列出的 Worker 分配记录。</td></tr>
                    : Memory.WorkerAllocations.map(Row => <tr key={Row.WorkerId}><td><Link className="text-link" to={WorkerTargetPath('workers', {
                        Id: Row.WorkerId, ProcessId: Snapshot.Process.Id, GenerationId: Snapshot.Process.GenerationId,
                    })}>{Row.WorkerId}</Link></td>
                    <td>{Bytes(Row.Allocation.Available, Row.Allocation.CurrentBytes)}</td><td>{Bytes(Row.Allocation.Available, Row.Allocation.PeakBytes)}</td>
                    <td>{Count(Row.Allocation.Available, Row.Allocation.AllocationCount)}</td><td>{Count(Row.Allocation.Available, Row.Allocation.ReleaseCount)}</td><td>{Row.Allocation.Coverage}</td></tr>)}</tbody></table></div></Panel>
        </> : null} />
        <div className="analysis-split"><HistoryPanel Scope="process" Title="进程流量与压力窗口" /><HistoryPanel Scope="process" Kind="latency" /></div>
    </>;
}

function BytePoolUsage(
    Available: boolean,
    UsedBytes: UInt64Value | null,
    CapacityBytes: UInt64Value | null,
): ReactNode {
    const Usage = DecideBytePoolUsage(Available, UsedBytes, CapacityBytes);
    if (Usage.State === 'unavailable') return <p className="field-hint">BytePool 使用率未采集。</p>;
    if (Usage.State === 'missing') return <p className="field-hint">BytePool 使用量或容量未采集，无法计算使用率。</p>;
    if (Usage.State === 'zero-capacity') return <p className="field-hint">BytePool 容量为 0，无法计算使用率。</p>;
    if (Usage.State === 'invalid' || Usage.Value === null) return <p className="field-hint">BytePool 使用率不可用。</p>;
    return <ProgressBar Value={Usage.Value} Tone="mint" Label="BytePool 使用率" />;
}
