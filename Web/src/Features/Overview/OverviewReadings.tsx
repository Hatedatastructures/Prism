import type { ReactNode } from 'react';
import { ArrowRight } from 'lucide-react';
import { TimeLink as Link } from '../TimeLink';
import { FormatCount, FormatRate, MeasureValue } from '../../Components/Ui';
import { AvailableBytes } from '../Resources/ResourceAvailability';
import type { OverviewSnapshot } from '../../Services/AdminDataSource';

/** @brief 展示当前快照中的上下行速率，与历史窗口数据分开呈现。 */
export function TrafficReadings(Input: Readonly<{ Value: OverviewSnapshot }>): ReactNode {
    const Traffic = Input.Value.Traffic;
    const DownRate = Traffic.Available && Traffic.DownBytesPerSecond !== null
        ? FormatRate(Traffic.DownBytesPerSecond) : '未采集';
    const UpRate = Traffic.Available && Traffic.UpBytesPerSecond !== null
        ? FormatRate(Traffic.UpBytesPerSecond) : '未采集';
    return <div className="overview-live-rates">
        <div className="snapshot-rate"><dl><dt>下行速率</dt><dd><MeasureValue Value={DownRate} /></dd></dl><span>当前快照 · 有效载荷</span></div>
        <div className="snapshot-rate"><dl><dt>上行速率</dt><dd><MeasureValue Value={UpRate} /></dd></dl><span>当前快照 · 有效载荷</span></div>
    </div>;
}

/** @brief 展示快照中的活动 TCP Session 与 UDP、QUIC 连接数。 */
export function ConnectionsSummary(Input: Readonly<{ Value: OverviewSnapshot }>): ReactNode {
    const Counts = Input.Value.Counts;
    return <section className="overview-connections-v2 snapshot-reading">
        <div className="snapshot-reading-heading"><h2>连接活动</h2><Link to="/sessions" aria-label="查看连接"><ArrowRight size={14} aria-hidden="true" /></Link></div>
        <div className="connection-reading">
            <strong>{FormatCount(Counts.TcpSessions)}</strong>
            <span>TCP Session</span>
        </div>
        <dl className="connection-protocols">
            <div><dt>UDP</dt><dd>{Counts.UdpConnections === null
                ? '未采集' : FormatCount(Counts.UdpConnections)}</dd></div>
            <div><dt>QUIC</dt><dd>{Counts.QuicConnections === null
                ? '未采集' : FormatCount(Counts.QuicConnections)}</dd></div>
        </dl>
    </section>;
}

/** @brief 进程当前 RSS 的独立读数；缺测继续显式呈现，不与受追踪分配相加。 */
export function MemoryReading(Input: Readonly<{ Value: OverviewSnapshot }>): ReactNode {
    const Memory = Input.Value.Memory;
    return <section className="snapshot-reading snapshot-memory">
        <div className="snapshot-reading-heading"><h2>进程 RSS</h2><Link to="/resources" aria-label="查看资源分析"><ArrowRight size={14} aria-hidden="true" /></Link></div>
        <strong><MeasureValue Value={AvailableBytes(Memory.ProcessAvailable, Memory.ProcessRssBytes)} /></strong>
        <span>进程驻留内存</span>
    </section>;
}
