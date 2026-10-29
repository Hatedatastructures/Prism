import type { ReactNode } from 'react';
import { ArrowRight } from 'lucide-react';
import { NavLink } from 'react-router';
import { TimeSeriesChart } from '../../Components/TimeSeriesChart';
import { FormatCount, FormatTime, Panel } from '../../Components/Ui';
import type { OverviewSnapshot } from '../../Services/AdminDataSource';
import { WithTime } from '../TimeRange';

/** @brief 使用后端返回的 TCP Session 历史，附带可追溯的累计运行计数。 */
export function OverviewConnectionsChart(Input: Readonly<{ Snapshot: OverviewSnapshot; Params: URLSearchParams }>): ReactNode {
    const Points = Input.Snapshot.TcpSessionHistory.flatMap(Sample => {
        const Time = Date.parse(Sample.Time), Count = Number(Sample.Count);
        return Number.isFinite(Time) && Number.isSafeInteger(Count) && Count >= 0 ? [{ Time, Count }] : [];
    }).sort((Left, Right) => Left.Time - Right.Time);
    const Series = [{ Key: 'sessions', Label: 'TCP Session', Color: 'var(--plot-line)', Value: (Point: { Time: number; Count: number }) => Point.Count, Format: (Value: number) => FormatCount(Math.round(Value)) }];
    return <Panel HeadingLevel={2} Title="连接活动" Subtitle="TCP Session 历史采样与累计运行计数" Action={<NavLink className="inline-flex items-center gap-1 text-sm font-medium hover:underline" to={WithTime('/sessions', Input.Params)}>查看会话<ArrowRight aria-hidden="true" /></NavLink>}>
        <div className="grid min-w-0 gap-5 xl:grid-cols-3"><div className="h-40 min-w-0 xl:col-span-2">{Points.length >= 2 ? <TimeSeriesChart Points={Points} Series={Series} AriaLabel="TCP 活动 Session 数量趋势" FormatTime={Value => FormatTime(new Date(Value).toISOString())} FormatAxis={Value => FormatCount(Math.round(Value))} IntegerAxis /> : <div className="flex h-full items-center justify-center text-sm text-muted-foreground">暂无足够的连接历史采样</div>}</div>
            <div><dl className="grid grid-cols-2 gap-3 xl:grid-cols-1"><Fact Label="当前 TCP Session" Value={FormatCount(Input.Snapshot.Counts.TcpSessions)} /><Fact Label="累计数据面错误" Value={Input.Snapshot.Traffic.Available ? FormatCount(Input.Snapshot.Traffic.Errors) : '未提供'} /><Fact Label="累计观测丢弃" Value={FormatCount(Input.Snapshot.Observations.Dropped)} /></dl><NavLink className="mt-3 inline-flex items-center gap-1 text-sm font-medium hover:underline" to={WithTime('/events', Input.Params)}>查看事件流<ArrowRight className="size-4" aria-hidden="true" /></NavLink></div>
        </div>
    </Panel>;
}

function Fact(Input: Readonly<{ Label: string; Value: string }>): ReactNode {
    return <div className="border-b pb-2"><dt className="text-xs text-muted-foreground">{Input.Label}</dt><dd className="mt-1 text-lg font-semibold tabular-nums">{Input.Value}</dd></div>;
}
