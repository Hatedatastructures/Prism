/** @file Worker 页面内基于实时 Session 快照构建的短时活动趋势。 */
import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { TimeSeriesChart } from '../../Components/TimeSeriesChart';
import { FormatCount, FormatTime } from '../../Components/Ui';
import type { SessionRecord } from '../../Services/AdminDataSource';

type ActivityPoint = Readonly<{ Time: number; Sessions: number | null; Accounts: number | null }>;
type ActivityHistory = Readonly<{ Scope: string; Points: readonly ActivityPoint[] }>;
export type WorkerActivitySnapshot = Readonly<{
    Points: readonly ActivityPoint[];
    SessionLabel: string;
    AccountLabel: string;
    Description: string;
    DemoMode: boolean;
}>;

/** @brief 只把本页成功读到的 worker 会话写入本地短时序列。 */
export function useWorkerActivityTrend(Input: Readonly<{
    Scope: string;
    Sessions: readonly SessionRecord[];
    DataUpdatedAt: number;
    Partial: boolean;
    DemoMode: boolean;
}>): WorkerActivitySnapshot {
    const [History, SetHistory] = useState<ActivityHistory | null>(null);
    const ActiveSessions = Input.Sessions.filter(Value => Value.Active || Value.Draining);
    const AccountCount = new Set(ActiveSessions.map(Value => Value.AccountId)).size;
    const DemoPoints = useMemo(() => Input.DemoMode && Input.DataUpdatedAt > 0
        ? MakeDemoPoints(Input.Scope, Input.DataUpdatedAt, ActiveSessions.length, AccountCount) : [],
    [Input.DemoMode, Input.Scope, Input.DataUpdatedAt, ActiveSessions.length, AccountCount]);
    useEffect(() => {
        if (!Input.Scope || Input.DataUpdatedAt <= 0) return;
        const Sample: ActivityPoint = { Time: Input.DataUpdatedAt, Sessions: ActiveSessions.length, Accounts: AccountCount };
        SetHistory(Previous => Append(Previous, Input.Scope, Sample));
    }, [Input.Scope, Input.Sessions, Input.DataUpdatedAt, ActiveSessions.length, AccountCount]);

    const Points = Input.DemoMode ? DemoPoints : History?.Scope === Input.Scope ? History.Points : [];
    const SessionLabel = Input.Partial ? '已载入连接' : '活动连接';
    const AccountLabel = Input.Partial ? '已载入账户' : '活跃账户';
    const Description = Input.DemoMode
        ? '演示曲线模拟连接与账户变化，末点对应当前快照。真实实例按页面轮询累积。'
        : Input.Partial
            ? '本页轮询快照；列表尚有分页，当前数值是已载入范围下界。'
            : '本页轮询快照；离开页面后不保留，断线区间不连线。';
    return {
        Points, SessionLabel, AccountLabel,
        Description, DemoMode: Input.DemoMode,
    };
}

export function WorkerActivityTrend(Input: Readonly<{ Trend: WorkerActivitySnapshot }>): ReactNode {
    const Trend = Input.Trend;
    const FirstPoint = Trend.Points.at(0);
    const LatestPoint = Trend.Points.at(-1);
    const Series = [
        { Key: 'Sessions', Label: Trend.SessionLabel, Color: 'var(--plot-line)', Value: (Point: ActivityPoint) => Point.Sessions, Format: (Value: number) => FormatCount(Math.round(Value)), Area: true },
        { Key: 'Accounts', Label: Trend.AccountLabel, Color: 'var(--plot-line-soft)', Value: (Point: ActivityPoint) => Point.Accounts, Format: (Value: number) => FormatCount(Math.round(Value)), Dash: '6 4' },
    ];
    return <section aria-label="连接与账户分配趋势" className="min-w-0 space-y-3">
        <div><h3 className="text-sm font-semibold">连接与账户分配</h3><p className="mt-1 text-xs text-muted-foreground">{Trend.Description}</p></div>
        {Trend.Points.length < 2
            ? <div className="grid grid-cols-1 items-center gap-2 border-y py-3 sm:grid-cols-[minmax(0,1fr)_auto]">
                <p className="text-sm text-muted-foreground">{Trend.DemoMode ? '演示模式不会自动轮询；点“刷新快照”累积采样。' : Trend.Points.length === 0 ? '等待首个 Worker 会话快照。' : '等待下一次实时轮询，再显示变化趋势。'}</p>
                {Trend.Points.length === 1 && FirstPoint && <p className="text-xs text-muted-foreground">首个样本 {FormatTime(new Date(FirstPoint.Time).toISOString(), true)}</p>}
            </div>
            : <><div className="h-64 min-w-0 sm:h-72"><TimeSeriesChart Points={Trend.Points} Series={Series} AriaLabel={Trend.DemoMode ? '演示模拟的 Worker 活动连接与唯一账户趋势' : '本页采集的 Worker 活动连接与唯一账户趋势'}
                FormatTime={Value => FormatTime(new Date(Value).toISOString())}
                FormatAxis={Value => FormatCount(Math.round(Value))} IntegerAxis /></div>
                <p className="border-t pt-2 text-xs text-muted-foreground">{Trend.DemoMode ? '演示采样' : '最近采样'} {LatestPoint ? FormatTime(new Date(LatestPoint.Time).toISOString(), true) : '时间未知'} · {Trend.Points.length} 个{Trend.DemoMode ? '模拟点' : '本页快照'}</p>
            </>}
    </section>;
}

function MakeDemoPoints(Scope: string, End: number, Sessions: number, Accounts: number): ActivityPoint[] {
    const Count = 16;
    const Seed = [...Scope].reduce((Total, Character) => Total + Character.charCodeAt(0), 0);
    return Array.from({ length: Count }, (_, Index) => {
        const Phase = Index / (Count - 1);
        const IsLatest = Index === Count - 1;
        const SessionSwing = Math.round(Math.sin(Phase * Math.PI * 4 + Seed) * Math.max(1, Sessions * 0.22));
        const SessionValue = IsLatest ? Sessions : Math.max(0, Sessions + SessionSwing);
        const AccountSwing = Math.round(Math.sin(Phase * Math.PI * 3 + Seed * 0.7) * Math.max(1, Accounts * 0.18));
        const AccountValue = IsLatest ? Accounts : Math.max(0, Math.min(SessionValue, Accounts + AccountSwing));
        return { Time: End - (Count - Index - 1) * 5_000, Sessions: SessionValue, Accounts: AccountValue };
    });
}

function Append(Previous: ActivityHistory | null, Scope: string, Sample: ActivityPoint): ActivityHistory {
    const Before = Previous?.Scope === Scope ? Previous.Points : [];
    if (Before.at(-1)?.Time === Sample.Time) return Previous ?? { Scope, Points: [Sample] };
    const Last = Before.at(-1);
    const Points = [...Before];
    if (Last && Sample.Time - Last.Time > 15_000) Points.push({ Time: Last.Time + (Sample.Time - Last.Time) / 2, Sessions: null, Accounts: null });
    Points.push(Sample);
    return { Scope, Points: Points.slice(-80) };
}
